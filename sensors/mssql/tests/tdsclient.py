"""A small TDS client for tests: builds PRELOGIN / LOGIN7 / batch packets, reads replies."""

from __future__ import annotations

import asyncio
import ssl
import struct
from dataclasses import dataclass, field

from mssql_sensor import tds


def packet(ptype: int, payload: bytes, eom: bool = True, pid: int = 1) -> bytes:
    return struct.pack(">BBHHBB", ptype, 1 if eom else 0, 8 + len(payload), 0, pid, 0) + payload


def prelogin(encryption: int = tds.ENC_NOT_SUP) -> bytes:
    body = (
        bytes([0, 0, 11, 0, 6, 1, 0, 17, 0, 1, 0xFF])
        + bytes([15, 0, 0x10, 0x4C, 0, 0])
        + bytes([encryption])
    )
    return packet(tds.T_PRELOGIN, body)


def login7(
    username: str = "sa",
    password: str = "x",
    hostname: str = "WIN-CLIENT",
    app: str = "test-app",
    library: str = "TDSLIB",
    database: str = "",
    version: int = 0x74000004,
    packet_size: int = 4096,
    legacy: bool = False,
    sspi: bytes = b"",
    extension: bool = False,
) -> bytes:
    fields = [hostname, username, None, app, "srv", "", library, "", database]
    data = bytearray()
    offsets: list[tuple[int, int]] = []
    base = 86 if legacy else 94
    for i, value in enumerate(fields):
        if i == 2:
            raw = tds.encode_password(password)
            cch = len(raw) // 2
        else:
            raw = (value or "").encode("utf-16-le")
            cch = len(raw) // 2
        offsets.append((base + len(data), cch))
        data += raw
    head = struct.pack("<IIIIII", 0, version, packet_size, 7, 1234, 0) + bytes(
        [0xE0, 0x83 if sspi else 0x03, 0, 0x10 if extension else 0]
    )
    head += struct.pack("<II", 0, 0x409)
    # slots: host, user, pass, app, server, extension, cltint, language, database; then
    # ClientID, SSPI, AtchDBFile and (TDS 7.2+) ChangePassword, cbSSPILong
    table = b"".join(struct.pack("<HH", off, cch) for off, cch in offsets)
    end = base + len(data)
    table += b"\x00" * 6 + struct.pack("<HH", end, len(sspi)) + struct.pack("<HH", end, 0)
    if not legacy:
        table += struct.pack("<HH", end, 0) + struct.pack("<I", 0)
    body = bytearray(head + table + data + sspi)
    struct.pack_into("<I", body, 0, len(body))
    return packet(tds.T_LOGIN7, bytes(body))


def batch(sql: str) -> bytes:
    all_headers = struct.pack("<IIHQI", 22, 18, 2, 0, 1)[:22]
    return packet(tds.T_SQLBATCH, all_headers + sql.encode("utf-16-le"))


@dataclass
class Reply:
    raw: bytes
    errors: list[tuple[int, str]] = field(default_factory=list)
    infos: list[tuple[int, str]] = field(default_factory=list)
    rows: list[list[str | int | None]] = field(default_factory=list)
    login_ack: bool = False
    done: int = 0


def _ucs(data: bytes) -> str:
    return data.decode("utf-16-le")


def parse_reply(raw: bytes, ver: int = 0x74000004) -> Reply:
    """Walk the tokens of a reply message (test-only, trusts the server)."""
    payload = bytearray()
    pos = 0
    while pos + 8 <= len(raw):
        length = struct.unpack_from(">H", raw, pos + 2)[0]
        payload += raw[pos + 8 : pos + length]
        pos += length
    out = Reply(raw=raw)
    p = bytes(payload)
    i = 0
    cols: list[str] = []  # kinds
    while i < len(p):
        t = p[i]
        i += 1
        if t in (0xAA, 0xAB):
            ln = struct.unpack_from("<H", p, i)[0]
            body = p[i + 2 : i + 2 + ln]
            num = struct.unpack_from("<I", body, 0)[0]
            chars = struct.unpack_from("<H", body, 6)[0]
            text = _ucs(body[8 : 8 + 2 * chars])
            (out.errors if t == 0xAA else out.infos).append((num, text))
            i += 2 + ln
        elif t in (0xE3, 0xAD):
            ln = struct.unpack_from("<H", p, i)[0]
            out.login_ack |= t == 0xAD
            i += 2 + ln
        elif t == 0x81:
            n = struct.unpack_from("<H", p, i)[0]
            i += 2
            cols = []
            for _ in range(n):
                i += 6 if ver >= 0x72000000 else 4
                ty = p[i]
                i += 1
                if ty == 0xE7:
                    i += 7
                    cols.append("s")
                elif ty == 0x38:
                    cols.append("i")
                else:
                    cols.append("d")
                nl = p[i]
                i += 1 + 2 * nl
        elif t == 0xD1:
            row: list[str | int | None] = []
            for kind in cols:
                if kind == "i":
                    row.append(struct.unpack_from("<i", p, i)[0])
                    i += 4
                elif kind == "d":
                    row.append(0)
                    i += 8
                else:
                    ln = struct.unpack_from("<H", p, i)[0]
                    i += 2
                    if ln == 0xFFFF:
                        row.append(None)
                    else:
                        row.append(_ucs(p[i : i + ln]))
                        i += ln
            out.rows.append(row)
        elif t in (0xFD, 0xFE, 0xFF):
            out.done = struct.unpack_from("<H", p, i)[0]
            i += 12 if ver >= 0x72000000 else 8
        elif t == 0x79:
            i += 4
        else:
            raise AssertionError(f"unknown token {t:#x} at {i}")
    return out


class Client:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self.ver = 0x74000004
        self.tls: ssl.SSLObject | None = None
        self._in = ssl.MemoryBIO()
        self._out = ssl.MemoryBIO()
        self._plain = b""
        self.server_encryption = -1

    @classmethod
    async def connect(cls, port: int, source: str | None = None) -> Client:
        local = (source, 0) if source else None
        reader, writer = await asyncio.open_connection("127.0.0.1", port, local_addr=local)
        return cls(reader, writer)

    async def _write(self, data: bytes) -> None:
        if self.tls is not None:
            self.tls.write(data)
            data = self._out.read()
        self.writer.write(data)
        await self.writer.drain()

    async def _read_exactly(self, n: int) -> bytes:
        if self.tls is None:
            return await self.reader.readexactly(n)
        while len(self._plain) < n:
            chunk = await self.reader.read(65536)
            if not chunk:
                raise asyncio.IncompleteReadError(self._plain, n)
            self._in.write(chunk)
            while True:
                try:
                    got = self.tls.read(65536)
                except ssl.SSLWantReadError:
                    break
                if not got:
                    break
                self._plain += got
        out, self._plain = self._plain[:n], self._plain[n:]
        return out

    async def read_message(self, timeout: float = 3.0) -> bytes:
        raw = b""
        async with asyncio.timeout(timeout):
            while True:
                head = await self._read_exactly(8)
                length = struct.unpack_from(">H", head, 2)[0]
                raw += head + await self._read_exactly(length - 8)
                if head[1] & 1:
                    return raw

    async def request(self, data: bytes) -> Reply:
        await self._write(data)
        return parse_reply(await self.read_message(), self.ver)

    async def prelogin(self, encryption: int = tds.ENC_NOT_SUP) -> bytes:
        """PRELOGIN exchange; when the server answers OFF/ON the TLS handshake follows."""
        self.writer.write(prelogin(encryption))
        await self.writer.drain()
        raw = await self.read_message()
        self.server_encryption = tds.parse_prelogin(raw[8:]).encryption or 0
        if self.server_encryption in (tds.ENC_OFF, tds.ENC_ON):
            await self._handshake()
        return raw

    async def _handshake(self) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        obj = ctx.wrap_bio(self._in, self._out)
        while True:
            try:
                obj.do_handshake()
                done = True
            except ssl.SSLWantReadError:
                done = False
            out = self._out.read()
            if out:
                for pkt in tds.frame(tds.T_PRELOGIN, out, 4096, 0):
                    self.writer.write(pkt)
                await self.writer.drain()
            if done:
                break
            msg = await self.read_message()
            self._in.write(msg[8:])
        self.tls = obj

    def drop_tls(self) -> None:
        self.tls = None

    async def login(self, username: str = "sa", password: str = "123456", **kw: object) -> Reply:
        enc = int(kw.pop("encryption", tds.ENC_NOT_SUP))  # type: ignore[call-overload]
        await self.prelogin(enc)
        self.ver = int(kw.get("version", self.ver))  # type: ignore[call-overload]
        await self._write(login7(username, password, **kw))  # type: ignore[arg-type]
        if self.tls is not None and self.server_encryption == tds.ENC_OFF:
            self.drop_tls()  # encryption "off": TLS protects LOGIN7 only, the reply is plaintext
        reply = parse_reply(await self.read_message(), self.ver)
        return reply

    async def close(self) -> None:
        self.writer.close()

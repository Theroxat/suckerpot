"""A tiny in-process SMB client used by the tests (no external dependency).

It builds the few request PDUs the sensor answers (NEGOTIATE, SESSION_SETUP with raw NTLM) and
parses the NetBIOS framing of responses. It is deliberately minimal and only for tests.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct

from smb_sensor import framing, ntlm, smb


def client_header(command: int, message_id: int, session_id: int = 0) -> bytes:
    return struct.pack(
        "<4sHHIHHIIQIIQ16s",
        smb.SMB2_MAGIC,
        smb.SMB2_HEADER_LEN,
        0,
        0,
        command,
        1,
        0,  # client flags
        0,
        message_id,
        0,
        0,
        session_id,
        b"\x00" * 16,
    )


def negotiate_request(dialects: list[int], *, contexts: bool = False) -> bytes:
    header = client_header(smb.SMB2_NEGOTIATE, 0)
    dialect_blob = b"".join(struct.pack("<H", d) for d in dialects)
    if contexts and smb.DIALECT_3_1_1 in dialects:
        # Fixed body with a NegotiateContextOffset/Count, then dialects (8-aligned), then one
        # encryption context advertising AES-128-GCM.
        fixed_wo_contexts = struct.pack("<HHHHI16s", 36, len(dialects), 1, 0, 0, b"\x00" * 16)
        after_dialects = smb.SMB2_HEADER_LEN + 36 + len(dialect_blob)
        pad = b"\x00" * ((8 - (after_dialects % 8)) % 8)
        ctx_offset = after_dialects + len(pad)
        enc_data = struct.pack("<HH", 1, 0x0002)
        enc = struct.pack("<HHI", smb.CTX_ENCRYPTION, len(enc_data), 0) + enc_data
        body = fixed_wo_contexts + struct.pack("<IHH", ctx_offset, 1, 0) + dialect_blob + pad + enc
        return framing.build_message(header + body)
    body = struct.pack("<HHHHI16sQ", 36, len(dialects), 1, 0, 0, b"\x00" * 16, 0) + dialect_blob
    return framing.build_message(header + body)


def session_setup_request(security_buffer: bytes, *, message_id: int, session_id: int = 0) -> bytes:
    header = client_header(smb.SMB2_SESSION_SETUP, message_id, session_id)
    sec_offset = smb.SMB2_HEADER_LEN + 24
    body = struct.pack(
        "<HBBIIHHQ",
        25,  # StructureSize
        0,  # Flags
        1,  # SecurityMode
        0,  # Capabilities
        0,  # Channel
        sec_offset,  # SecurityBufferOffset
        len(security_buffer),  # SecurityBufferLength
        0,  # PreviousSessionId
    )
    return framing.build_message(header + body + security_buffer)


def ntlm_negotiate() -> bytes:
    return ntlm.SIGNATURE + struct.pack(
        "<II", ntlm.TYPE_NEGOTIATE, ntlm.NEG_UNICODE | ntlm.NEG_NTLM
    )


def ntlm_authenticate(
    domain: str, user: str, workstation: str, *, nt_response: bytes = b"\x11" * 24
) -> bytes:
    """Build a minimal NTLM AUTHENTICATE with the given names (UTF-16LE)."""
    flags = ntlm.NEG_UNICODE | ntlm.NEG_NTLM

    def u(text: str) -> bytes:
        return text.encode("utf-16-le")

    fixed = 64  # through NegotiateFlags + reserved up to payload start
    lm = b"\x00"
    parts = [lm, nt_response, u(domain), u(user), u(workstation), b""]
    offsets = []
    cursor = fixed
    for part in parts:
        offsets.append((len(part), cursor))
        cursor += len(part)
    header = ntlm.SIGNATURE + struct.pack("<I", ntlm.TYPE_AUTHENTICATE)
    for length, off in offsets:
        header += struct.pack("<HHI", length, length, off)
    header += struct.pack("<I", flags)
    assert len(header) == fixed, len(header)
    return header + b"".join(parts)


async def exchange(port: int, request: bytes, *, host: str = "127.0.0.1") -> bytes:
    reader, writer = await asyncio.open_connection(host, port)
    try:
        writer.write(request)
        await writer.drain()
        return await read_pdu(reader)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def read_pdu(reader: asyncio.StreamReader, timeout: float = 5.0) -> bytes:
    header = await asyncio.wait_for(reader.readexactly(framing.HEADER_LEN), timeout)
    _type, length = framing.parse_header(header)
    return await asyncio.wait_for(reader.readexactly(length), timeout)


class Conn:
    """A live connection that can send several PDUs and read the replies."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer

    @classmethod
    async def open(cls, port: int, host: str = "127.0.0.1", source: str | None = None) -> Conn:
        local = (source, 0) if source else None
        reader, writer = await asyncio.open_connection(host, port, local_addr=local)
        return cls(reader, writer)

    async def send(self, request: bytes) -> bytes:
        self.writer.write(request)
        await self.writer.drain()
        return await read_pdu(self.reader)

    async def send_raw(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    async def close(self) -> None:
        self.writer.close()
        with contextlib.suppress(Exception):
            await self.writer.wait_closed()

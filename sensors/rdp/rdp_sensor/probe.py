"""Bounded, regex-free inspection helpers: previews, protocol guesses, TLS ClientHello
fingerprints and the (credential-free) NTLM NEGOTIATE message.

All functions are linear in their input and never index past its end.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any

PREVIEW_BYTES = 256

_HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"CONNECT ",
    b"PATCH ",
    b"TRACE ",
    b"PRI * HTTP/2",
)


def hex_preview(data: bytes, limit: int = PREVIEW_BYTES) -> str:
    return data[:limit].hex()


def ascii_preview(data: bytes, limit: int = PREVIEW_BYTES) -> str:
    """Printable ASCII kept as is, everything else shown as ``.``."""
    return "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in data[:limit])


def guess_protocol(data: bytes) -> str:
    """Best-effort name of whatever a client sent to the RDP port."""
    if not data:
        return "empty"
    head = data[:16]
    if data.startswith(_HTTP_METHODS):
        return "http"
    if len(data) >= 3 and data[0] == 0x16 and data[1] == 0x03:
        return "tls"
    if len(data) >= 3 and data[0] == 0x80 and data[2] == 0x01:
        return "sslv2"
    if data.startswith(b"SSH-"):
        return "ssh"
    if data[0] == 0x03 and len(data) >= 2 and data[1] == 0x00:
        return "tpkt"
    if len(data) >= 8 and data[4:8] in (b"\xffSMB", b"\xfeSMB"):
        return "smb"
    if data[0] == 0x05 and len(data) >= 2 and 1 <= data[1] <= 16 and len(data) <= 18:
        return "socks5"
    if data[0] == 0x04 and len(data) >= 8 and data[1] in (1, 2):
        return "socks4"
    if data.startswith((b"*1\r\n", b"*2\r\n", b"*3\r\n", b"PING", b"INFO")):
        return "redis"
    if head.upper().startswith((b"HELP", b"STATS", b"VERSION", b"QUIT")):
        return "text-command"
    if data.startswith(b"\x30") and len(data) > 2:
        return "asn1-ber"
    if all(b in (0x0D, 0x0A) for b in head):
        return "newline"
    if all(0x20 <= b < 0x7F or b in (0x09, 0x0D, 0x0A) for b in head):
        return "text"
    return "unknown"


# --- TLS ClientHello -------------------------------------------------------------------------

TLS_RECORD_HEADER = 5
MAX_TLS_RECORD = 16384 + 2048


def tls_record_length(buf: bytes) -> int | None:
    """Total length (header included) of the first TLS handshake record, or None if invalid."""
    if len(buf) < TLS_RECORD_HEADER or buf[0] != 0x16 or buf[1] != 0x03:
        return None
    length = (buf[3] << 8) | buf[4]
    if length == 0 or length > MAX_TLS_RECORD:
        return None
    return TLS_RECORD_HEADER + length


def _is_grease(value: int) -> bool:
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ValueError("truncated")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int(struct.unpack(">H", self.take(2))[0])

    def u24(self) -> int:
        raw = self.take(3)
        return (raw[0] << 16) | (raw[1] << 8) | raw[2]


def _u16_list(raw: bytes) -> list[int]:
    return [struct.unpack_from(">H", raw, i)[0] for i in range(0, len(raw) - 1, 2)]


def parse_client_hello(record: bytes) -> dict[str, Any] | None:
    """Fingerprint the first TLS record if it is a ClientHello (JA3 + SNI + ALPN).

    Returns None if the record is not a (complete) ClientHello. Never raises.
    """
    try:
        rec = _Reader(record)
        if rec.u8() != 0x16:
            return None
        rec.take(2)
        body = rec.take(rec.u16())
        hs = _Reader(body)
        if hs.u8() != 0x01:
            return None
        hello = _Reader(hs.take(hs.u24()))
        version = hello.u16()
        hello.take(32)  # random
        hello.take(hello.u8())  # session id
        ciphers = _u16_list(hello.take(hello.u16()))
        hello.take(hello.u8())  # compression methods
        extensions: list[int] = []
        groups: list[int] = []
        formats: list[int] = []
        versions: list[int] = []
        sni: str | None = None
        alpn: list[str] = []
        if hello.pos < len(hello.data):
            exts = _Reader(hello.take(hello.u16()))
            while exts.pos < len(exts.data) and len(extensions) < 64:
                ext_type = exts.u16()
                ext = exts.take(exts.u16())
                extensions.append(ext_type)
                if ext_type == 0 and len(ext) >= 5 and ext[2] == 0:
                    name_len = struct.unpack_from(">H", ext, 3)[0]
                    sni = ext[5 : 5 + name_len].decode("ascii", "replace")[:255]
                elif ext_type == 10 and len(ext) >= 2:
                    groups = _u16_list(ext[2 : 2 + struct.unpack_from(">H", ext, 0)[0]])
                elif ext_type == 11 and ext:
                    formats = list(ext[1 : 1 + ext[0]])
                elif ext_type == 16 and len(ext) >= 2:
                    alpn_raw = ext[2:]
                    i = 0
                    while i < len(alpn_raw) and len(alpn) < 8:
                        n = alpn_raw[i]
                        alpn.append(alpn_raw[i + 1 : i + 1 + n].decode("ascii", "replace"))
                        i += 1 + n
                elif ext_type == 43 and ext:
                    versions = _u16_list(ext[1 : 1 + ext[0]])
    except (ValueError, IndexError, struct.error):
        return None

    def join(values: list[int]) -> str:
        return "-".join(str(v) for v in values if not _is_grease(v))

    ja3 = ",".join([str(version), join(ciphers), join(extensions), join(groups), join(formats)])
    return {
        "ja3": ja3[:2048],
        "ja3_hash": hashlib.md5(ja3.encode(), usedforsecurity=False).hexdigest(),
        "sni": sni,
        "alpn": alpn,
        "supported_versions": [f"0x{v:04x}" for v in versions if not _is_grease(v)][:16],
        "cipher_count": len(ciphers),
    }


# --- CredSSP / NTLM --------------------------------------------------------------------------

NTLMSSP = b"NTLMSSP\x00"
NEGOTIATE_OEM_DOMAIN_SUPPLIED = 0x00001000
NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000
NEGOTIATE_VERSION = 0x02000000


def credssp_version(data: bytes) -> int | None:
    """TSRequest.version (``30 .. a0 03 02 01 <v>``) from the first bytes, if present."""
    idx = data.find(b"\xa0\x03\x02\x01", 0, 16)
    if idx < 0 or idx + 4 >= len(data) or data[0] != 0x30:
        return None
    return data[idx + 4]


def _ntlm_field(msg: bytes, offset: int) -> str | None:
    if offset + 8 > len(msg):
        return None
    length, _max, start = struct.unpack_from("<HHI", msg, offset)
    if length == 0 or start + length > len(msg):
        return None
    return msg[start : start + min(length, 64)].decode("latin-1")


def parse_ntlm_negotiate(data: bytes) -> dict[str, Any] | None:
    """Describe an NTLM NEGOTIATE (type 1) message embedded in a TSRequest.

    A NEGOTIATE message carries no credential material: only flags, the client's OS version
    and optionally its domain and workstation names.
    """
    idx = data.find(NTLMSSP)
    if idx < 0:
        return None
    msg = data[idx : idx + 1024]
    if len(msg) < 16 or struct.unpack_from("<I", msg, 8)[0] != 1:
        return None
    flags = struct.unpack_from("<I", msg, 12)[0]
    out: dict[str, Any] = {"flags": f"0x{flags:08x}"}
    if flags & NEGOTIATE_OEM_DOMAIN_SUPPLIED:
        out["domain"] = _ntlm_field(msg, 16)
    if flags & NEGOTIATE_OEM_WORKSTATION_SUPPLIED:
        out["workstation"] = _ntlm_field(msg, 24)
    if flags & NEGOTIATE_VERSION and len(msg) >= 40:
        major, minor, build = struct.unpack_from("<BBH", msg, 32)
        out["os_version"] = f"{major}.{minor}.{build}"
    return out

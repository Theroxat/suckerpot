"""Bounded, regex-free inspection helpers: hex / ASCII previews and a protocol guess.

All functions are linear in their input and never index past its end. They never interpret
the bytes as anything executable; they only describe them for the event record.
"""

from __future__ import annotations

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
    """Best-effort name of whatever a client sent to the SMB port."""
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
    # NetBIOS session service over TCP: a 4-byte header, type 0x00, then an SMB signature.
    if len(data) >= 8 and data[0] == 0x00 and data[4:8] == b"\xfeSMB":
        return "smb2"
    if len(data) >= 8 and data[0] == 0x00 and data[4:8] == b"\xffSMB":
        return "smb1"
    if len(data) >= 4 and data[0] == 0x81:
        return "netbios-session-request"
    if len(data) >= 4 and data[:4] in (b"\xffSMB", b"\xfeSMB"):
        return "smb-unframed"
    if data[0] == 0x03 and len(data) >= 2 and data[1] == 0x00:
        return "tpkt"
    if data[0] == 0x05 and len(data) >= 2 and 1 <= data[1] <= 16 and len(data) <= 18:
        return "socks5"
    if data[0] == 0x04 and len(data) >= 8 and data[1] in (1, 2):
        return "socks4"
    if data.startswith((b"*1\r\n", b"*2\r\n", b"*3\r\n", b"PING", b"INFO")):
        return "redis"
    if data.startswith(b"\x30") and len(data) > 2:
        return "asn1-ber"
    if all(b in (0x0D, 0x0A) for b in head):
        return "newline"
    if all(0x20 <= b < 0x7F or b in (0x09, 0x0D, 0x0A) for b in head):
        return "text"
    return "unknown"

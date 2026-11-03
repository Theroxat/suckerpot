"""Strict, bounded TLS ClientHello reader that extracts the SNI.

The proxy only serves ``CONNECT <allowed name>:443``. Without this check a client could name an
allowed host in CONNECT and then ask for another one in the TLS handshake, using the CDN in front
of the allowed host as general egress (domain fronting). The first flight is therefore read,
parsed and required to carry exactly one ``host_name`` equal to the CONNECT host. Anything else
(absent, malformed, multiple names, ECH, oversized, too slow) is refused.
"""

from __future__ import annotations

import asyncio

RECORD_HEADER = 5
MAX_RECORD = 16384
MAX_HELLO = 16384  # handshake message body cap
MAX_RECORDS = 16
HELLO_TIMEOUT = 5.0
_HANDSHAKE = 22
_CLIENT_HELLO = 1
_EXT_SNI = 0
_EXT_ECH = frozenset({0xFE0D, 0xFF0D})  # encrypted ClientHello (final and draft codepoints)
_HOST_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-.")


class HelloError(ValueError):
    """The client's first flight is not an acceptable ClientHello."""


class _Cursor:
    __slots__ = ("data", "pos")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise HelloError("truncated")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def uint(self, n: int) -> int:
        return int.from_bytes(self.take(n), "big")

    def left(self) -> int:
        return len(self.data) - self.pos


def _parse_server_name(ext: bytes) -> str:
    cur = _Cursor(ext)
    if cur.uint(2) != cur.left() or cur.left() == 0:
        raise HelloError("bad server_name list")
    if cur.uint(1) != 0:
        raise HelloError("not a host_name")
    raw = cur.take(cur.uint(2))
    if cur.left() != 0:
        raise HelloError("more than one server name")
    try:
        name = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise HelloError("non-ascii name") from exc
    name = name.lower()
    if not name or len(name) > 253 or not set(name) <= _HOST_CHARS:
        raise HelloError("bad host name")
    if name.startswith((".", "-")) or name.endswith((".", "-")) or ".." in name:
        raise HelloError("bad host name")
    return name


def parse_hello_body(body: bytes) -> str:
    """Return the lowercase SNI of a ClientHello body (after the 4-byte handshake header)."""
    cur = _Cursor(body)
    if cur.uint(1) != 3 or cur.uint(1) > 3:  # legacy_version 0x0300..0x0303
        raise HelloError("bad version")
    cur.take(32)  # random
    sid_len = cur.uint(1)
    if sid_len > 32:
        raise HelloError("bad session id")
    cur.take(sid_len)
    suites = cur.uint(2)
    if suites < 2 or suites % 2:
        raise HelloError("bad cipher suites")
    cur.take(suites)
    comp_len = cur.uint(1)
    if comp_len < 1:
        raise HelloError("bad compression")
    cur.take(comp_len)
    if cur.left() < 2:
        raise HelloError("no extensions")
    if cur.uint(2) != cur.left():
        raise HelloError("extensions length mismatch")
    name: str | None = None
    seen: set[int] = set()
    while cur.left():
        etype = cur.uint(2)
        data = cur.take(cur.uint(2))
        if etype in seen:
            raise HelloError("duplicate extension")
        seen.add(etype)
        if etype in _EXT_ECH:
            raise HelloError("encrypted client hello")
        if etype == _EXT_SNI:
            name = _parse_server_name(data)
    if name is None:
        raise HelloError("no server_name")
    return name


async def _read_exactly(reader: asyncio.StreamReader, n: int) -> bytes:
    try:
        return await reader.readexactly(n)
    except (asyncio.IncompleteReadError, ConnectionError) as exc:
        raise HelloError("client closed early") from exc


async def _read_flight(reader: asyncio.StreamReader) -> tuple[bytes, str]:
    raw = bytearray()
    payload = bytearray()
    for _ in range(MAX_RECORDS):
        header = await _read_exactly(reader, RECORD_HEADER)
        raw += header
        length = int.from_bytes(header[3:5], "big")
        if header[0] != _HANDSHAKE or header[1] != 3 or header[2] > 4:
            raise HelloError("not a TLS handshake record")
        if not 0 < length <= MAX_RECORD:
            raise HelloError("bad record length")
        if len(payload) + length > MAX_HELLO + 4:
            raise HelloError("hello too large")
        body = await _read_exactly(reader, length)
        raw += body
        payload += body
        if len(payload) >= 4:
            if payload[0] != _CLIENT_HELLO:
                raise HelloError("not a ClientHello")
            hlen = int.from_bytes(payload[1:4], "big")
            if hlen > MAX_HELLO:
                raise HelloError("hello too large")
            if len(payload) >= 4 + hlen:
                if len(payload) != 4 + hlen:
                    raise HelloError("trailing bytes after ClientHello")
                return bytes(raw), parse_hello_body(bytes(payload[4:]))
    raise HelloError("too many records")


async def read_client_hello(reader: asyncio.StreamReader) -> tuple[bytes, str]:
    """Read the first flight; return (raw bytes to forward, lowercase SNI) or raise HelloError."""
    try:
        async with asyncio.timeout(HELLO_TIMEOUT):
            return await _read_flight(reader)
    except TimeoutError as exc:
        raise HelloError("timeout") from exc

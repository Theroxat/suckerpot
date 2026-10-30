"""HTTP/1.1 request reading, shaped like Go's net/http server (which is what dockerd runs).

Hand written on purpose: every read has a deadline, every buffer a limit, no regular
expressions. Bodies are streamed: only the first ``body_cap`` bytes are kept, the rest is hashed
and thrown away, up to ``body_total_max``.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import parse_qsl

from synology_sensor.config import Config
from synology_sensor.cpu import Meter

_TOKEN = frozenset("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_METHOD = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ")


class HttpError(Exception):
    """A malformed request. Go answers a bare ``400 Bad Request`` (or 431, 413...) and closes."""

    def __init__(self, status: int, text: str = "") -> None:
        super().__init__(status)
        self.status = status
        self.text = text


class IdleTimeout(Exception):
    """No (further) request arrived in time."""


class SlowRequest(Exception):
    """The head or body did not arrive fast enough (slowloris)."""


class ClientGone(Exception):
    """The peer closed the connection (possibly mid-request)."""


def to_text(raw: bytes | str) -> str:
    if isinstance(raw, str):
        return raw
    return raw.decode("utf-8", "replace")


@dataclass
class Request:
    method: str = ""
    target: str = ""
    path: str = ""
    query_raw: str = ""
    version: str = "HTTP/1.1"
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    body_len: int = 0
    body_sha256: str = ""
    body_truncated: bool = False
    chunked: bool = False
    content_length: int | None = None

    def header(self, name: str) -> str | None:
        low = name.lower()
        for k, v in self.headers:
            if k.lower() == low:
                return v
        return None

    def query(self) -> list[tuple[str, str]]:
        try:
            return parse_qsl(self.query_raw, keep_blank_values=True, max_num_fields=64)
        except ValueError:
            return []

    def qget(self, key: str, default: str = "") -> str:
        for k, v in self.query():
            if k == key:
                return v
        return default

    def keep_alive(self) -> bool:
        conn = (self.header("connection") or "").lower()
        if self.version == "HTTP/1.0":
            return "keep-alive" in conn
        return "close" not in conn

    def wants_upgrade(self) -> bool:
        return "upgrade" in (self.header("connection") or "").lower()


class ConnReader:
    """Buffered, deadline-driven reader over a StreamReader."""

    def __init__(self, reader: asyncio.StreamReader, cfg: Config) -> None:
        self.reader = reader
        self.cfg = cfg
        self.buf = bytearray()
        self.eof = False
        self.consumed = 0  # bytes of the current request seen so far (for partial events)
        self.meter: Meter | None = None

    async def tick(self) -> None:
        """Let other connections run when this one has used up its wall-clock slice."""
        if self.meter is not None:
            await self.meter.tick()

    async def _fill(self, timeout: float) -> bool:  # noqa: ASYNC109 - passed on to wait_for
        """Read more input. False on EOF. Raises TimeoutError when nothing arrives in time."""
        if self.eof:
            return False
        if self.meter is not None:
            self.meter.flush()
        try:
            data = await asyncio.wait_for(self.reader.read(16384), timeout)
        except TimeoutError:
            raise
        except OSError:  # includes ssl.SSLError and ConnectionError: the peer is gone
            raise ClientGone from None
        finally:
            if self.meter is not None:
                self.meter.mark()
        if not data:
            self.eof = True
            return False
        self.buf += data
        return True

    async def read_head(self, *, first: bool) -> bytes | None:
        """Raw request head (without the blank line). None on a clean EOF between requests."""
        cfg = self.cfg
        idle = cfg.first_byte_timeout if first else cfg.keepalive_timeout
        # RFC 9112: ignore empty lines before the request line.
        while not self.buf:
            try:
                if not await self._fill(idle):
                    return None
            except TimeoutError:
                raise IdleTimeout from None
        deadline = time.monotonic() + cfg.head_timeout
        while True:
            cut, sep = _find_end(self.buf)
            if cut > cfg.head_limit:
                raise HttpError(431, "Request Header Fields Too Large")
            if cut >= 0:
                head = bytes(self.buf[:cut])
                del self.buf[: cut + sep]
                return head
            if len(self.buf) > cfg.head_limit:
                raise HttpError(431, "Request Header Fields Too Large")
            left = deadline - time.monotonic()
            if left <= 0:
                raise SlowRequest
            try:
                if not await self._fill(left):
                    raise ClientGone
            except TimeoutError:
                raise SlowRequest from None

    async def read_body(
        self, req: Request, started: float, grow: Callable[[int], bool] | None = None
    ) -> None:
        """Fill ``req.body`` (bounded), ``body_len``, ``body_sha256``, ``body_truncated``."""
        cfg = self.cfg
        te = (req.header("transfer-encoding") or "").lower()
        cl = req.header("content-length")
        sha = hashlib.sha256()
        kept = bytearray()
        total = 0
        t0 = time.monotonic()

        def take(chunk: bytes | bytearray) -> None:
            nonlocal total
            sha.update(chunk)
            room = cfg.body_cap - len(kept)
            if room > 0:
                if grow is not None and not grow(min(room, len(chunk))):
                    raise HttpError(503, "Service Unavailable")
                kept.extend(chunk[:room])
            total += len(chunk)

        async def more() -> bool:
            elapsed = time.monotonic() - t0
            if elapsed > cfg.body_total_timeout:
                raise SlowRequest
            if elapsed > 5 and total / elapsed < cfg.body_min_rate:
                raise SlowRequest
            try:
                return await self._fill(cfg.body_timeout)
            except TimeoutError:
                raise SlowRequest from None

        if te:
            if te.split(",")[-1].strip() != "chunked":
                raise HttpError(501, "Unsupported transfer encoding")
            req.chunked = True
            while True:
                line = await self._line(more, 256)
                await self.tick()
                size_text = line.split(b";", 1)[0].strip()
                try:
                    size = int(size_text, 16) if size_text and len(size_text) <= 8 else -1
                except ValueError:
                    size = -1
                if size < 0:
                    raise HttpError(400, "Bad Request")
                if size == 0:
                    for _ in range(8):  # trailers
                        if not await self._line(more, 1024):
                            break
                    break
                if total + size > cfg.body_total_max:
                    req.body_truncated = True
                    break
                left = size
                while left > 0:
                    if not self.buf and not await more():
                        raise ClientGone
                    n = min(left, len(self.buf))
                    take(self.buf[:n])
                    del self.buf[:n]
                    left -= n
                    await self.tick()
                if await self._line(more, 8):  # the CRLF after the chunk
                    raise HttpError(400, "Bad Request")
        elif cl is not None:
            try:
                length = int(cl) if cl.isascii() and cl.isdigit() and len(cl) <= 12 else -1
            except ValueError:
                length = -1
            if length < 0:
                raise HttpError(400, "Bad Request")
            req.content_length = length
            want = min(length, cfg.body_total_max)
            if length > cfg.body_total_max:
                req.body_truncated = True
            left = want
            while left > 0:
                if not self.buf and not await more():
                    raise ClientGone
                n = min(left, len(self.buf))
                take(self.buf[:n])
                del self.buf[:n]
                left -= n
                await self.tick()
        req.body = bytes(kept)
        req.body_len = total
        req.body_sha256 = sha.hexdigest() if total else ""
        if total > cfg.body_cap:
            req.body_truncated = True

    async def _line(self, more, limit: int) -> bytes:  # type: ignore[no-untyped-def]
        while True:
            idx = self.buf.find(b"\n")
            if idx >= 0:
                line = bytes(self.buf[:idx]).rstrip(b"\r")
                del self.buf[: idx + 1]
                return line
            if len(self.buf) > limit:
                raise HttpError(400, "Bad Request")
            if not await more():
                raise ClientGone


def _find_end(buf: bytearray) -> tuple[int, int]:
    """Position and length of the blank line that ends the head, or (-1, 0)."""
    a = buf.find(b"\r\n\r\n")
    b = buf.find(b"\n\n")
    if a >= 0 and (b < 0 or a < b):
        return a, 4
    if b >= 0:
        return b, 2
    return -1, 0


def parse_head(raw: bytes, cfg: Config) -> Request:
    """Parse a request head; HttpError for anything Go would refuse."""
    lines = raw.split(b"\n")
    first = lines[0].rstrip(b"\r")
    if len(first) > cfg.request_line_limit:
        raise HttpError(414, "Request-URI Too Long")
    parts = first.split(b" ")
    if len(parts) != 3:
        raise HttpError(400, "Bad Request")
    method, target, version = (p.decode("latin-1") for p in parts)
    if not method or not all(c in _METHOD for c in method) or len(method) > 32:
        raise HttpError(400, "Bad Request")
    if version not in ("HTTP/1.0", "HTTP/1.1"):
        major, _, minor = version[5:].partition(".")
        well_formed = version.startswith("HTTP/") and major.isdigit() and minor.isdigit()
        if well_formed and major != "1":
            raise HttpError(505, "HTTP Version Not Supported")
        raise HttpError(400, "")
    if not target.startswith("/") and target != "*":
        raise HttpError(400, "Bad Request")
    req = Request(method=method, target=target, version=version)
    path, _, query = target.partition("?")
    req.path = path
    req.query_raw = query.partition("#")[0]
    for line in lines[1:]:
        line = line.rstrip(b"\r")
        if not line:
            continue
        if len(req.headers) >= cfg.max_headers:
            raise HttpError(431, "Request Header Fields Too Large")
        name, sep, value = line.partition(b":")
        text = name.decode("latin-1")
        if not sep or not text or not all(c in _TOKEN for c in text):
            raise HttpError(400, "Bad Request")
        req.headers.append((text, value.strip(b" \t").decode("latin-1")))
    if version == "HTTP/1.1" and req.header("host") is None:
        raise HttpError(400, "Bad Request: missing required Host header")
    return req

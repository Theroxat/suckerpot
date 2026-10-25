"""HTTP/1.x request reading with Apache's behaviour for good and bad input.

Hand written on purpose: general-purpose HTTP servers normalise or reject malformed requests
in ways that identify them (lower-cased header names, their own error bodies, no HTTP/0.9, ...).
Every read here has a deadline, every buffer a limit, and no regular expressions are used.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from web_sensor import apache
from web_sensor.config import Config

# Bytes that may appear in a request line or header value: everything but C0 controls and DEL.
# (HTAB is allowed in header values only and handled there.)
_CTL_DELETE = bytes(range(0x20, 0x7F)) + bytes(range(0x80, 0x100))
_HOST_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._:[]")
_HEX = frozenset("0123456789abcdefABCDEF")


class HttpError(Exception):
    """A request that Apache would answer with an error page."""

    def __init__(
        self, status: int, extra: str = "", *, close: bool = True, host: bool = True
    ) -> None:
        super().__init__(status)
        self.status = status
        self.extra = extra
        self.close = close
        self.host = host  # False: the page names the server address, not the Host header
        self.req: Request | None = None


class IdleTimeout(Exception):
    """No (further) request arrived in time. The connection is closed silently."""


class HeaderTimeout(Exception):
    """The request head or body did not arrive in time: Apache answers 408."""


class ClientGone(Exception):
    """The peer closed the connection (possibly mid-request)."""


def to_text(raw: str) -> str:
    """Convert a latin-1 view of wire bytes back to text (UTF-8, lossy)."""
    return raw.encode("latin-1", "replace").decode("utf-8", "replace")


@dataclass
class Request:
    method: str = ""
    target: str = ""  # request target as sent (latin-1 view of the wire bytes)
    path: str = ""  # path part of the target, still percent-encoded
    query: str = ""
    version: str = "HTTP/1.1"
    http09: bool = False
    headers: list[tuple[str, str]] = field(default_factory=list)
    host: str | None = None  # lower-cased host name, no port
    host_port: int | None = None
    content_length: int | None = None
    chunked: bool = False
    expect_continue: bool = False
    body: bytes = b""  # first analysis_cap bytes of the body
    body_len: int = 0  # bytes read (up to the body cap)
    body_sha256: str = ""
    body_truncated: bool = False  # more body existed than what was read
    body_seconds: float = 0.0
    head_bytes: int = 0
    _ci: dict[str, str] = field(default_factory=dict, repr=False)

    def header(self, name: str) -> str | None:
        return self._ci.get(name.lower())

    def release(self) -> None:
        """Drop the bulky parts once the response is built: writing it to a slow peer can take
        a long time, and the head (up to 128 KB) and body prefix are no longer needed."""
        self.headers = []
        self._ci = {}
        self.body = b""

    def finalize_headers(self) -> None:
        ci: dict[str, str] = {}
        for k, v in self.headers:
            lk = k.lower()
            ci[lk] = f"{ci[lk]}, {v}" if lk in ci else v
        self._ci = ci

    @property
    def minor(self) -> int:
        """HTTP minor version used for behaviour (Apache treats anything >= 1.1 alike)."""
        try:
            major, _, minor = self.version[5:].partition(".")
            return 1 if (int(major) > 1 or int(minor or 0) >= 1) else 0
        except ValueError:
            return 1

    def connection_tokens(self) -> set[str]:
        raw = self.header("connection") or ""
        return {t.strip().lower() for t in raw.split(",")[:16]}


def _valid_host(value: str) -> tuple[str, int | None] | None:
    """Validate a Host header or URI authority; return (lower-cased name, port)."""
    if not value or len(value) > 255 or not all(c in _HOST_CHARS for c in value):
        return None
    name, port = value, None
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            return None
        name, rest = value[: end + 1], value[end + 1 :]
        if rest:
            if not rest.startswith(":"):
                return None
            port_s = rest[1:]
            if port_s and not (port_s.isdigit() and len(port_s) <= 5):
                return None
            port = int(port_s) if port_s else None
    elif ":" in value:
        name, _, port_s = value.partition(":")
        if ":" in port_s or (port_s and not (port_s.isdigit() and len(port_s) <= 5)):
            return None
        port = int(port_s) if port_s else None
    if not name:
        return None
    if port is not None and port > 65535:
        return None
    return name.lower(), port


class ConnReader:
    """Reads requests (and their bodies) from one connection."""

    def __init__(self, reader: asyncio.StreamReader, cfg: Config) -> None:
        self._r = reader
        self._cfg = cfg
        self.buf = bytearray()
        self.bytes_in = 0
        self.raw_head = bytearray()  # first bytes of the current request head (for forensics)
        self._head_base = 0

    # -- low level -------------------------------------------------------------------------

    async def _fill(self, limit: float) -> None:
        try:
            data = await asyncio.wait_for(self._r.read(16384), max(limit, 0.001))
        except TimeoutError:
            raise HeaderTimeout from None
        except (ConnectionError, OSError):
            raise ClientGone from None
        if not data:
            raise ClientGone
        self.bytes_in += len(data)
        self.buf += data

    def _head_timeout(self, start: float) -> float:
        cfg = self._cfg
        received = self.bytes_in - self._head_base
        limit = min(cfg.header_timeout_max, cfg.header_timeout + received / cfg.body_min_rate)
        return start + limit - time.monotonic()

    async def _line(self, start: float, limit: int, *, request_line: bool) -> bytes:
        """Return one line without its CRLF. Bare LF is a 400 like Apache's strict mode."""
        while True:
            idx = self.buf.find(b"\n")
            if idx != -1:
                if idx > limit + 1:
                    raise self._too_long(request_line)
                line = bytes(self.buf[:idx])
                del self.buf[: idx + 1]
                if len(self.raw_head) < 4096:
                    self.raw_head += line[:1024] + b"\n"
                if not line.endswith(b"\r"):
                    raise HttpError(400)
                return line[:-1]
            if len(self.buf) > limit + 2:
                raise self._too_long(request_line)
            await self._fill(self._head_timeout(start))

    @staticmethod
    def _too_long(request_line: bool) -> HttpError:
        if request_line:
            return HttpError(414)
        return HttpError(400, apache.EXTRA_HEADER_SIZE)

    # -- request head ----------------------------------------------------------------------

    async def read_request(self, *, first: bool) -> Request | None:
        """Read the next request head. ``None`` means the peer is done (EOF, idle timeout)."""
        cfg = self._cfg
        idle = cfg.first_byte_timeout if first else cfg.keepalive_timeout
        if not self.buf:
            try:
                data = await asyncio.wait_for(self._r.read(16384), idle)
            except TimeoutError:
                return None
            except (ConnectionError, OSError):
                return None
            if not data:
                return None
            self.bytes_in += len(data)
            self.buf += data
        start = time.monotonic()
        self._head_base = self.bytes_in - len(self.buf)
        self.raw_head = bytearray()
        req = Request()
        try:
            await self._read_head(req, start)
        except HttpError as err:
            err.req = req
            raise
        finally:
            req.head_bytes = self.bytes_in - self._head_base - len(self.buf)
        return req

    async def _read_head(self, req: Request, start: float) -> None:
        cfg = self._cfg
        # Apache skips a few empty lines before the request line.
        for _ in range(8):
            line = await self._line(start, cfg.request_line_limit, request_line=True)
            if line:
                break
        else:
            raise HttpError(400)
        self._parse_request_line(req, line)
        if req.http09:
            req.finalize_headers()
            return
        total = 0
        fields = 0
        while True:
            line = await self._line(start, cfg.header_line_limit, request_line=False)
            if not line:
                break
            total += len(line) + 2
            if total > cfg.max_header_bytes:
                raise HttpError(400, apache.EXTRA_HEADER_SIZE)
            if line[0] in (0x20, 0x09):  # obsolete line folding
                if not req.headers:
                    raise HttpError(400)
                k, v = req.headers[-1]
                if len(v) < 8190:
                    room = 8190 - len(v) - 1
                    req.headers[-1] = (k, v + " " + line[:room].decode("latin-1").strip(" \t"))
                continue
            fields += 1
            if fields > cfg.max_headers:
                raise HttpError(400, apache.EXTRA_HEADER_COUNT)
            name_b, sep, value_b = line.partition(b":")
            if not sep:
                raise HttpError(400)
            name = name_b.decode("latin-1")
            if not apache.is_token(name):
                raise HttpError(400)
            # No control characters in values (HTAB is fine).
            if value_b.replace(b"\t", b"").translate(None, _CTL_DELETE):
                raise HttpError(400)
            req.headers.append((name, value_b.decode("latin-1").strip(" \t")))
        req.finalize_headers()
        self._interpret_headers(req)

    @staticmethod
    def _parse_request_line(req: Request, line: bytes) -> None:
        if line.translate(None, _CTL_DELETE):
            raise HttpError(400)
        parts = line.split(b" ")
        if len(parts) not in (2, 3) or not all(parts):
            raise HttpError(400)
        method = parts[0].decode("latin-1")
        target = parts[1].decode("latin-1")
        if not apache.is_token(method):
            raise HttpError(400)
        req.method = method
        req.target = target
        if len(parts) == 2:
            if method != "GET":
                raise HttpError(400)
            req.http09 = True
            req.version = "HTTP/0.9"
        else:
            proto = parts[2].decode("latin-1")
            if not proto.startswith("HTTP/"):
                raise HttpError(400)
            major, dot, minor = proto[5:].partition(".")
            if (
                not dot
                or not major.isdigit()
                or not minor.isdigit()
                or len(major) > 3
                or len(minor) > 3
            ):
                raise HttpError(400)
            if int(major) == 0:
                raise HttpError(400)
            req.version = proto
        if "#" in target:
            raise HttpError(400)
        path = target
        if target.startswith("/"):
            pass
        elif target == "*":
            if method != "OPTIONS":
                raise HttpError(400)
        elif method == "CONNECT":
            auth = _valid_host(target)
            if auth is None:
                raise HttpError(400)
            req.host, req.host_port = auth
            req.path = target
            return
        elif "://" in target:
            scheme, _, rest = target.partition("://")
            if (
                not scheme
                or not scheme[0].isalpha()
                or not all(c.isalnum() or c in "+-." for c in scheme)
            ):
                raise HttpError(400)
            authority, slash, tail = rest.partition("/")
            authority = authority.split("?", 1)[0]
            auth = _valid_host(authority.rpartition("@")[2])
            if auth is None:
                raise HttpError(400)
            req.host, req.host_port = auth
            path = "/" + tail if slash else "/"
            if not slash and "?" in rest:
                path = "/?" + rest.partition("?")[2]
        else:
            raise HttpError(400)
        path, _, query = path.partition("?")
        req.path = path
        req.query = query

    @staticmethod
    def _interpret_headers(req: Request) -> None:
        hosts = [v for k, v in req.headers if k.lower() == "host"]
        if len(hosts) > 1:
            raise HttpError(400)
        if hosts:
            auth = _valid_host(hosts[0])
            if auth is None:
                raise HttpError(400)
            if req.host is None:  # an absolute URI wins over the Host header
                req.host, req.host_port = auth
        elif req.minor >= 1 and req.method != "CONNECT":
            raise HttpError(400)
        te = req.header("transfer-encoding")
        cl = req.header("content-length")
        if te is not None:
            if te.strip().lower() != "chunked":
                raise HttpError(400, host=False)
            req.chunked = True
        elif cl is not None:
            if not cl.isascii() or not cl.isdigit() or len(cl) > 18:
                raise HttpError(400, host=False)
            req.content_length = int(cl)
        expect = req.header("expect")
        req.expect_continue = bool(expect and expect.strip().lower() == "100-continue")

    # -- body ------------------------------------------------------------------------------

    def _body_timeout(self, start: float, received: int) -> float:
        cfg = self._cfg
        limit = min(cfg.body_total_timeout, cfg.body_timeout + received / cfg.body_min_rate)
        return start + limit - time.monotonic()

    async def read_body(
        self,
        req: Request,
        send_continue: Callable[[], Awaitable[None]] | None = None,
        retain: int | None = None,
    ) -> None:
        """Read the body into the request (retaining only a bounded prefix).

        Raises ``HttpError(413)`` when it exceeds the cap; ``req`` then holds what was read.
        """
        cfg = self._cfg
        if req.chunked:
            pass
        elif req.content_length:
            if req.content_length > cfg.body_cap:
                req.body_truncated = True
                raise HttpError(413)
        else:
            return
        if req.expect_continue and send_continue is not None:
            await send_continue()
        start = time.monotonic()
        digest = hashlib.sha256()
        keep = bytearray()
        keep_cap = retain if retain is not None else cfg.analysis_cap

        def take(data: bytes | bytearray) -> None:
            digest.update(data)
            req.body_len += len(data)
            room = keep_cap - len(keep)
            if room > 0:
                keep.extend(data[:room])

        try:
            if req.chunked:
                await self._read_chunked(req, start, take)
            else:
                remaining = req.content_length or 0
                while remaining:
                    if not self.buf:
                        await self._fill(self._body_timeout(start, req.body_len))
                    n = min(remaining, len(self.buf))
                    take(self.buf[:n])
                    del self.buf[:n]
                    remaining -= n
        finally:
            req.body = bytes(keep)
            req.body_sha256 = digest.hexdigest()
            req.body_seconds = time.monotonic() - start

    async def _body_line(self, start: float, req: Request) -> bytes:
        while True:
            idx = self.buf.find(b"\n")
            if idx != -1:
                line = bytes(self.buf[:idx]).rstrip(b"\r")
                del self.buf[: idx + 1]
                return line
            if len(self.buf) > 4096:
                raise HttpError(400)
            await self._fill(self._body_timeout(start, req.body_len))

    async def _read_chunked(
        self, req: Request, start: float, take: Callable[[bytes | bytearray], None]
    ) -> None:
        cfg = self._cfg
        while True:
            line = await self._body_line(start, req)
            size_s = line.split(b";", 1)[0].strip().decode("latin-1")
            if not size_s or len(size_s) > 8 or not all(c in _HEX for c in size_s):
                raise HttpError(400)
            size = int(size_s, 16)
            if size == 0:
                for _ in range(64):  # trailers
                    if not await self._body_line(start, req):
                        return
                raise HttpError(400)
            if req.body_len + size > cfg.body_cap:
                # Record what fits, then answer 413 like Apache does for oversized bodies.
                room = cfg.body_cap - req.body_len
                while room > 0:
                    if not self.buf:
                        await self._fill(self._body_timeout(start, req.body_len))
                    n = min(room, len(self.buf))
                    take(self.buf[:n])
                    del self.buf[:n]
                    room -= n
                req.body_truncated = True
                raise HttpError(413)
            remaining = size
            while remaining:
                if not self.buf:
                    await self._fill(self._body_timeout(start, req.body_len))
                n = min(remaining, len(self.buf))
                take(self.buf[:n])
                del self.buf[:n]
                remaining -= n
            if await self._body_line(start, req):  # the CRLF after the chunk data
                raise HttpError(400)

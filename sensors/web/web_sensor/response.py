"""Responses and their serialisation, with Apache's header order.

Observed order (2.4.58 + mod_php, mod_deflate on):

* error pages: ``Date, Server, [Allow|Location], Content-Length, [Keep-Alive], [Connection],
  Content-Type``
* static files: ``Date, Server, Last-Modified, ETag, Accept-Ranges, Content-Length, [Vary],
  [Keep-Alive], [Connection], Content-Type``; with gzip ``Vary, Content-Encoding`` come before
  ``Content-Length``
* PHP: ``Date, Server, [X-Powered-By], <headers sent by the script>, Vary, [Content-Encoding],
  Content-Length | Transfer-Encoding, [Keep-Alive], [Connection], Content-Type``
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from web_sensor import apache

Kind = Literal["error", "static", "php"]

# Apache switches from Content-Length to chunked once the output reaches this many bytes.
PHP_BUFFER_LIMIT = 8000


@dataclass
class Response:
    status: int = 200
    body: bytes = b""
    content_type: str | None = None
    headers: list[tuple[str, str]] = field(default_factory=list)
    kind: Kind = "error"
    close: bool = False  # the connection cannot be kept alive after this response
    last_modified: float | None = None  # static files
    accept_ranges: bool = False
    no_length: bool = False  # Apache 413 pages carry no Content-Length
    gzip_ok: bool = True
    content_range: str | None = None  # 206 responses: sent after Content-Length and Vary
    full_len: int = 0  # size of the whole entity when body is a range of it
    chunked: bool = False  # error pages Apache sends chunked (416)
    xpb: bool = True  # PHP responses carry X-Powered-By (autoindex pages are PHP-ordered, not PHP)
    packed: bytes | None = None  # gzip of ``body`` computed (and cached) by the handler
    app: str = ""  # which fake application answered (for events)
    route: str = ""


@dataclass
class RenderContext:
    method: str
    minor: int
    accept_encoding: str | None
    server_token: str
    php_version: str
    expose_php: bool
    date: str
    persist: bool  # the connection stays open after this response
    keepalive_header: bool  # client asked for keep-alive explicitly: add Keep-Alive/Connection
    keepalive_left: int
    keepalive_timeout: int


def _status_line(status: int) -> str:
    return f"HTTP/1.1 {status} {apache.STATUS_TEXT.get(status, 'Unknown')}\r\n"


def render(resp: Response, ctx: RenderContext) -> tuple[bytes, bool]:
    """Serialise a response. Returns (wire bytes, whether the connection stays open)."""
    head_only = ctx.method == "HEAD"
    body = resp.body
    lines: list[tuple[str, str]] = [("Date", ctx.date), ("Server", ctx.server_token)]
    if resp.kind == "php" and resp.xpb and ctx.expose_php:
        lines.append(("X-Powered-By", f"PHP/{ctx.php_version}"))
    lines.extend(resp.headers)

    ctype = resp.content_type
    gzip_used = False
    eligible = (
        resp.kind != "error"
        and ctype is not None
        and apache.deflate_eligible(ctype)
        and resp.status in (200, 206, 404)
        and max(len(body), resp.full_len) > 16
    )
    chunked = False
    wants_gzip = eligible and resp.gzip_ok and apache.accepts_gzip(ctx.accept_encoding)
    if wants_gzip:
        packed = resp.packed if resp.packed is not None else apache.gzip_bytes(body)
        if len(packed) < len(body):
            body = packed
            gzip_used = True

    length_headers: list[tuple[str, str]] = []
    if resp.status == 304:
        pass
    elif resp.kind == "static":
        if gzip_used:
            # ETag gets a "-gzip" suffix when the representation is compressed.
            lines = [(k, _gzip_etag(v)) if k == "ETag" else (k, v) for k, v in lines]
            lines.append(("Vary", "Accept-Encoding"))
            lines.append(("Content-Encoding", "gzip"))
            length_headers.append(("Content-Length", str(len(body))))
        else:
            length_headers.append(("Content-Length", str(len(body))))
            if eligible:
                length_headers.append(("Vary", "Accept-Encoding"))
        if resp.content_range:
            length_headers.append(("Content-Range", resp.content_range))
    elif resp.kind == "php":
        if eligible and not head_only:
            lines.append(("Vary", "Accept-Encoding"))
        if gzip_used:
            lines.append(("Content-Encoding", "gzip"))
            length_headers.append(("Content-Length", str(len(body))))
        elif head_only:
            pass
        elif len(body) < PHP_BUFFER_LIMIT:
            length_headers.append(("Content-Length", str(len(body))))
        elif ctx.minor >= 1:
            length_headers.append(("Transfer-Encoding", "chunked"))
            chunked = True
        # HTTP/1.0 and large: no length, the connection closes to delimit the body
    elif resp.chunked:
        if not head_only:
            length_headers.append(("Transfer-Encoding", "chunked"))
            chunked = True
    else:
        if not resp.no_length and not (head_only and resp.kind == "error"):
            length_headers.append(("Content-Length", str(len(body))))
    lines.extend(length_headers)

    persist = ctx.persist
    if resp.kind == "php" and not chunked and not gzip_used and not head_only:
        if len(body) >= PHP_BUFFER_LIMIT:
            persist = False  # close-delimited body (HTTP/1.0)
    if resp.no_length:
        persist = False
    if resp.close:
        persist = False
    if persist and ctx.keepalive_header:
        lines.append(("Keep-Alive", f"timeout={ctx.keepalive_timeout}, max={ctx.keepalive_left}"))
        lines.append(("Connection", "Keep-Alive"))
    elif not persist:
        lines.append(("Connection", "close"))
    if ctype is not None and resp.status != 304:
        lines.append(("Content-Type", ctype))

    out = bytearray(_status_line(resp.status).encode("ascii"))
    for k, v in lines:
        out += f"{k}: {v}\r\n".encode("latin-1", "replace")
    out += b"\r\n"
    parts: list[bytes | bytearray] = [out]
    if not head_only and resp.status not in (204, 304):
        if chunked and body:
            parts += [f"{len(body):x}\r\n".encode("ascii"), body, b"\r\n0\r\n\r\n"]
        elif chunked:
            parts.append(b"0\r\n\r\n")
        else:
            parts.append(body)
    return b"".join(parts), persist  # one copy of the body, not three


def _gzip_etag(value: str) -> str:
    return value[:-1] + '-gzip"' if value.endswith('"') else value

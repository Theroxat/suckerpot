"""Apache 2.4 (Ubuntu) response conventions: status texts, error pages, dates, ETags, gzip.

The error pages are byte-identical to what ``apache2 2.4.58-1ubuntu8`` sends (they were diffed
against a reference server, see README). Keep the templates exactly as they are.
"""

from __future__ import annotations

import html
import time
import zlib
from email.utils import formatdate

STATUS_TEXT: dict[int, str] = {
    100: "Continue",
    200: "OK",
    206: "Partial Content",
    301: "Moved Permanently",
    302: "Found",
    304: "Not Modified",
    400: "Bad Request",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    408: "Request Timeout",
    413: "Request Entity Too Large",
    414: "Request-URI Too Long",
    416: "Requested Range Not Satisfiable",
    500: "Internal Server Error",
    501: "Not Implemented",
    503: "Service Unavailable",
}

# Methods Apache knows (anything else gets 501). It answers 405 to the ones the target does not
# handle, with ``Allow: GET,POST,OPTIONS,HEAD``.
KNOWN_METHODS = frozenset(
    {
        "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
        "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "VERSION-CONTROL",
        "REPORT", "CHECKOUT", "CHECKIN", "UNCHECKOUT", "MKWORKSPACE", "UPDATE", "LABEL", "MERGE",
        "BASELINE-CONTROL", "MKACTIVITY", "ORDERPATCH", "ACL", "SEARCH",
    }
)  # fmt: skip
ALLOW_DEFAULT = "GET,POST,OPTIONS,HEAD"

_TOKEN_CHARS = frozenset(
    "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

_HEAD = (
    '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n'
    "<html><head>\n"
    "<title>{code} {title}</title>\n"
    "</head><body>\n"
    "<h1>{title}</h1>\n"
)
_TAIL = "<hr>\n<address>{server} Server at {host} Port {port}</address>\n</body></html>\n"

_MSG: dict[int, str] = {
    400: "<p>Your browser sent a request that this server could not understand.<br />\n{extra}</p>\n",
    403: "<p>You don't have permission to access this resource.</p>\n",
    404: "<p>The requested URL was not found on this server.</p>\n",
    405: "<p>The requested method {method} is not allowed for this URL.</p>\n",
    408: "<p>Server timeout waiting for the HTTP request from the client.</p>\n",
    413: (
        "The requested resource does not allow request data with {method} requests, or the "
        "amount of data provided in\nthe request exceeds the capacity limit.\n"
    ),
    414: "<p>The requested URL's length exceeds the capacity\nlimit for this server.<br />\n</p>\n",
    416: (
        "<p>None of the range-specifier values in the Range\n"
        "request-header field overlap the current extent\n"
        "of the selected resource.</p>\n"
    ),
    500: (
        "<p>The server encountered an internal error or\n"
        "misconfiguration and was unable to complete\n"
        "your request.</p>\n"
        "<p>Please contact the server administrator at \n"
        " webmaster@localhost to inform them of the time this error occurred,\n"
        " and the actions you performed just before this error.</p>\n"
        "<p>More information about this error may be available\n"
        "in the server error log.</p>\n"
    ),
    501: "<p>{method} not supported for current URL.<br />\n</p>\n",
    503: (
        "<p>The server is temporarily unable to service your\n"
        "request due to maintenance downtime or capacity\n"
        "problems. Please try again later.</p>\n"
    ),
    301: '<p>The document has moved <a href="{url}">here</a>.</p>\n',
    302: '<p>The document has moved <a href="{url}">here</a>.</p>\n',
}

# Extra lines Apache adds to the 400 page for specific causes.
EXTRA_HEADER_SIZE = "Size of a request header field exceeds server limit."
EXTRA_HEADER_COUNT = "The number of request header fields exceeds this server's limit."
EXTRA_PLAIN_HTTP = (
    "Reason: You're speaking plain HTTP to an SSL-enabled server port.<br />\n"
    " Instead use the HTTPS scheme to access this URL, please.<br />\n"
)


def is_token(value: str) -> bool:
    return bool(value) and all(c in _TOKEN_CHARS for c in value)


def error_page(
    status: int,
    *,
    server: str,
    host: str,
    port: int,
    method: str = "",
    url: str = "",
    extra: str = "",
) -> bytes:
    """The HTML body of an Apache-generated error page."""
    title = STATUS_TEXT[status]
    esc = html.escape
    body = _HEAD.format(code=status, title=title)
    body += _MSG[status].format(method=esc(method), url=esc(url), extra=extra)
    body += _TAIL.format(server=server, host=esc(host), port=port)
    return body.encode("utf-8")


def http_date(ts: float | None = None) -> str:
    return formatdate(ts, usegmt=True)


class DateCache:
    """``Date`` header value, recomputed at most once per second."""

    def __init__(self) -> None:
        self._sec = 0
        self._value = ""

    def now(self) -> str:
        sec = int(time.time())
        if sec != self._sec:
            self._sec = sec
            self._value = http_date(sec)
        return self._value


def etag(size: int, mtime: float, *, gzip: bool = False) -> str:
    """Apache's default FileETag: ``"<size hex>-<mtime in microseconds, hex>"``."""
    value = f"{size:x}-{int(mtime * 1_000_000):x}"
    return f'"{value}-gzip"' if gzip else f'"{value}"'


def parse_http_date(value: str) -> float | None:
    from email.utils import parsedate_to_datetime

    try:
        return parsedate_to_datetime(value).timestamp()
    except (TypeError, ValueError, IndexError, OverflowError):
        return None


def gzip_bytes(data: bytes) -> bytes:
    """Gzip stream with the header mod_deflate writes (no mtime, OS = Unix)."""
    comp = zlib.compressobj(6, zlib.DEFLATED, -15)
    body = comp.compress(data) + comp.flush()
    trailer = zlib.crc32(data).to_bytes(4, "little") + (len(data) & 0xFFFFFFFF).to_bytes(
        4, "little"
    )
    return b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03" + body + trailer


# Content types mod_deflate compresses in Ubuntu's default configuration.
DEFLATE_TYPES = frozenset(
    {
        "text/html",
        "text/plain",
        "text/xml",
        "text/css",
        "text/javascript",
        "application/x-javascript",
        "application/javascript",
        "application/ecmascript",
        "application/rss+xml",
        "application/wasm",
        "application/xml",
    }
)


def deflate_eligible(content_type: str) -> bool:
    return content_type.split(";", 1)[0].strip().lower() in DEFLATE_TYPES


def accepts_gzip(accept_encoding: str | None) -> bool:
    if not accept_encoding:
        return False
    for item in accept_encoding.split(",")[:16]:
        name, _, params = item.partition(";")
        if name.strip().lower() in ("gzip", "x-gzip"):
            q = params.strip().lower()
            return not (q.startswith("q=") and q[2:].strip() in ("0", "0.", "0.0", "0.00", "0.000"))
    return False

"""An HTTP CONNECT tunnel through the egress proxy, for ``smtplib`` (tunnel mode, README).

``smtplib`` has no proxy support, so in tunnel mode the worker opens the socket itself: CONNECT to
the SMTP host through the authenticated proxy, then TLS on top. There is no direct fallback.

Errors carry a constant ``code`` only: never the proxy's answer, its address or its credentials.
"""

from __future__ import annotations

import base64
import ipaddress
import os
import re
import socket
import time
from urllib.parse import unquote, urlsplit

PROXY_VARS = ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY")
MAX_HEADER_BYTES = 8192
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")


class TunnelError(OSError):
    """The proxy refused or broke the tunnel. ``code`` is a constant."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def proxy_url_from_env() -> str | None:
    """The first proxy variable that is set (upper case first, then lower case), else ``None``."""
    for name in PROXY_VARS:
        value = os.environ.get(name) or os.environ.get(name.lower())
        if value:
            return value
    return None


def _check_target(host: str, port: int) -> str:
    if not 0 < port < 65536:
        raise TunnelError("bad_port")
    bare = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        addr = ipaddress.ip_address(bare)
    except ValueError:
        if not _HOST_RE.match(bare):
            raise TunnelError("bad_host") from None
        return bare
    if not addr.is_global:  # a literal address must be public
        raise TunnelError("blocked_host")
    return f"[{addr}]" if addr.version == 6 else str(addr)


def _read_head(sock: socket.socket, deadline: float) -> bytes:
    head = b""
    while not head.endswith(b"\r\n\r\n"):
        if len(head) >= MAX_HEADER_BYTES or time.monotonic() > deadline:
            raise TunnelError("proxy_bad_answer")
        try:
            chunk = sock.recv(1)  # one byte: never swallow data that follows the headers
        except OSError:
            raise TunnelError("proxy_unreachable") from None
        if not chunk:
            raise TunnelError("proxy_closed")
        head += chunk
    return head


def connect_via_proxy(proxy_url: str, host: str, port: int, *, timeout: float) -> socket.socket:
    """CONNECT ``host:port`` through the proxy and return the connected socket."""
    target = _check_target(host, port)
    try:
        parts = urlsplit(proxy_url)
        proxy_host, proxy_port = parts.hostname, parts.port
    except ValueError:
        raise TunnelError("bad_proxy") from None
    if parts.scheme != "http" or not proxy_host or not proxy_port:
        raise TunnelError("bad_proxy")
    headers = f"CONNECT {target}:{port} HTTP/1.1\r\nHost: {target}:{port}\r\n"
    if parts.username is not None:
        cred = f"{unquote(parts.username)}:{unquote(parts.password or '')}".encode()
        headers += f"Proxy-Authorization: Basic {base64.b64encode(cred).decode()}\r\n"
    request = (headers + "\r\n").encode("ascii")
    deadline = time.monotonic() + timeout
    try:
        sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    except OSError:
        raise TunnelError("proxy_unreachable") from None
    try:
        sock.settimeout(timeout)
        sock.sendall(request)
        status = _read_head(sock, deadline).split(b"\r\n", 1)[0].split()
        if len(status) < 2 or status[1] != b"200":
            raise TunnelError("proxy_refused")
    except BaseException as exc:
        sock.close()
        if isinstance(exc, OSError) and not isinstance(exc, TunnelError):
            raise TunnelError("proxy_unreachable") from None
        raise
    return sock

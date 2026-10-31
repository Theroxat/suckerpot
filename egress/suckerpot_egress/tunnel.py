"""HTTP CONNECT through the proxy, for clients that need a raw socket (smtplib)."""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import re
import socket
import time
from urllib.parse import urlsplit

from suckerpot_egress.gate import EgressGate
from suckerpot_egress.settings import EgressSettings

MAX_HEADER_BYTES = 8192
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")


class TunnelError(OSError):
    """The proxy refused or broke the tunnel. ``code`` is a constant."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _check_target(host: str, port: int) -> str:
    """Return the host as it goes on the CONNECT line, or raise."""
    if not 0 < port < 65536:
        raise TunnelError("bad_port")
    bare = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        addr = ipaddress.ip_address(bare)
    except ValueError:
        if not _HOST_RE.match(bare):
            raise TunnelError("bad_host") from None
        return bare
    if not addr.is_global:  # literal addresses must be public
        raise TunnelError("blocked_host")
    return f"[{addr}]" if addr.version == 6 else str(addr)


def _read_head(sock: socket.socket, deadline: float) -> bytes:
    head = b""
    while not head.endswith(b"\r\n\r\n"):
        if len(head) >= MAX_HEADER_BYTES or time.monotonic() > deadline:
            raise TunnelError("bad_answer")
        chunk = sock.recv(1)  # one byte: never swallow data that follows the headers
        if not chunk:
            raise TunnelError("closed")
        head += chunk
    return head


def connect_via_proxy(
    settings: EgressSettings, host: str, port: int, *, timeout: float, validate: bool = True
) -> socket.socket:
    """CONNECT without the gate. ``validate=False`` is for the self-test only."""
    target = _check_target(host, port) if validate else host
    parts = urlsplit(settings.proxy_url)
    if not parts.hostname or not parts.port:
        raise TunnelError("bad_proxy")
    cred = f"{settings.proxy_user}:{settings.proxy_password}".encode()
    auth = base64.b64encode(cred).decode()
    request = (
        f"CONNECT {target}:{port} HTTP/1.1\r\nHost: {target}:{port}\r\n"
        f"Proxy-Authorization: Basic {auth}\r\n\r\n"
    ).encode("ascii")
    deadline = time.monotonic() + timeout
    try:
        sock = socket.create_connection((parts.hostname, parts.port), timeout=timeout)
    except OSError:
        raise TunnelError("proxy_unreachable") from None
    try:
        sock.settimeout(timeout)
        sock.sendall(request)
        status_line = _read_head(sock, deadline).split(b"\r\n", 1)[0].split()
        if len(status_line) < 2 or status_line[1] != b"200":
            raise TunnelError("refused")
    except BaseException:
        sock.close()
        raise
    return sock


def open_tunnel_sync(gate: EgressGate, host: str, port: int, *, timeout: float) -> socket.socket:
    gate.require_open()
    try:
        sock = connect_via_proxy(gate.settings, host, port, timeout=timeout)
    except TunnelError as exc:
        if exc.code == "proxy_unreachable":
            gate.note_proxy_error()
        raise
    gate.note_proxy_ok()
    return sock


async def open_tunnel(gate: EgressGate, host: str, port: int, *, timeout: float) -> socket.socket:  # noqa: ASYNC109 - the public signature takes a timeout
    """CONNECT host:port through the proxy; returns a connected, blocking socket."""
    return await asyncio.to_thread(open_tunnel_sync, gate, host, port, timeout=timeout)

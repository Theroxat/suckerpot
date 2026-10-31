"""Fakes: a control + echo transport, a fake CONNECT proxy and a fake SMTP server."""

from __future__ import annotations

import socketserver
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx

from suckerpot_egress import EgressGate, EgressSettings

VPN_IP = "9.9.9.77"


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def settings(**kw: object) -> EgressSettings:
    base: dict[str, object] = {
        "proxy_url": "http://127.0.0.1:1",
        "proxy_password": "x" * 24,
        "control_url": "http://vpn:8000",
        "echo_urls": ("https://echo-a.test", "https://echo-b.test"),
        "allowed_cidrs": (__import__("ipaddress").ip_network("9.9.9.0/24"),),
    }
    base.update(kw)
    return EgressSettings(**base)  # type: ignore[arg-type]


def fake_world(
    *,
    vpn: str | None = "running",  # None: vpn unreachable
    public_ip: str | None = VPN_IP,
    echo: dict[str, str | None] | None = None,
    vpn_status_code: int = 200,
) -> Callable[[httpx.Request], httpx.Response]:
    answers = echo or {"echo-a.test": VPN_IP, "echo-b.test": VPN_IP}

    def handler(request: httpx.Request) -> httpx.Response:
        host, path = request.url.host, request.url.path
        if host == "vpn":
            if vpn is None:
                raise httpx.ConnectError("down")
            if path == "/v1/vpn/status":
                return httpx.Response(vpn_status_code, json={"status": vpn})
            if path == "/v1/publicip/ip":
                if public_ip is None:
                    return httpx.Response(200, json={"public_ip": ""})
                return httpx.Response(200, json={"public_ip": public_ip})
        if host in answers:
            body = answers[host]
            if body is None:
                raise httpx.ConnectError("no route")
            return httpx.Response(200, text=body + "\n")
        return httpx.Response(404)

    return handler


def gate_for(
    handler: Callable[[httpx.Request], httpx.Response], clock: Clock | None = None, **kw: object
) -> EgressGate:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return EgressGate(settings(**kw), client=client, clock=clock or Clock())


async def open_gate(clock: Clock | None = None, **kw: object) -> EgressGate:
    gate = gate_for(fake_world(), clock, **kw)
    status = await gate.check()
    assert status.open, status.reason
    return gate


class FakeProxy:
    """Accepts CONNECT, records it, and bridges to a fake upstream for the host ``smtp.test``."""

    def __init__(self, *, answer: int = 200, upstream: tuple[str, int] | None = None) -> None:
        self.requests: list[str] = []
        self.answer = answer
        self.upstream = upstream
        proxy = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                data = b""
                while not data.endswith(b"\r\n\r\n"):
                    chunk = self.request.recv(1)
                    if not chunk:
                        return
                    data += chunk
                proxy.requests.append(data.decode())
                if proxy.answer != 200 or proxy.upstream is None:
                    self.request.sendall(f"HTTP/1.1 {proxy.answer} X\r\n\r\n".encode())
                    return
                import socket as _s

                up = _s.create_connection(proxy.upstream, timeout=5)
                self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                done = threading.Event()

                def pump(a: _s.socket, b: _s.socket) -> None:
                    try:
                        while chunk := a.recv(4096):
                            b.sendall(chunk)
                    except OSError:
                        pass
                    done.set()

                threading.Thread(target=pump, args=(up, self.request), daemon=True).start()
                pump(self.request, up)
                up.close()

        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class FakeSmtp:
    """A tiny SMTP server: greets, answers EHLO/NOOP/QUIT."""

    def __init__(self) -> None:
        self.lines: list[str] = []
        outer = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                self.wfile.write(b"220 mx.test ESMTP\r\n")
                while line := self.rfile.readline():
                    text = line.decode().strip()
                    outer.lines.append(text)
                    cmd = text.split(" ")[0].upper()
                    if cmd == "QUIT":
                        self.wfile.write(b"221 bye\r\n")
                        return
                    if cmd in ("EHLO", "HELO"):
                        self.wfile.write(b"250 mx.test\r\n")
                    else:
                        self.wfile.write(b"250 ok\r\n")

        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


# VPN_IP is a real public address on purpose: documentation ranges are not "global" for Python.

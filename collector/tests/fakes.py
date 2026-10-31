"""In-process fakes: a proxy that is also the origin, and an egress gate that is open.

The proxy listens on 127.0.0.1 only. Requests arrive as ``GET http://host/path`` (absolute form,
the way an HTTP proxy sees them) and are answered from a table, so nothing ever leaves the test
process: no real host is resolved or contacted.
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

import httpx
from suckerpot_egress import EgressGate, EgressSettings

VPN_IP = "9.9.9.77"


@dataclass
class Reply:
    status: int = 200
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    chunked: bool = False  # no Content-Length: the size is only known by reading
    declared_length: int | None = None  # a Content-Length that may lie
    delay: float = 0.0


class FakeProxy:
    def __init__(self, handler: Callable[[str, dict[str, str]], Reply]) -> None:
        self.handler = handler
        self.seen: list[tuple[str, dict[str, str]]] = []
        self.port = 0
        self._server: asyncio.Server | None = None

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            _method, target, _ = lines[0].split(" ", 2)
            headers = {
                k.lower(): v.strip() for k, _, v in (ln.partition(":") for ln in lines[1:] if ln)
            }
            self.seen.append((target, headers))
            reply = self.handler(target, headers)
            if reply.delay:
                await asyncio.sleep(reply.delay)
            out = [f"HTTP/1.1 {reply.status} X".encode(), b"Connection: close"]
            for k, v in reply.headers.items():
                out.append(f"{k}: {v}".encode())
            if reply.chunked:
                out.append(b"Transfer-Encoding: chunked")
            else:
                length = reply.declared_length
                out.append(
                    f"Content-Length: {len(reply.body) if length is None else length}".encode()
                )
            writer.write(b"\r\n".join(out) + b"\r\n\r\n")
            if reply.chunked:
                for i in range(0, len(reply.body), 8192):
                    part = reply.body[i : i + 8192]
                    writer.write(f"{len(part):x}\r\n".encode() + part + b"\r\n")
                    await writer.drain()
                writer.write(b"0\r\n\r\n")
            else:
                writer.write(reply.body)
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, ValueError):
            pass
        finally:
            writer.close()

    @asynccontextmanager
    async def running(self) -> AsyncIterator[FakeProxy]:
        self._server = await asyncio.start_server(self._serve, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        try:
            yield self
        finally:
            self._server.close()
            await self._server.wait_closed()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


def _world(request: httpx.Request) -> httpx.Response:
    host, path = request.url.host, request.url.path
    if host == "vpn" and path == "/v1/vpn/status":
        return httpx.Response(200, json={"status": "running"})
    if host == "vpn" and path == "/v1/publicip/ip":
        return httpx.Response(200, json={"public_ip": VPN_IP})
    if host in ("echo-a.test", "echo-b.test"):
        return httpx.Response(200, text=VPN_IP)
    return httpx.Response(404)


def egress_settings(proxy_url: str) -> EgressSettings:
    return EgressSettings(
        proxy_url=proxy_url,
        proxy_password="x" * 24,
        control_url="http://vpn:8000",
        echo_urls=("https://echo-a.test", "https://echo-b.test"),
        allowed_cidrs=(ipaddress.ip_network("9.9.9.0/24"),),
        check_interval_s=300,
    )


async def open_gate(proxy_url: str, *, open_: bool = True) -> EgressGate:
    """A gate whose self-check talks to an in-memory world (no network). Closed if not checked."""
    gate = EgressGate(
        egress_settings(proxy_url), client=httpx.AsyncClient(transport=httpx.MockTransport(_world))
    )
    if open_:
        status = await gate.check()
        assert status.open, status.reason
    return gate

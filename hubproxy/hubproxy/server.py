"""The proxy and control listeners.

Only an authenticated ``CONNECT <allowed name>:443`` is ever served. Nothing about a client or a
refused request is logged: the only observable output is a set of counters.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import socket
from collections import Counter
from collections.abc import Awaitable, Callable
from contextlib import suppress

from .addrs import is_global_unicast
from .config import HTTPS_PORT, Settings
from .httpwire import HEAD_LIMIT, BadRequest, Head, parse_head
from .sni import HelloError, read_client_hello

HEAD_TIMEOUT = 5.0
RESOLVE_TIMEOUT = 5.0
CONNECT_TIMEOUT = 10.0
IDLE_TIMEOUT = 60.0
TOTAL_TIMEOUT = 600.0
MAX_ADDRESSES = 4
CONTROL_MAX_CONNS = 8
CHUNK = 16384
USERNAME = "egress"

Resolver = Callable[[str], Awaitable[list[str]]]
Connector = Callable[[str, int], Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]]

_REASONS = {
    200: "Connection established",
    400: "Bad Request",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    407: "Proxy Authentication Required",
    502: "Bad Gateway",
    503: "Service Unavailable",
}


def _response(code: int, extra: str = "", body: bytes = b"") -> bytes:
    head = f"HTTP/1.1 {code} {_REASONS[code]}\r\n{extra}Content-Length: {len(body)}\r\n"
    return head.encode("ascii") + b"Connection: close\r\n\r\n" + body


# Constant answers: the body never depends on the request.
_ESTABLISHED = b"HTTP/1.1 200 Connection established\r\n\r\n"
_ANSWERS = {
    code: _response(code, 'Proxy-Authenticate: Basic realm="proxy"\r\n' if code == 407 else "")
    for code in (400, 403, 404, 405, 407, 502, 503)
}


async def default_resolver(host: str) -> list[str]:
    """Resolve IPv4 addresses only (the networks have no IPv6)."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, HTTPS_PORT, family=socket.AF_INET, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


async def default_connector(
    ip: str, port: int
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    # ``ip`` is an already vetted literal: no name is resolved here.
    return await asyncio.open_connection(ip, port)


async def resolve_bind_host(name: str) -> str:
    """Resolve ``name`` to exactly one IPv4 address, or raise OSError (fail closed)."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(name, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    addrs = {str(info[4][0]) for info in infos}
    if len(addrs) != 1:
        raise OSError(f"HUBPROXY_BIND_HOST must resolve to exactly one address, got {len(addrs)}")
    return addrs.pop()


def _digest(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


class HubProxy:
    def __init__(
        self,
        settings: Settings,
        resolver: Resolver = default_resolver,
        connector: Connector = default_connector,
    ) -> None:
        self.settings = settings
        self.allow = frozenset(settings.allow)
        self._expected = _digest(f"{USERNAME}:{settings.password}".encode())
        self._resolver = resolver
        self._connector = connector
        self.counters: Counter[str] = Counter()
        self._active = 0
        self._control_active = 0
        self._servers: list[asyncio.Server] = []

    # -- lifecycle -------------------------------------------------------------------------

    async def start(self) -> None:
        s = self.settings
        proxy_host: str | list[str] = s.bind
        control_host: str | list[str] = s.bind
        if s.bind_host:
            # Fail closed: exactly one address, only on the internal network. The control
            # listener also answers on loopback for the container healthcheck.
            addr = await resolve_bind_host(s.bind_host)
            proxy_host = addr
            control_host = [addr, "127.0.0.1"]
        proxy = await asyncio.start_server(
            self._handle_proxy, proxy_host, s.proxy_port, limit=HEAD_LIMIT, backlog=32
        )
        control = await asyncio.start_server(
            self._handle_control, control_host, s.control_port, limit=HEAD_LIMIT, backlog=8
        )
        self._servers = [proxy, control]

    def ports(self) -> tuple[int, int]:
        proxy, control = self._servers
        return int(proxy.sockets[0].getsockname()[1]), int(control.sockets[0].getsockname()[1])

    async def stop(self) -> None:
        for srv in self._servers:
            srv.close()
        for srv in self._servers:
            await srv.wait_closed()

    # -- shared helpers --------------------------------------------------------------------

    async def _read_head(self, reader: asyncio.StreamReader) -> Head | None:
        try:
            async with asyncio.timeout(HEAD_TIMEOUT):
                raw = await reader.readuntil(b"\r\n\r\n")
            return parse_head(raw)
        except (
            TimeoutError,
            asyncio.IncompleteReadError,
            asyncio.LimitOverrunError,
            BadRequest,
            ConnectionError,
        ):
            self.counters["bad_request"] += 1
            return None

    def _authorized(self, head: Head) -> bool:
        value = head.headers.get("proxy-authorization", "")
        scheme, _, token = value.partition(" ")
        supplied = b""
        if scheme.lower() == "basic":
            with suppress(binascii.Error, ValueError):
                supplied = base64.b64decode(token.strip(), validate=True)
        # Fixed-length digests compared in constant time.
        return hmac.compare_digest(_digest(supplied), self._expected)

    @staticmethod
    async def _close(writer: asyncio.StreamWriter) -> None:
        with suppress(Exception):
            writer.close()
            async with asyncio.timeout(2):
                await writer.wait_closed()

    @staticmethod
    async def _answer(writer: asyncio.StreamWriter, payload: bytes) -> None:
        with suppress(Exception):
            writer.write(payload)
            async with asyncio.timeout(2):
                await writer.drain()

    # -- proxy listener --------------------------------------------------------------------

    async def _handle_proxy(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if self._active >= self.settings.max_conns:
            self.counters["refused_busy"] += 1
            await self._answer(writer, _ANSWERS[503])
            await self._close(writer)
            return
        self._active += 1
        try:
            await self._serve_connect(reader, writer)
        except Exception:
            self.counters["errors"] += 1
        finally:
            self._active -= 1
            await self._close(writer)

    async def _serve_connect(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        head = await self._read_head(reader)
        if head is None:
            await self._answer(writer, _ANSWERS[400])
            return
        if head.method != "CONNECT":
            self.counters["refused_method"] += 1
            await self._answer(writer, _ANSWERS[405])
            return
        if not self._authorized(head):
            self.counters["refused_auth"] += 1
            await self._answer(writer, _ANSWERS[407])
            return
        if head.target.lower() not in self.allow:
            self.counters["refused_host"] += 1
            await self._answer(writer, _ANSWERS[403])
            return
        host = head.target.lower().rpartition(":")[0]
        upstream = await self._dial(host)
        if upstream is None:
            await self._answer(writer, _ANSWERS[502])
            return
        up_reader, up_writer = upstream
        try:
            await self._answer(writer, _ESTABLISHED)
            # The TLS server name must be the CONNECT host: no domain fronting through the CDN.
            try:
                first_flight, sni = await read_client_hello(reader)
            except HelloError:
                self.counters["refused_sni"] += 1
                return
            if sni != host:
                self.counters["refused_sni"] += 1
                return
            up_writer.write(first_flight)
            async with asyncio.timeout(IDLE_TIMEOUT):
                await up_writer.drain()
            self.counters["allowed"] += 1
            await self._relay(reader, writer, up_reader, up_writer)
        finally:
            await self._close(up_writer)

    async def _dial(self, host: str) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
        try:
            async with asyncio.timeout(RESOLVE_TIMEOUT):
                answers = await self._resolver(host)
        except TimeoutError, OSError:
            self.counters["refused_resolution"] += 1
            return None
        # Any non-global answer taints the whole response (rebinding or poisoned DNS).
        if not answers or not all(is_global_unicast(ip) for ip in answers):
            self.counters["refused_address"] += 1
            return None
        for ip in answers[:MAX_ADDRESSES]:
            try:
                async with asyncio.timeout(CONNECT_TIMEOUT):
                    return await self._connector(ip, HTTPS_PORT)
            except TimeoutError, OSError:
                continue
        self.counters["refused_connect"] += 1
        return None

    @staticmethod
    async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        try:
            while True:
                async with asyncio.timeout(IDLE_TIMEOUT):
                    chunk = await src.read(CHUNK)
                if not chunk:
                    break
                dst.write(chunk)
                async with asyncio.timeout(IDLE_TIMEOUT):
                    await dst.drain()
        except TimeoutError, OSError:
            pass
        finally:
            with suppress(Exception):
                if dst.can_write_eof():
                    dst.write_eof()

    async def _relay(
        self,
        c_reader: asyncio.StreamReader,
        c_writer: asyncio.StreamWriter,
        u_reader: asyncio.StreamReader,
        u_writer: asyncio.StreamWriter,
    ) -> None:
        tasks = [
            asyncio.create_task(self._pipe(c_reader, u_writer)),
            asyncio.create_task(self._pipe(u_reader, c_writer)),
        ]
        try:
            async with asyncio.timeout(TOTAL_TIMEOUT):
                await asyncio.gather(*tasks)
        except TimeoutError:
            self.counters["tunnel_expired"] += 1
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    # -- control listener ------------------------------------------------------------------

    def status(self) -> dict[str, object]:
        return {"mode": "direct", "allow": list(self.settings.allow), "ok": True}

    async def _handle_control(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if self._control_active >= CONTROL_MAX_CONNS:
            await self._close(writer)
            return
        self._control_active += 1
        try:
            head = await self._read_head(reader)
            if head is None:
                await self._answer(writer, _ANSWERS[400])
            elif head.method != "GET":
                await self._answer(writer, _ANSWERS[405])
            elif head.target != "/status":
                await self._answer(writer, _ANSWERS[404])
            else:
                body = json.dumps(self.status(), separators=(",", ":")).encode()
                await self._answer(
                    writer, _response(200, "Content-Type: application/json\r\n", body)
                )
        except Exception:
            self.counters["errors"] += 1
        finally:
            self._control_active -= 1
            await self._close(writer)

from __future__ import annotations

import asyncio
import base64
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field

from hubproxy.config import Settings
from hubproxy.server import HubProxy

PASSWORD = "correct-horse-battery-staple"
ALLOW = "hub.selfhostr.io"
GLOBAL_IP = "8.8.8.8"  # only ever handed to the fake connector, never dialled


def basic(password: str = PASSWORD, user: str = "egress") -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def connect_request(
    target: str = f"{ALLOW}:443",
    auth: str | None = None,
    method: str = "CONNECT",
    extra: str = "",
) -> bytes:
    auth = basic() if auth is None else auth
    lines = [f"{method} {target} HTTP/1.1", f"Host: {target}"]
    if auth:
        lines.append(f"Proxy-Authorization: {auth}")
    text = "\r\n".join(lines) + "\r\n" + extra + "\r\n"
    return text.encode()


@dataclass
class Fakes:
    answers: dict[str, list[str]] = field(default_factory=lambda: {ALLOW: [GLOBAL_IP]})
    resolved: list[str] = field(default_factory=list)
    dialled: list[tuple[str, int]] = field(default_factory=list)
    echo_servers: list[asyncio.AbstractServer] = field(default_factory=list)
    echo_port: int = 0
    fail_connect: bool = False

    async def resolve(self, host: str) -> list[str]:
        self.resolved.append(host)
        return self.answers.get(host, [])

    async def connect(
        self, ip: str, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        self.dialled.append((ip, port))
        if self.fail_connect:
            raise ConnectionRefusedError
        return await asyncio.open_connection("127.0.0.1", self.echo_port)


async def _echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    with suppress(Exception):
        while data := await reader.read(1024):
            writer.write(b"echo:" + data)
            await writer.drain()
    writer.close()


@asynccontextmanager
async def running(
    fakes: Fakes | None = None, max_conns: int = 8
) -> AsyncIterator[tuple[HubProxy, Fakes, int, int]]:
    fakes = fakes or Fakes()
    echo = await asyncio.start_server(_echo, "127.0.0.1", 0)
    fakes.echo_port = echo.sockets[0].getsockname()[1]
    settings = Settings(
        allow=(f"{ALLOW}:443",),
        password=PASSWORD,
        max_conns=max_conns,
        bind="127.0.0.1",
        proxy_port=0,
        control_port=0,
    )
    proxy = HubProxy(settings, resolver=fakes.resolve, connector=fakes.connect)
    await proxy.start()
    proxy_port, control_port = proxy.ports()
    try:
        yield proxy, fakes, proxy_port, control_port
    finally:
        await proxy.stop()
        echo.close()
        await echo.wait_closed()


async def exchange(port: int, payload: bytes, read: int = 4096) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(payload)
    await writer.drain()
    try:
        async with asyncio.timeout(5):
            return await reader.read(read)
    finally:
        writer.close()


def _ext(etype: int, data: bytes) -> bytes:
    return etype.to_bytes(2, "big") + len(data).to_bytes(2, "big") + data


def sni_ext(*names: str) -> bytes:
    entries = b"".join(b"\x00" + len(n).to_bytes(2, "big") + n.encode() for n in names)
    return _ext(0, len(entries).to_bytes(2, "big") + entries)


def client_hello_body(extensions: bytes | None, session_id: bytes = b"") -> bytes:
    body = b"\x03\x03" + bytes(32) + bytes([len(session_id)]) + session_id
    body += b"\x00\x04\x13\x01\x13\x02" + b"\x01\x00"
    if extensions is not None:
        body += len(extensions).to_bytes(2, "big") + extensions
    return body


def records(body: bytes, split: int | None = None, msg_type: int = 1) -> bytes:
    msg = bytes([msg_type]) + len(body).to_bytes(3, "big") + body
    parts = [msg] if split is None else [msg[:split], msg[split:]]
    return b"".join(b"\x16\x03\x01" + len(p).to_bytes(2, "big") + p for p in parts)


def client_hello(sni: str | None = ALLOW, split: int | None = None) -> bytes:
    exts = _ext(43, b"\x02\x03\x04") + (sni_ext(sni) if sni is not None else b"")
    return records(client_hello_body(exts), split)

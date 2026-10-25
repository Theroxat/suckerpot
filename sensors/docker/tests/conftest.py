from __future__ import annotations

import asyncio
import contextlib
import json
import socket
from collections.abc import AsyncIterator
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest
from suckerpot_common import Event

from docker_sensor.api import DockerApi
from docker_sensor.config import Config
from docker_sensor.events import EventSink
from docker_sensor.memguard import MemoryGuard
from docker_sensor.profile import build_profile
from docker_sensor.server import DockerSensor, DockerServer


class FakePublisher:
    def __init__(self) -> None:
        self.events: list[Event] = []

    async def publish(self, event: Event) -> bool:
        self.events.append(event)
        return True

    async def close(self) -> None:
        return None


@dataclass
class Harness:
    port: int
    publisher: FakePublisher
    sensor: DockerSensor
    sink: EventSink
    cfg: Config

    async def events(self, type_: str | None = None, wait: float = 0.15) -> list[Event]:
        await asyncio.sleep(wait)
        await self.sink.flush()
        return [e for e in self.publisher.events if type_ is None or e.type == type_]

    async def raw(self, data: bytes, *, wait: float = 1.0) -> bytes:
        """Send bytes, read until the server closes or ``wait`` passes without data."""
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(data)
        await writer.drain()
        out = b""
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(65536), wait)
                if not chunk:
                    break
                out += chunk
        except TimeoutError:
            pass
        writer.close()
        return out

    async def http(
        self,
        method: str,
        path: str,
        body: bytes | dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        payload = b""
        hdrs = {"Host": "127.0.0.1:2375", "User-Agent": "Docker-Client/27.3.1 (linux)"}
        if isinstance(body, dict):
            payload = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        elif body is not None:
            payload = body
        if payload:
            hdrs["Content-Length"] = str(len(payload))
        hdrs["Connection"] = "close"
        hdrs.update(headers or {})
        head = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
        raw = await self.raw(head.encode() + b"\r\n" + payload, wait=2.0)
        return parse_response(raw)


def parse_response(raw: bytes) -> tuple[int, dict[str, str], bytes]:
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        k, _, v = line.partition(":")
        headers[k.strip()] = v.strip()
    if headers.get("Transfer-Encoding") == "chunked":
        out = b""
        rest = body
        while rest:
            size_line, _, rest = rest.partition(b"\r\n")
            size = int(size_line, 16)
            if size == 0:
                break
            out += rest[:size]
            rest = rest[size + 2 :]
        body = out
    return status, headers, body


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@contextlib.asynccontextmanager
async def start(overrides: dict[str, object] | None = None) -> AsyncIterator[Harness]:
    base: dict[str, object] = {
        "host": "127.0.0.1",
        "port": 0,
        "quiet_loopback": False,
        "conn_rate": 1000.0,
        "conn_burst": 1000.0,
        "stream_delay": 0.0,
    }
    opts = dict(overrides or {})
    guard = opts.pop("guard", None) or MemoryGuard(1 << 40, cgroup=Path("/nonexistent"))
    cfg = replace(Config(), **{**base, **opts})  # type: ignore[arg-type]
    profile = build_profile(b"x" * 32, 1_790_000_000.0)
    pub = FakePublisher()
    sink = EventSink(pub, rate=1000, burst=2000, global_rate=5000, global_burst=10000)
    sink.start()
    sensor = DockerSensor(cfg, sink, DockerApi(cfg, profile), guard=guard)  # type: ignore[arg-type]
    server = DockerServer(cfg, sensor)
    port = await server.start()
    try:
        yield Harness(port, pub, sensor, sink, cfg)
    finally:
        await server.stop()
        await sink.close()


@pytest.fixture
async def harness() -> AsyncIterator[Harness]:
    async with start() as h:
        yield h

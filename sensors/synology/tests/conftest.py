from __future__ import annotations

import asyncio
import contextlib
import http.client
import socket
import ssl
from collections.abc import AsyncIterator
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest
from suckerpot_common import Event

from synology_sensor.api import SynologyApi
from synology_sensor.config import Config
from synology_sensor.events import EventSink
from synology_sensor.memguard import MemoryGuard
from synology_sensor.profile import build_profile
from synology_sensor.server import SynologySensor, SynologyServer
from synology_sensor.tls import ensure_certificate, load_public_key_pem, make_context


class FakePublisher:
    def __init__(self) -> None:
        self.events: list[Event] = []

    async def publish(self, event: Event) -> bool:
        self.events.append(event)
        return True

    async def close(self) -> None:
        return None


@dataclass
class Resp:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        import json

        return json.loads(self.body)


@dataclass
class Harness:
    port: int
    tls_port: int
    publisher: FakePublisher
    sensor: SynologySensor
    sink: EventSink
    cfg: Config

    async def events(self, type_: str | None = None, wait: float = 0.15) -> list[Event]:
        await asyncio.sleep(wait)
        await self.sink.flush()
        return [e for e in self.publisher.events if type_ is None or e.type == type_]

    async def raw(
        self, data: bytes, *, wait: float = 1.0, tls: bool = False, sni: str | None = None
    ) -> bytes:
        """Send bytes, read until the server closes or ``wait`` passes without data."""
        port = self.tls_port if tls else self.port
        ctx = None
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=ctx, server_hostname=sni if tls else None
        )
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

    def _request(
        self,
        method: str,
        path: str,
        body: bytes | None,
        headers: dict[str, str],
        tls: bool,
    ) -> Resp:
        hdrs = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Test/1.0", **headers}
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                "127.0.0.1", self.tls_port, timeout=10, context=ctx
            )
        else:
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, body=body, headers=hdrs)
            r = conn.getresponse()
            return Resp(r.status, {k: v for k, v in r.getheaders()}, r.read())
        finally:
            conn.close()

    async def http(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        *,
        tls: bool = False,
    ) -> Resp:
        return await asyncio.to_thread(self._request, method, path, body, headers or {}, tls)

    async def form(self, path: str, fields: str, headers: dict[str, str] | None = None) -> Resp:
        hdrs = {"Content-Type": "application/x-www-form-urlencoded", **(headers or {})}
        return await self.http("POST", path, fields.encode(), hdrs)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@contextlib.asynccontextmanager
async def start(
    tmp_path: Path, overrides: dict[str, object] | None = None
) -> AsyncIterator[Harness]:
    base: dict[str, object] = {
        "host": "127.0.0.1",
        "http_port": 0,
        "https_port": 0,
        "quiet_loopback": False,
        "conn_rate": 1000.0,
        "conn_burst": 1000.0,
        "req_rate": 1000.0,
        "req_burst": 1000.0,
        "tls_per_sec": 1000.0,
        "tls_burst": 1000.0,
        "tls_ip_rate": 1000.0,
        "tls_ip_burst": 1000.0,
        "data_dir": str(tmp_path),
    }
    opts = dict(overrides or {})
    guard = opts.pop("guard", None) or MemoryGuard(1 << 40, cgroup=Path("/nonexistent"))
    cfg = replace(Config(), **{**base, **opts})  # type: ignore[arg-type]
    profile = build_profile(b"x" * 32, 1_790_000_000.0)
    cert, key = ensure_certificate(cfg.data_dir, profile)
    pub = FakePublisher()
    sink = EventSink(pub, rate=1000, burst=2000, global_rate=5000, global_burst=10000)
    sink.start()
    api = SynologyApi(cfg, profile, load_public_key_pem(cert))
    sensor = SynologySensor(cfg, sink, api, guard=guard)  # type: ignore[arg-type]
    sensor.tls_ctx = make_context(cert, key, sensor.on_sni)
    server = SynologyServer(cfg, sensor)
    port, tls_port = await server.start()
    try:
        yield Harness(port, tls_port, pub, sensor, sink, cfg)
    finally:
        await server.stop()
        await sink.close()


@pytest.fixture
async def harness(tmp_path: Path) -> AsyncIterator[Harness]:
    async with start(tmp_path) as h:
        yield h

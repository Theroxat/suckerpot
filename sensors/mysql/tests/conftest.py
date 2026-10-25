from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, replace
from typing import Any

import pymysql
import pytest
from suckerpot_common import Event

from mysql_sensor.config import Config
from mysql_sensor.events import EventSink
from mysql_sensor.identity import Identity, load_or_create_identity
from mysql_sensor.server import MySQLServer, Sensor

VERSION = "8.0.43-0ubuntu0.24.04.2"


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
    sensor: Sensor
    sink: EventSink
    cfg: Config
    identity: Identity
    data_dir: str

    async def events(self, type_: str | None = None) -> list[Event]:
        await asyncio.sleep(0.05)
        await self.sink.flush()
        return [e for e in self.publisher.events if type_ is None or e.type == type_]

    async def wait_disconnects(self, n: int, timeout: float = 8.0) -> list[Event]:
        async with asyncio.timeout(timeout):
            while True:
                found = await self.events("disconnect")
                if len(found) >= n:
                    return found
                await asyncio.sleep(0.05)

    def connect(self, **kw: object) -> Any:
        params: dict[str, object] = {
            "host": "127.0.0.1",
            "port": self.port,
            "user": "root",
            "password": "",
            "connect_timeout": 5,
            "read_timeout": 10,
            "write_timeout": 10,
        }
        params.update(kw)
        return pymysql.connect(**params)  # type: ignore[call-overload]

    async def aconnect(self, **kw: object) -> Any:
        return await asyncio.to_thread(self.connect, **kw)


@pytest.fixture(scope="session")
def identity(tmp_path_factory: pytest.TempPathFactory) -> Identity:
    return load_or_create_identity(tmp_path_factory.mktemp("data"), VERSION)


HarnessFactory = Callable[..., contextlib.AbstractAsyncContextManager[Harness]]


@pytest.fixture
def make_harness(identity: Identity) -> HarnessFactory:
    @contextlib.asynccontextmanager
    async def factory(
        sink_kw: dict[str, float] | None = None, **overrides: object
    ) -> AsyncIterator[Harness]:
        params: dict[str, object] = {
            "host": "127.0.0.1",
            "port": 0,
            "quiet_loopback": False,
            "data_dir": str(identity.tls_chain.parent),
            # Everything connects from 127.0.0.1: keep the per-source admission limits out of
            # the way unless a test is about them.
            "connections_per_sec_per_ip": 1e6,
            "connections_burst_per_ip": 1e6,
            "refusal_delay": 0.05,
            **overrides,
        }
        cfg = replace(Config(), **params)  # type: ignore[arg-type]
        pub = FakePublisher()
        kw: dict[str, float] = {
            "per_ip_rate": 1000.0,
            "per_ip_burst": 1000.0,
            "important_ip_rate": 1000.0,
            "important_ip_burst": 1000.0,
        }
        kw.update(sink_kw or {})
        sink = EventSink(pub, dst_port=3306, **kw)  # type: ignore[arg-type]
        sink.start()
        sensor = Sensor(cfg, sink, identity)
        server = MySQLServer(cfg, sensor)
        port = await server.start()
        try:
            yield Harness(port, pub, sensor, sink, cfg, identity, cfg.data_dir)
        finally:
            await server.stop()
            await sink.close()

    return factory

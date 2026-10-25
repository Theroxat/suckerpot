from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, replace

import pytest
from suckerpot_common import Event

from smb_sensor.config import Config
from smb_sensor.events import EventSink
from smb_sensor.identity import Identity, load_or_create_identity
from smb_sensor.memguard import MemoryGuard
from smb_sensor.server import Sensor, SMBServer


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

    async def events(self, type_: str | None = None) -> list[Event]:
        await asyncio.sleep(0.05)
        await self.sink.flush()
        return [e for e in self.publisher.events if type_ is None or e.type == type_]

    async def wait_events(self, type_: str, n: int, timeout: float = 5.0) -> list[Event]:
        async with asyncio.timeout(timeout):
            while True:
                found = await self.events(type_)
                if len(found) >= n:
                    return found
                await asyncio.sleep(0.05)


@pytest.fixture(scope="session")
def identity(tmp_path_factory: pytest.TempPathFactory) -> Identity:
    return load_or_create_identity(tmp_path_factory.mktemp("data"))


HarnessFactory = Callable[..., contextlib.AbstractAsyncContextManager[Harness]]


@pytest.fixture
def make_harness(identity: Identity) -> HarnessFactory:
    @contextlib.asynccontextmanager
    async def factory(
        sink_kw: dict[str, float] | None = None,
        guard: MemoryGuard | None = None,
        **overrides: object,
    ) -> AsyncIterator[Harness]:
        params: dict[str, object] = {
            "host": "127.0.0.1",
            "port": 0,
            "quiet_loopback": False,
            **overrides,
        }
        cfg = replace(Config(), **params)  # type: ignore[arg-type]
        pub = FakePublisher()
        kw: dict[str, float] = {"per_ip_rate": 1000.0, "per_ip_burst": 1000.0}
        kw.update(sink_kw or {})
        sink = EventSink(pub, dst_port=445, **kw)  # type: ignore[arg-type]
        sink.start()
        sensor = Sensor(cfg, sink, identity, guard=guard)
        server = SMBServer(cfg, sensor)
        port = await server.start()
        try:
            yield Harness(port, pub, sensor, sink, cfg)
        finally:
            await server.stop()
            await sink.close()

    return factory

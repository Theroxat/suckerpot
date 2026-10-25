from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from suckerpot_common import Event

from rdp_sensor.config import Config
from rdp_sensor.events import EventSink
from rdp_sensor.identity import Identity, load_or_create_identity
from rdp_sensor.memguard import MemoryGuard
from rdp_sensor.server import RDPServer, Sensor, make_tls_context


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

    async def events(self, type_: str | None = None) -> list[Event]:
        await asyncio.sleep(0.05)
        await self.sink.flush()
        return [e for e in self.publisher.events if type_ is None or e.type == type_]

    async def wait_disconnects(self, n: int, timeout: float = 5.0) -> list[Event]:
        async with asyncio.timeout(timeout):
            while True:
                found = await self.events("disconnect")
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
        sink = EventSink(pub, dst_port=3389, **kw)  # type: ignore[arg-type]
        sink.start()
        # A roomy guard by default so unit tests never trip the process memory backstop (which
        # reflects the whole shared test container); the Docker load test uses the real limit.
        sensor = Sensor(
            cfg, sink, make_tls_context(identity), identity, guard=guard or MemoryGuard(8 << 30)
        )
        server = RDPServer(cfg, sensor)
        port = await server.start()
        try:
            yield Harness(port, pub, sensor, sink, cfg, identity)
        finally:
            await server.stop()
            await sink.close()

    return factory


def data_dir(path: Path) -> str:
    return str(path)

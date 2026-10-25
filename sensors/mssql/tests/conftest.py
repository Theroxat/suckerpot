from __future__ import annotations

import asyncio
import contextlib
import ssl
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from suckerpot_common import Event

from mssql_sensor.config import Config
from mssql_sensor.events import EventSink
from mssql_sensor.identity import Profile, derive_profile
from mssql_sensor.memguard import MemoryGuard
from mssql_sensor.server import MssqlServer, Sensor


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
    profile: Profile

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
def profile() -> Profile:
    return derive_profile("ab" * 32)


HarnessFactory = Callable[..., contextlib.AbstractAsyncContextManager[Harness]]


@pytest.fixture
def make_harness(profile: Profile) -> HarnessFactory:
    @contextlib.asynccontextmanager
    async def factory(
        sink_kw: dict[str, float] | None = None,
        guard: MemoryGuard | None = None,
        tls_ctx: ssl.SSLContext | None = None,
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
        sink = EventSink(pub, dst_port=1433, **kw)  # type: ignore[arg-type]
        sink.start()
        sensor = Sensor(cfg, sink, profile, guard, tls_ctx)
        server = MssqlServer(cfg, sensor)
        port = await server.start()
        try:
            yield Harness(port, pub, sensor, sink, cfg, profile)
        finally:
            await server.stop()
            await sink.close()

    return factory


def data_dir(path: Path) -> str:
    return str(path)


async def talk(port: int, payload: bytes, wait: float = 0.3, source: str | None = None) -> bytes:
    """Send ``payload``, collect everything the server answers within ``wait`` seconds."""
    local = (source, 0) if source else None
    reader, writer = await asyncio.open_connection("127.0.0.1", port, local_addr=local)
    writer.write(payload)
    await writer.drain()
    data = b""
    with contextlib.suppress(TimeoutError):
        async with asyncio.timeout(wait):
            while chunk := await reader.read(65536):
                data += chunk
    writer.close()
    return data

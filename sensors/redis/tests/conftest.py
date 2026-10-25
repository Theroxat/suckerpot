from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from suckerpot_common import Event

from redis_sensor.config import Config
from redis_sensor.events import EventSink
from redis_sensor.identity import Profile, derive_profile
from redis_sensor.info import ServerContext
from redis_sensor.memguard import MemoryGuard
from redis_sensor.server import RedisServer, Sensor


class FakePublisher:
    def __init__(self, delay: float = 0.0) -> None:
        self.events: list[Event] = []
        self.delay = delay

    async def publish(self, event: Event) -> bool:
        if self.delay:
            await asyncio.sleep(self.delay)
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
def make_harness(profile: Profile, tmp_path_factory: pytest.TempPathFactory) -> HarnessFactory:
    @contextlib.asynccontextmanager
    async def factory(
        sink_kw: dict[str, float] | None = None,
        guard: MemoryGuard | None = None,
        publish_delay: float = 0.0,
        **overrides: object,
    ) -> AsyncIterator[Harness]:
        params: dict[str, object] = {
            "host": "127.0.0.1",
            "port": 0,
            "quiet_loopback": False,
            **overrides,
        }
        cfg = replace(Config(), **params)  # type: ignore[arg-type]
        pub = FakePublisher(publish_delay)
        kw: dict[str, float] = {"per_ip_rate": 1000.0, "per_ip_burst": 1000.0}
        kw.update(sink_kw or {})
        sink = EventSink(pub, dst_port=6379, **kw)  # type: ignore[arg-type]
        sink.start()
        if guard is None:  # the test process' own RSS must not trip the memory guard
            cg = tmp_path_factory.mktemp("cgroup")
            (cg / "memory.current").write_text("1000000\n")
            (cg / "memory.max").write_text("268435456\n")
            (cg / "memory.stat").write_text("inactive_file 0\n")
            guard = MemoryGuard(256 << 20, cgroup=cg)
        sensor = Sensor(cfg, sink, ServerContext(profile), guard)
        server = RedisServer(cfg, sensor)
        port = await server.start()
        try:
            yield Harness(port, pub, sensor, sink, cfg, profile)
        finally:
            await server.stop()
            await sink.close()

    return factory


def data_dir(path: Path) -> str:
    return str(path)


def cmd(*parts: str | bytes) -> bytes:
    """Encode a command as a RESP array."""
    out = b"*%d\r\n" % len(parts)
    for part in parts:
        raw = part.encode() if isinstance(part, str) else part
        out += b"$%d\r\n%s\r\n" % (len(raw), raw)
    return out


async def talk(port: int, payload: bytes, wait: float = 0.3) -> bytes:
    """Send ``payload``, collect everything the server answers within ``wait`` seconds."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(payload)
    await writer.drain()
    data = b""
    with contextlib.suppress(TimeoutError):
        async with asyncio.timeout(wait):
            while chunk := await reader.read(65536):
                data += chunk
    writer.close()
    return data

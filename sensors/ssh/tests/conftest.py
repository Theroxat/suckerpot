from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, replace
from pathlib import Path

import asyncssh
import pytest
from suckerpot_common import Event

from ssh_sensor.config import Config
from ssh_sensor.events import EventSink
from ssh_sensor.hostkeys import load_or_create_host_keys
from ssh_sensor.server import Sensor, SSHSensorServer
from ssh_sensor.shell.baseimage import derive_profile
from ssh_sensor.shell.interp import Shell


class FakePublisher:
    def __init__(self) -> None:
        self.events: list[Event] = []
        self.ok = True

    async def publish(self, event: Event) -> bool:
        self.events.append(event)
        return self.ok

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
        await asyncio.sleep(0.1)
        await self.sink.flush()
        return [e for e in self.publisher.events if type_ is None or e.type == type_]

    async def connect(self, **kw: object) -> asyncssh.SSHClientConnection:
        opts: dict[str, object] = {
            "known_hosts": None,
            "username": "root",
            "password": "root",
            "client_keys": None,
            "agent_path": None,
        }
        opts.update(kw)
        return await asyncssh.connect("127.0.0.1", self.port, **opts)


@pytest.fixture(scope="session")
def host_keys(tmp_path_factory: pytest.TempPathFactory) -> list[asyncssh.SSHKey]:
    return load_or_create_host_keys(tmp_path_factory.mktemp("keys") / "host_keys")


@pytest.fixture
def make_harness(
    host_keys: list[asyncssh.SSHKey],
) -> Callable[..., contextlib.AbstractAsyncContextManager[Harness]]:
    @contextlib.asynccontextmanager
    async def factory(**overrides: object) -> AsyncIterator[Harness]:
        params: dict[str, object] = {
            "host": "127.0.0.1",
            "port": 0,
            "auth_fail_delay": (0.0, 0.0),
            "command_delay": False,
            "quiet_loopback": False,
            "events_per_sec": 1000.0,
            "events_burst": 1000.0,
            "conn_rate_per_ip": 1000.0,
            "conn_burst_per_ip": 1000.0,
            # the dedicated tests set these budgets themselves
            "shell_cpu_share": 1000.0,
            "shell_cpu_burst": 1000.0,
            "memory_limit": 1 << 40,
            "ip_event_bytes_per_sec": 1e9,
            "ip_event_bytes_burst": 1e9,
            "global_event_bytes_per_sec": 1e9,
            "global_event_bytes_burst": 1e9,
            "inbound_bytes_per_sec": 1e9,
            "inbound_bytes_burst": 1e9,
            "inbound_conn_bytes_per_sec": 1e9,
            "inbound_conn_bytes_burst": 1e9,
            **overrides,
        }
        cfg = replace(Config(), **params)  # type: ignore[arg-type]
        pub = FakePublisher()
        sink = EventSink(
            pub,
            rate=cfg.events_per_sec,
            burst=cfg.events_burst,
            dst_port=22,
            noisy_rate=1000.0,
            noisy_burst=1000.0,
            valuable_rate=1000.0,
            valuable_burst=1000.0,
            global_rate=100000.0,
            global_burst=100000.0,
            ip_bytes_rate=cfg.ip_event_bytes_per_sec,
            ip_bytes_burst=cfg.ip_event_bytes_burst,
            global_bytes_rate=cfg.global_event_bytes_per_sec,
            global_bytes_burst=cfg.global_event_bytes_burst,
            queue_bytes=cfg.event_queue_bytes,
        )
        sink.start()
        profile = derive_profile("test-seed", cfg.hostname)
        sensor = Sensor(cfg, sink, profile)
        server = SSHSensorServer(cfg, sensor, host_keys)
        port = await server.start()
        try:
            yield Harness(port, pub, sensor, sink, cfg)
        finally:
            await server.stop()
            await sink.close()

    return factory


@pytest.fixture
def shell() -> Shell:
    cfg = Config(command_delay=False)
    from ssh_sensor.shell.baseimage import build_base_image

    profile = derive_profile("test-seed", "srv-web01")
    return Shell(
        cfg=cfg,
        base=build_base_image(profile),
        profile=profile,
        username="root",
        client_ip="203.0.113.9",
        client_port=51000,
    )


def tmp_dir(path: Path) -> str:
    return str(path)

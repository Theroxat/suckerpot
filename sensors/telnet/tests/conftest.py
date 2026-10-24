from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, replace

import pytest
from suckerpot_common import Event

from telnet_sensor.config import Config
from telnet_sensor.events import EventSink
from telnet_sensor.server import Sensor, TelnetServer

IAC = 255


class FakePublisher:
    def __init__(self) -> None:
        self.events: list[Event] = []

    async def publish(self, event: Event) -> bool:
        self.events.append(event)
        return True

    async def close(self) -> None:
        return None


def strip_iac(data: bytes) -> bytes:
    """Remove Telnet commands from a byte stream (good enough for the server's output)."""
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b != IAC:
            out.append(b)
            i += 1
        elif i + 1 < len(data) and data[i + 1] == IAC:
            out.append(IAC)
            i += 2
        elif i + 1 < len(data) and data[i + 1] == 250:  # SB ... IAC SE
            end = data.find(bytes((IAC, 240)), i)
            i = len(data) if end < 0 else end + 2
        else:
            i += 3
    return bytes(out)


class RawClient:
    """A plain TCP client speaking raw Telnet bytes."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self.raw = b""
        self.pos = 0  # consumed up to here (in the cleaned text)

    @property
    def text(self) -> bytes:
        return strip_iac(self.raw)

    async def send(self, data: bytes | str) -> None:
        self.writer.write(data.encode() if isinstance(data, str) else data)
        await self.writer.drain()

    async def until(self, marker: bytes | str, timeout: float = 5.0) -> bytes:
        """Read until ``marker`` appears after the last consumed position; returns that slice."""
        needle = marker.encode() if isinstance(marker, str) else marker
        async with asyncio.timeout(timeout):
            while True:
                text = self.text
                idx = text.find(needle, self.pos)
                if idx >= 0:
                    chunk = text[self.pos : idx + len(needle)]
                    self.pos = idx + len(needle)
                    return chunk
                data = await self.reader.read(4096)
                if not data:
                    raise EOFError(f"closed before {needle!r}; got {text[self.pos :]!r}")
                self.raw += data

    async def run(self, line: str, prompt: bytes = b" # ", timeout: float = 5.0) -> str:
        await self.send(line + "\r\n")
        out = await self.until(prompt, timeout)
        text = out.decode("utf-8", "replace")
        # drop the echoed command line and the trailing prompt
        _, _, rest = text.partition("\r\n")
        return rest[: -len(prompt)].rsplit("\r\n", 1)[0] if "\r\n" in rest else ""

    async def login(
        self, user: str = "root", password: str = "vizxv", prompt: bytes = b" # "
    ) -> None:
        await self.until(b"login: ")
        await self.send(user + "\r\n")
        await self.until(b"Password: ")
        await self.send(password + "\r\n")
        await self.until(prompt)

    async def read_all(self, timeout: float = 5.0) -> bytes:
        async with asyncio.timeout(timeout):
            while True:
                data = await self.reader.read(4096)
                if not data:
                    return self.text
                self.raw += data

    async def close(self) -> None:
        self.writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self.writer.wait_closed(), 2)


@dataclass
class Harness:
    port: int
    publisher: FakePublisher
    sensor: Sensor
    sink: EventSink
    cfg: Config
    clients: list[RawClient]

    async def events(self, type_: str | None = None) -> list[Event]:
        await asyncio.sleep(0.15)
        await self.sink.flush()
        return [e for e in self.publisher.events if type_ is None or e.type == type_]

    async def connect(self) -> RawClient:
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        client = RawClient(reader, writer)
        self.clients.append(client)
        return client

    async def logged_in(
        self, user: str = "root", password: str = "vizxv", prompt: bytes = b" # "
    ) -> RawClient:
        client = await self.connect()
        await client.login(user, password, prompt)
        return client


@pytest.fixture
def make_harness() -> Callable[..., contextlib.AbstractAsyncContextManager[Harness]]:
    @contextlib.asynccontextmanager
    async def factory(
        sink_limits: dict[str, float] | None = None, **overrides: object
    ) -> AsyncIterator[Harness]:
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
            "hostname": "dvr-test",
            **overrides,
        }
        cfg = replace(Config(), **params)  # type: ignore[arg-type]
        pub = FakePublisher()
        limits: dict[str, float] = {
            "noisy_rate": 1000.0,
            "noisy_burst": 1000.0,
            "valuable_rate": 1000.0,
            "valuable_burst": 1000.0,
            "global_rate": 100000.0,
            "global_burst": 100000.0,
            **(sink_limits or {}),
        }
        sink = EventSink(
            pub,
            rate=cfg.events_per_sec,
            burst=cfg.events_burst,
            dst_port=cfg.public_port,
            **limits,  # type: ignore[arg-type]
        )
        sink.start()
        sensor = Sensor(cfg, sink, "test-seed")
        server = TelnetServer(cfg, sensor)
        port = await server.start()
        harness = Harness(port, pub, sensor, sink, cfg, [])
        try:
            yield harness
        finally:
            for client in harness.clients:
                await client.close()
            await server.stop()
            await sink.close()

    return factory


@pytest.fixture
def make_shell() -> Callable[..., object]:
    from ssh_sensor.config import Config as ShellConfig

    from telnet_sensor.device import PERSONALITY_BY_NAME, build_base_image, derive_device
    from telnet_sensor.devshell import DeviceShell

    def factory(user: str = "root", **overrides: object) -> DeviceShell:
        p = PERSONALITY_BY_NAME["dvr"]
        profile = derive_device("shell-seed", "dvr-test", p)
        cfg = ShellConfig(command_delay=False, **overrides)  # type: ignore[arg-type]
        return DeviceShell(
            cfg=cfg,
            base=build_base_image(profile, p),
            profile=profile,
            username=user,
            client_ip="203.0.113.9",
            client_port=40000,
            personality_name="dvr",
        )

    return factory

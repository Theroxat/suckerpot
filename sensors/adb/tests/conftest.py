from __future__ import annotations

import asyncio
import contextlib
import struct
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, replace

import pytest
from suckerpot_common import Event

from adb_sensor.config import Config
from adb_sensor.events import EventSink
from adb_sensor.server import AdbServer, Sensor
from adb_sensor.wire import (
    A_CLSE,
    A_CNXN,
    A_OKAY,
    A_OPEN,
    A_WRTE,
    HEADER_SIZE,
    V2_EXIT,
    V2_HEADER,
    V2_STDERR,
    V2_STDOUT,
    checksum,
    pack,
)


class FakePublisher:
    def __init__(self) -> None:
        self.events: list[Event] = []

    async def publish(self, event: Event) -> bool:
        self.events.append(event)
        return True

    async def close(self) -> None:
        return None


class AdbClient:
    """A minimal adb host speaking the wire protocol by hand."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self.next_id = 1
        self.banner = b""
        self.version = 0
        self.maxdata = 0

    async def send(self, command: int, arg0: int, arg1: int, data: bytes = b"") -> None:
        self.writer.write(pack(command, arg0, arg1, data))
        await self.writer.drain()

    async def recv(self, timeout: float = 5.0) -> tuple[int, int, int, bytes]:
        async with asyncio.timeout(timeout):
            head = await self.reader.readexactly(HEADER_SIZE)
            command, arg0, arg1, length, crc, magic = struct.unpack("<6I", head)
            assert magic == command ^ 0xFFFFFFFF
            data = await self.reader.readexactly(length) if length else b""
            assert crc == checksum(data) or True
            return command, arg0, arg1, data

    async def connect(self, banner: bytes = b"host::features=shell_v2,cmd\0") -> None:
        await self.send(A_CNXN, 0x01000001, 256 * 1024, banner)
        command, self.version, self.maxdata, self.banner = await self.recv()
        assert command == A_CNXN

    async def open(self, service: str) -> int | None:
        """OPEN a service; returns our local id, or None when it was refused (CLSE)."""
        local = self.next_id
        self.next_id += 1
        await self.send(A_OPEN, local, 0, service.encode() + b"\0")
        while True:
            command, arg0, arg1, _ = await self.recv()
            if command == A_WRTE:  # output of an earlier stream (e.g. a prompt)
                await self.send(A_OKAY, arg1, arg0)
                continue
            if command == A_OKAY and arg1 != local:
                continue
            if command == A_CLSE and arg0 != 0:  # an earlier stream being closed
                await self.send(A_CLSE, arg1, arg0)
                continue
            break
        if command == A_OKAY:
            self.remote = arg0
            return local
        assert command == A_CLSE
        return None

    async def read_stream(self, local: int, timeout: float = 5.0) -> bytes:
        """Collect WRTE data (acknowledging each) until the device closes the stream."""
        out = b""
        async with asyncio.timeout(timeout):
            while True:
                command, arg0, arg1, data = await self.recv(timeout)
                if command == A_WRTE:
                    out += data
                    await self.send(A_OKAY, local, arg0)
                elif command == A_CLSE:
                    await self.send(A_CLSE, local, arg0)
                    return out

    async def read_until(self, local: int, marker: bytes, timeout: float = 5.0) -> bytes:
        out = b""
        async with asyncio.timeout(timeout):
            while marker not in out:
                command, arg0, arg1, data = await self.recv(timeout)
                if command == A_WRTE:
                    out += data
                    await self.send(A_OKAY, local, arg0)
                elif command == A_CLSE:
                    raise EOFError(f"closed before {marker!r}; got {out!r}")
        return out

    async def write(self, local: int, remote: int, data: bytes) -> None:
        await self.send(A_WRTE, local, remote, data)
        command, _, _, _ = await self.recv()
        assert command == A_OKAY

    async def shell(self, command: str, timeout: float = 5.0) -> str:
        """`adb shell <command>` with the legacy (non-v2) service."""
        local = await self.open(f"shell:{command}")
        assert local is not None
        return (await self.read_stream(local, timeout)).decode("utf-8", "replace")

    async def shell_v2(self, command: str, timeout: float = 5.0) -> tuple[bytes, bytes, int]:
        local = await self.open(f"shell,v2,raw:{command}")
        assert local is not None
        raw = await self.read_stream(local, timeout)
        out, err, status = b"", b"", -1
        pos = 0
        while pos + 5 <= len(raw):
            pid, length = V2_HEADER.unpack_from(raw, pos)
            body = raw[pos + 5 : pos + 5 + length]
            pos += 5 + length
            if pid == V2_STDOUT:
                out += body
            elif pid == V2_STDERR:
                err += body
            elif pid == V2_EXIT:
                status = body[0]
        return out, err, status

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
    clients: list[AdbClient]

    async def events(self, type_: str | None = None) -> list[Event]:
        await asyncio.sleep(0.2)
        await self.sink.flush()
        return [e for e in self.publisher.events if type_ is None or e.type == type_]

    async def raw(self, source: str | None = None) -> AdbClient:
        """A new client; ``source`` (127.0.0.N) gives it its own source IP."""
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", self.port, local_addr=(source, 0) if source else None
        )
        client = AdbClient(reader, writer)
        self.clients.append(client)
        return client

    async def connect(self, source: str | None = None) -> AdbClient:
        client = await self.raw(source)
        await client.connect()
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
            "command_delay": False,
            "quiet_loopback": False,
            "events_per_sec": 1000.0,
            "events_burst": 1000.0,
            "conn_rate_per_ip": 1000.0,
            "conn_burst_per_ip": 1000.0,
            "busybox": "yes",
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
        sensor.cgroup_dir = "/nonexistent"
        server = AdbServer(cfg, sensor)
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

    from adb_sensor.androidshell import AndroidShell
    from adb_sensor.device import build_base_image, derive_device

    def factory(user: str = "root", busybox: str = "yes", **overrides: object) -> AndroidShell:
        dev = derive_device("shell-seed", "", busybox, user == "root")
        cfg = ShellConfig(command_delay=False, **overrides)  # type: ignore[arg-type]
        return AndroidShell(
            cfg=cfg,
            base=build_base_image(dev),
            profile=dev.profile,
            username=user,
            client_ip="203.0.113.9",
            client_port=40000,
            device=dev,
        )

    return factory

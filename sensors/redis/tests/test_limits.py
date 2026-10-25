"""Connection caps, timeouts, buffer budgets, the memory guard and floods."""

from __future__ import annotations

import asyncio
import os
import socket
import time
from pathlib import Path

from conftest import HarnessFactory, cmd, talk

from redis_sensor.memguard import MemoryGuard


async def test_per_ip_cap_refuses_like_maxclients(make_harness: HarnessFactory) -> None:
    async with make_harness(max_per_ip=2, first_data_timeout=5.0) as h:
        held = [await asyncio.open_connection("127.0.0.1", h.port) for _ in range(2)]
        await asyncio.sleep(0.1)
        reader, writer = await asyncio.open_connection("127.0.0.1", h.port)
        writer.write(cmd("PING"))
        t0 = time.monotonic()
        async with asyncio.timeout(3):
            assert await reader.read(100) == b"-ERR max number of clients reached\r\n"
        assert time.monotonic() - t0 >= 0.05  # not an instant accept-and-close
        writer.close()
        assert h.sensor.rejected == 1
        for _, w in held:
            w.close()
        await h.wait_disconnects(2)
        assert h.sensor.total == 0 and h.sensor.per_ip == {}
        assert h.sensor.buffered == 0


async def test_global_cap_evicts_oldest_idle(make_harness: HarnessFactory) -> None:
    async with make_harness(max_connections=3, max_per_ip=100, first_data_timeout=5.0) as h:
        conns = [await asyncio.open_connection("127.0.0.1", h.port) for _ in range(3)]
        await asyncio.sleep(0.1)
        reader, writer = await asyncio.open_connection("127.0.0.1", h.port)
        writer.write(cmd("PING"))
        async with asyncio.timeout(2):
            assert await reader.read(64) == b"+PONG\r\n"
            assert await conns[0][0].read(10) == b""
        writer.close()
        assert h.sensor.evicted == 1
        for _, w in conns:
            w.close()
        disc = await h.wait_disconnects(4)
        assert sum(d.data["reason"] == "evicted" for d in disc) == 1


async def test_global_cap_refuses_when_nobody_is_idle(make_harness: HarnessFactory) -> None:
    async with make_harness(max_connections=2, max_per_ip=100) as h:
        busy = []
        for _ in range(2):
            r, w = await asyncio.open_connection("127.0.0.1", h.port)
            w.write(b"*1\r\n$4\r\nPI")  # half a command
            busy.append((r, w))
        await asyncio.sleep(0.2)
        reader, writer = await asyncio.open_connection("127.0.0.1", h.port)
        async with asyncio.timeout(4):
            assert (await reader.read(100)).startswith(b"-ERR max number of clients")
        writer.close()
        for _, w in busy:
            w.close()
        assert h.sensor.rejected == 1


async def test_timeouts(make_harness: HarnessFactory) -> None:
    async with make_harness(first_data_timeout=0.3, idle_timeout=0.4, max_session=1.0) as h:
        _, w1 = await asyncio.open_connection("127.0.0.1", h.port)  # says nothing
        r2, w2 = await asyncio.open_connection("127.0.0.1", h.port)
        w2.write(cmd("PING"))
        assert await r2.read(10) == b"+PONG\r\n"
        r3, w3 = await asyncio.open_connection("127.0.0.1", h.port)
        for _ in range(8):  # keeps the connection alive until the session cap
            w3.write(cmd("PING"))
            await asyncio.sleep(0.2)
        reasons = sorted(d.data["reason"] for d in await h.wait_disconnects(3))
        assert reasons == ["idle", "max_session", "no_data"]
        for w in (w1, w2, w3):
            w.close()


async def test_command_and_byte_limits(make_harness: HarnessFactory) -> None:
    async with make_harness(max_commands=50, max_bytes_in=20_000) as h:
        out = await talk(h.port, cmd("PING") * 200, wait=1.0)
        assert out == b"+PONG\r\n" * 50
        out = await talk(h.port, cmd("SET", "k", "v" * 4000) * 10, wait=1.0)
        assert out.count(b"+OK") <= 5
        reasons = {d.data["reason"] for d in await h.wait_disconnects(2)}
        assert reasons == {"command_limit", "input_limit"}


async def test_buffer_budget_across_connections(make_harness: HarnessFactory) -> None:
    async with make_harness(max_buffered=300_000, max_per_ip=100) as h:
        conns = []
        for _ in range(12):
            r, w = await asyncio.open_connection("127.0.0.1", h.port)
            w.write(b"*2\r\n$3\r\nSET\r\n$524288\r\n" + b"x" * 100_000)
            conns.append((r, w))
        await asyncio.sleep(0.5)
        assert h.sensor.buffered <= 300_000 + 32 * 1024 * 2
        reasons = [d.data["reason"] for d in await h.events("disconnect")]
        assert reasons.count("budget") >= 8
        for _, w in conns:
            w.close()
        await h.wait_disconnects(12)
        assert h.sensor.buffered == 0


async def test_peer_that_never_reads_is_aborted(make_harness: HarnessFactory) -> None:
    async with make_harness(write_timeout=0.5) as h:
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
        s.connect(("127.0.0.1", h.port))
        s.setblocking(False)
        loop = asyncio.get_running_loop()
        payload = cmd("INFO", "all") * 200
        for _ in range(20):
            try:
                await loop.sock_sendall(s, payload)
            except OSError:
                break
        d = (await h.wait_disconnects(1, timeout=15))[0]
        assert d.data["reason"] in ("write_timeout", "client_reset")
        await asyncio.sleep(0.2)
        assert h.sensor.total == 0
        s.close()


def _cgroup(path: Path, current: int, limit: int) -> Path:
    (path / "memory.current").write_text(f"{current}\n")
    (path / "memory.max").write_text(f"{limit}\n")
    (path / "memory.stat").write_text("inactive_file 0\n")
    return path


async def test_memory_guard_refuses_and_sheds(make_harness: HarnessFactory, tmp_path: Path) -> None:
    cg = _cgroup(tmp_path, 10 << 20, 100 << 20)
    guard = MemoryGuard(100 << 20, cgroup=cg)
    async with make_harness(guard=guard, max_per_ip=100) as h:
        conns = []
        for _ in range(4):
            r, w = await asyncio.open_connection("127.0.0.1", h.port)
            w.write(cmd("PING"))
            await r.read(10)
            conns.append((r, w))
        _cgroup(tmp_path, 75 << 20, 100 << 20)  # above 70 %: refuse new connections
        guard.sample()
        assert guard.refusing
        r, w = await asyncio.open_connection("127.0.0.1", h.port)
        assert (await r.read(100)).startswith(b"-ERR max number of clients")
        w.close()
        _cgroup(tmp_path, 90 << 20, 100 << 20)  # above 85 %: shed
        assert h.sensor.check_memory() >= 1
        await asyncio.sleep(0.3)
        reasons = [d.data["reason"] for d in await h.events("disconnect")]
        assert "memory_pressure" in reasons
        _cgroup(tmp_path, 10 << 20, 100 << 20)
        h.sensor.check_memory()
        assert not guard.refusing
        for _, w in conns:
            w.close()


def test_guard_without_cgroup_uses_rss(tmp_path: Path) -> None:
    guard = MemoryGuard(256 << 20, cgroup=tmp_path / "missing")
    assert guard.source == "rss"
    guard.sample()
    assert guard.usage > 0


async def test_hostile_commands_do_not_stall_the_loop(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        r, w = await asyncio.open_connection("127.0.0.1", h.port)
        w.write(cmd("MSET", *[x for i in range(60) for x in (f"{'a' * 200}{i}", "v")]))
        nasty = ["*a" * 60 + "b", "[" * 120, "*" * 127 + "x", "a" * 100_000]
        for p in nasty:
            w.write(cmd("KEYS", p) + cmd("CONFIG", "GET", p) + cmd("SCAN", "0", "MATCH", p))
        w.write(cmd("PING"))
        await w.drain()
        t0 = time.monotonic()
        data = b""
        async with asyncio.timeout(5):
            while not data.endswith(b"+PONG\r\n"):
                data += await r.read(65536)
        assert time.monotonic() - t0 < 2.0
        w.close()


async def test_flood_from_many_ips_is_aggregated(make_harness: HarnessFactory) -> None:
    async with make_harness(sink_kw={"per_ip_rate": 0.001, "per_ip_burst": 2.0}) as h:
        for _ in range(10):
            await talk(h.port, cmd("PING"), wait=0.05)
        await asyncio.sleep(0.2)
        assert h.sink.sessions_suppressed == 8
        assert h.sink.flush_suppressed(60.0) == 1
        scans = await h.events("scan")
        assert scans[-1].data == {
            "kind": "rate_limited",
            "suppressed_connections": 8,
            "window_s": 60.0,
        }
        assert len(await h.events("connect")) == 2


async def test_parallel_connections_memory_plateau(make_harness: HarnessFactory) -> None:
    import resource

    async with make_harness(max_connections=200, max_per_ip=200) as h:
        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        for _round in range(3):
            conns = [await asyncio.open_connection("127.0.0.1", h.port) for _ in range(150)]
            for _, w in conns:
                w.write(b"*2\r\n$3\r\nSET\r\n$100000\r\n" + b"x" * 30_000)
            await asyncio.sleep(0.3)
            for _, w in conns:
                w.close()
            await asyncio.sleep(0.3)
        grown = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before
        assert grown < 120_000  # KiB; 150 connections x 3 rounds must not accumulate
        assert h.sensor.total == 0 and h.sensor.buffered == 0
    assert os.getpid() > 0

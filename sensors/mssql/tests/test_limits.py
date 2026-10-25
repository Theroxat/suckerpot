"""Connection caps, budgets, the memory guard and floods."""

from __future__ import annotations

import asyncio
import resource
import socket
import time
from pathlib import Path

from conftest import HarnessFactory, talk
from tdsclient import Client, batch, login7, packet, prelogin

from mssql_sensor import tds
from mssql_sensor.memguard import MemoryGuard


async def test_global_cap_evicts_oldest_idle(make_harness: HarnessFactory) -> None:
    async with make_harness(max_connections=3, max_per_ip=100, first_data_timeout=5.0) as h:
        conns = [await asyncio.open_connection("127.0.0.1", h.port) for _ in range(3)]
        await asyncio.sleep(0.1)
        reader, writer = await asyncio.open_connection("127.0.0.1", h.port)
        writer.write(prelogin())
        async with asyncio.timeout(2):
            assert (await reader.read(64))[:1] == b"\x04"
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
            w.write(prelogin()[:5])  # half a header
            busy.append((r, w))
        await asyncio.sleep(0.2)
        reader, writer = await asyncio.open_connection("127.0.0.1", h.port)
        async with asyncio.timeout(4):
            assert await reader.read(100) == b""  # closed without service
        writer.close()
        for _, w in busy:
            w.close()
        assert h.sensor.rejected == 1


async def test_message_and_byte_limits(make_harness: HarnessFactory) -> None:
    async with make_harness(max_commands=20, max_bytes_in=30_000) as h:
        out = await talk(
            h.port, prelogin() + login7("sa", "sa") + batch("select 1") * 100, wait=1.0
        )
        assert out
        out = await talk(
            h.port, prelogin() + packet(tds.T_LOGIN7, b"\0" * 4000, eom=False) * 20, wait=1.0
        )
        reasons = {d.data["reason"] for d in await h.wait_disconnects(2)}
        assert "message_limit" in reasons or "input_limit" in reasons
        assert "input_limit" in reasons or "protocol_error" in reasons


async def test_never_ending_message_is_cut(make_harness: HarnessFactory) -> None:
    async with make_harness(max_bytes_in=10_000_000) as h:
        r, w = await asyncio.open_connection("127.0.0.1", h.port)
        w.write(prelogin())
        w.write(login7("sa", "sa"))
        await w.drain()
        chunk = packet(tds.T_SQLBATCH, b"\x00" * 8, eom=False)
        for _ in range(3000):
            w.write(chunk)
        await w.drain()
        d = (await h.wait_disconnects(1))[0]
        assert d.data["reason"] == "message_limit"
        w.close()


async def test_buffer_budget_across_connections(make_harness: HarnessFactory) -> None:
    async with make_harness(max_buffered=100_000, max_per_ip=100) as h:
        conns = []
        for _ in range(12):
            r, w = await asyncio.open_connection("127.0.0.1", h.port)
            w.write(bytes([0x12, 0x00, 0x7F, 0xFF, 0, 0, 1, 0]) + b"x" * 15_000)  # never completes
            conns.append((r, w))
        await asyncio.sleep(0.5)
        assert h.sensor.buffered <= 100_000 + 2 * 16 * 1024
        reasons = [d.data["reason"] for d in await h.events("disconnect")]
        assert reasons.count("budget") >= 4
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
        await loop.sock_sendall(s, prelogin() + login7("sa", "sa"))
        payload = batch("select * from sys.sql_logins") * 300
        for _ in range(30):
            try:
                await loop.sock_sendall(s, payload)
            except OSError:
                break
        d = (await h.wait_disconnects(1, timeout=15))[0]
        assert d.data["reason"] in ("write_timeout", "client_reset", "input_limit")
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
            w.write(prelogin())
            await r.read(100)
            conns.append((r, w))
        _cgroup(tmp_path, 75 << 20, 100 << 20)
        guard.sample()
        assert guard.refusing
        r, w = await asyncio.open_connection("127.0.0.1", h.port)
        assert await r.read(100) == b""
        w.close()
        _cgroup(tmp_path, 90 << 20, 100 << 20)
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


async def test_hostile_batches_do_not_stall_the_loop(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        r, w = await asyncio.open_connection("127.0.0.1", h.port)
        w.write(prelogin() + login7("sa", "sa"))
        nasty = ["select " + "(" * 30000, "'" * 30000, "exec " + "a." * 15000, " exec " * 5000]
        for text in nasty:
            w.write(batch(text[:16000]))
        w.write(batch("select 42"))
        await w.drain()
        t0 = time.monotonic()
        seen = b""
        async with asyncio.timeout(8):
            while b"\xd1\x2a\x00\x00\x00" not in seen:
                chunk = await r.read(65536)
                assert chunk
                seen += chunk
        assert time.monotonic() - t0 < 3.0
        w.close()


async def test_flood_from_many_ips_is_aggregated(make_harness: HarnessFactory) -> None:
    async with make_harness(sink_kw={"per_ip_rate": 0.001, "per_ip_burst": 2.0}) as h:
        for _ in range(10):
            await talk(h.port, prelogin(), wait=0.05)
        await asyncio.sleep(0.2)
        assert h.sink.sessions_suppressed == 8
        assert h.sink.flush_suppressed(60.0) == 1
        scans = await h.events("scan")
        assert scans[-1].data["kind"] == "rate_limited"
        assert len(await h.events("connect")) == 2


async def test_parallel_connections_memory_plateau(make_harness: HarnessFactory) -> None:
    async with make_harness(max_connections=200, max_per_ip=200) as h:
        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        for _round in range(3):
            conns = [await asyncio.open_connection("127.0.0.1", h.port) for _ in range(150)]
            for _, w in conns:
                w.write(
                    prelogin() + login7("sa", "sa") + b"\x01\x00\x7f\xff\0\0\0\0" + b"x" * 30_000
                )
            await asyncio.sleep(0.3)
            for _, w in conns:
                w.close()
            await asyncio.sleep(0.3)
        grown = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before
        assert grown < 120_000
        assert h.sensor.total == 0 and h.sensor.buffered == 0


async def test_expensive_batches_from_two_ips_do_not_delay_a_victim(
    make_harness: HarnessFactory,
) -> None:
    """2 IPs x 8 connections of the most expensive batch; a third IP must not notice."""
    async with make_harness(max_per_ip=50, idle_timeout=30.0, max_session=60.0) as h:
        heavy = batch(("select " + "serverproperty('a') " * 600 + " exec x " * 1500)[:16000])
        conns = []
        for source in ("127.0.0.3", "127.0.0.4"):
            for _ in range(8):
                r, w = await asyncio.open_connection("127.0.0.1", h.port, local_addr=(source, 0))
                w.write(prelogin() + login7("sa", "sa") + heavy * 150)
                conns.append((r, w))
        await asyncio.sleep(0.5)
        worst = 0.0
        for _ in range(6):  # fresh connections and queries of the victim while the load runs
            t0 = time.monotonic()
            c = await Client.connect(h.port, source="127.0.0.2")
            await c.login("sa", "sa")
            await c.request(batch("select 1"))
            worst = max(worst, time.monotonic() - t0)
            await c.close()
            await asyncio.sleep(0.2)
        assert worst < 1.0, worst
        for _, w in conns:
            w.close()
        # the abusers recover on their own once the load stops
        await asyncio.sleep(0.5)
        t0 = time.monotonic()
        async with asyncio.timeout(8):
            c = await Client.connect(h.port, source="127.0.0.3")
            await c.login("sa", "sa")
            await c.request(batch("select 1"))
            await c.close()
        assert time.monotonic() - t0 < 8


def test_cpu_delay_throttles_one_ip_only() -> None:
    from mssql_sensor.config import Config
    from mssql_sensor.identity import derive_profile
    from mssql_sensor.server import Sensor

    class _Sink:
        pass

    sensor = Sensor(Config(), _Sink(), derive_profile("ab" * 32))  # type: ignore[arg-type]
    assert sensor.cpu_delay("192.0.2.1", 0.01) == 0.0
    waits = [sensor.cpu_delay("192.0.2.1", 0.2) for _ in range(6)]
    assert waits[-1] > 0.5
    assert sensor.cpu_delay("192.0.2.2", 0.01) <= waits[-1]


async def test_flooding_ip_cannot_starve_a_victim(make_harness: HarnessFactory) -> None:
    from suckerpot_common import EventType

    async with make_harness() as h:
        for i in range(3000):
            h.sink.emit(
                session_id="flood", src_ip="203.0.113.9", src_port=1000 + i % 100,
                type_=EventType.command, data={"input": "select 1"},
            )  # fmt: skip
            h.sink.emit(
                session_id="flood", src_ip="203.0.113.9", src_port=1,
                type_=EventType.login_attempt, data={"username": "sa", "password": str(i)},
                priority=True,
            )  # fmt: skip
        for i in range(5):
            assert h.sink.emit(
                session_id="victim", src_ip="198.51.100.7", src_port=2, type_=EventType.login_attempt,
                data={"username": "sa", "password": f"v{i}"}, priority=True,
            )  # fmt: skip
        got = [e for e in await h.events("login_attempt") if e.src_ip.exploded == "198.51.100.7"]
        assert len(got) == 5
        flood = [e for e in h.publisher.events if str(e.src_ip) == "203.0.113.9"]
        assert len(flood) < 400  # per-IP budgets cut the flood before the shared queue
        assert h.sink.flush_suppressed(60.0) >= 1
        scans = await h.events("scan")
        assert any(e.data.get("kind") == "events_limited" for e in scans)

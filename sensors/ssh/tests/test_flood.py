"""Regression tests for review pass 3: input floods, shell CPU starvation, event bytes."""

from __future__ import annotations

import asyncio
import contextlib
import time
from pathlib import Path
from typing import Any

import asyncssh
import pytest
from suckerpot_common import Event, EventType

from ssh_sensor import server as server_mod
from ssh_sensor.config import Config
from ssh_sensor.cpu import CpuBudget
from ssh_sensor.events import EventSink, approx_size
from ssh_sensor.memguard import MemoryProbe
from ssh_sensor.server import _pending_input
from ssh_sensor.shell.interp import Shell


class FakePublisher:
    async def publish(self, event: Event) -> bool:
        return True

    async def close(self) -> None:
        return None


LINE = b"echo " + b"x" * 4000 + b"\n"


def rss_bytes() -> int:
    return MemoryProbe(1).rss()


async def flood(proc: asyncssh.SSHClientProcess[bytes], seconds: float, line: bytes = LINE) -> int:
    """Write ``line`` as fast as the server's window allows; returns the bytes sent."""
    sent = 0
    end = time.monotonic() + seconds
    chunk = line * 16
    try:
        while time.monotonic() < end and not proc.stdin.channel.is_closing():
            proc.stdin.write(chunk)
            await asyncio.wait_for(proc.stdin.drain(), 5)
            sent += len(chunk)
    except (asyncssh.Error, ConnectionError, OSError, TimeoutError):
        pass
    return sent


async def drain_output(proc: asyncssh.SSHClientProcess[bytes]) -> None:
    try:
        while await proc.stdout.read(65536):
            pass
    except (asyncssh.Error, ConnectionError, OSError):
        pass


def slow_lines(monkeypatch: pytest.MonkeyPatch, seconds: float) -> None:
    """Make every command line burn ``seconds`` of real CPU on the event loop."""
    original = Shell.run_line

    def run_line(self: Shell, line: str) -> Any:
        end = time.perf_counter() + seconds
        while time.perf_counter() < end:
            pass
        return original(self, line)

    monkeypatch.setattr(Shell, "run_line", run_line)


# ---- H1: input floods ----------------------------------------------------------------------
async def test_unread_input_stays_within_the_window(make_harness, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    slow_lines(monkeypatch, 0.002)
    window = 64 * 1024
    async with make_harness(channel_window=window, shell_cpu_share=0.05, shell_cpu_burst=0.05) as h:
        conn = await h.connect()
        proc = await conn.create_process(None, encoding=None)
        reader = asyncio.create_task(drain_output(proc))
        writer = asyncio.create_task(flood(proc, 2.0))
        peak = 0
        while not writer.done():
            await asyncio.sleep(0.05)
            for c in h.sensor.connections:
                for p in c.processes:
                    peak = max(peak, _pending_input(p))
        sent = await writer
        reader.cancel()
        conn.close()
    # stream buffer (one window) + channel buffer (one window) + one packet
    assert peak <= 2 * window + 32 * 1024, peak
    assert sent < 4 * 1024 * 1024  # the slow shell throttled the client


async def test_input_backstop_closes_flooding_session(make_harness, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # Without the fixed window accounting, asyncssh lets unread input grow: the backstop
    # must close the session.
    monkeypatch.setattr(
        server_mod._FlowControlledChannel,
        "_deliver_data",
        asyncssh.SSHServerChannel._deliver_data,
    )
    slow_lines(monkeypatch, 0.002)
    async with make_harness(channel_window=16 * 1024, shell_cpu_share=0.02) as h:
        conn = await h.connect()
        proc = await conn.create_process(None, encoding=None)
        reader = asyncio.create_task(drain_output(proc))
        await flood(proc, 4.0)
        reader.cancel()
        conn.close()
        disc = await h.events(EventType.disconnect)
    assert disc and disc[-1].data["reason"] == "input flood"


async def test_fifteen_flooding_sessions_keep_memory_low(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(shell_cpu_share=0.3, shell_cpu_burst=0.2, max_per_ip=20) as h:
        before = rss_bytes()
        conns = [await h.connect() for _ in range(15)]
        procs = [await c.create_process(None, encoding=None) for c in conns]
        readers = [asyncio.create_task(drain_output(p)) for p in procs]
        sent = await asyncio.gather(*(flood(p, 4.0) for p in procs))
        tracked = sum(_pending_input(p) for c in h.sensor.connections for p in c.processes)
        after = rss_bytes()
        for r in readers:
            r.cancel()
        for c in conns:
            c.close()
    assert sum(sent) > 0
    assert tracked <= 15 * (2 * 64 * 1024 + 32 * 1024), tracked
    assert after < 200 * 1024 * 1024, after
    assert after - before < 64 * 1024 * 1024, (before, after)


async def test_tiny_packet_flood_is_metered(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(
        inbound_conn_bytes_per_sec=8 * 1024, inbound_conn_bytes_burst=16 * 1024
    ) as h:
        conn = await h.connect()
        proc = await conn.create_process(None, encoding=None)
        reader = asyncio.create_task(drain_output(proc))
        start_bytes = h.sensor.inbound_bytes
        t0 = time.monotonic()
        end = t0 + 2.0
        sent = 0
        with contextlib.suppress(TimeoutError, BrokenPipeError, ConnectionError):
            while time.monotonic() < end:  # one tiny SSH packet per write (window allowing)
                proc.stdin.write(b"echo busy\n")
                sent += 10
                if sent % 1000 == 0:
                    # backpressure: the metered server stops opening the window
                    await asyncio.wait_for(proc.stdin.drain(), max(0.01, end - time.monotonic()))
        processed = h.sensor.inbound_bytes - start_bytes
        elapsed = time.monotonic() - t0
        assert h.sensor.inbound_pauses > 0
        # wire bytes fed to asyncssh: burst + rate x time + one slice (4 KiB)
        assert processed <= 16 * 1024 + 8 * 1024 * elapsed + 8 * 1024, (processed, elapsed)
        reader.cancel()
        conn.close()
    # the session still worked: commands from the metered input ran
    cmds = [e for e in h.publisher.events if e.type == EventType.command]
    assert cmds and cmds[0].data["input"] == "echo busy"


def _fake_cgroup(tmp_path: Path, current: int, maximum: str = "1000", inactive: int = 0) -> Path:
    (tmp_path / "memory.current").write_text(f"{current}\n")
    (tmp_path / "memory.max").write_text(f"{maximum}\n")
    (tmp_path / "memory.stat").write_text(f"anon 1\ninactive_file {inactive}\nactive_file 3\n")
    return tmp_path


def test_memory_probe_cgroup_and_fallback(tmp_path: Path) -> None:
    probe = MemoryProbe(5000, cgroup=_fake_cgroup(tmp_path, 800, inactive=300))
    assert probe.limit() == 1000 and probe.usage() == 500
    unlimited = MemoryProbe(5000, cgroup=_fake_cgroup(tmp_path, 1, "max"))
    assert unlimited.limit() == 5000
    status = tmp_path / "status"
    status.write_text("Name:\tpython\nVmRSS:\t   2048 kB\n")
    none = MemoryProbe(5000, cgroup=tmp_path / "missing", proc_status=status)
    assert none.usage() == 2048 * 1024 and none.limit() == 5000


class _StubProbe:
    def __init__(self, used: int, limit: int) -> None:
        self.used, self.lim = used, limit

    def usage(self) -> int:
        return self.used

    def limit(self) -> int:
        return self.lim


async def test_memory_guard_refuses_then_drops(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        conn = await h.connect()
        held = await conn.create_process(None, encoding="utf-8")  # keeps the connection open
        held.stdin.write("echo warm\n")
        assert (await asyncio.wait_for(held.stdout.readline(), 5)) == "warm\n"
        sensor = h.sensor
        assert len(sensor.connections) == 1
        tracked = sensor.memory_in_use()
        # retained heap only (sessions hold little): the guard does not act
        sensor.memory = _StubProbe(95 << 30, 100 << 30)
        sensor.guard_tick()
        assert sensor.mem_level == 0
        # sessions hold a real share: pressure, then critical
        limit = tracked * 4
        sensor.memory = _StubProbe(int(limit * 0.75), limit)
        sensor.guard_tick()
        assert sensor.mem_level == 1
        assert all(c.throttled for c in sensor.connections)
        assert not sensor.admit("198.51.100.20") and sensor.mem_refused == 1
        with pytest.raises(asyncssh.ChannelOpenError):
            await conn.run("echo refused")
        limit = max(1, sensor.memory_in_use()) * 4
        sensor.memory = _StubProbe(int(limit * 0.9), limit)
        sensor.guard_tick()
        assert sensor.mem_dropped == 1
        await asyncio.wait_for(conn.wait_closed(), 5)
        disc = await h.events(EventType.disconnect)
        assert disc[-1].data["reason"] == "memory limit"
        sensor.memory = _StubProbe(10, limit)
        sensor.guard_tick()
        assert sensor.mem_level == 0 and sensor.admit("198.51.100.21")
        sensor.release("198.51.100.21")


async def test_per_ip_share_of_memory_budget(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(memory_budget=4 * 1024 * 1024, memory_share_per_ip=0.1) as h:
        conn = await h.connect()
        proc = await conn.create_process(None, encoding="utf-8")
        for i in range(160):  # ~480 KB in the fake filesystem, over 10% of 4 MiB
            proc.stdin.write(f"echo {'y' * 3000} >> /tmp/a{i % 4}\n")
        proc.stdin.write("echo hi\n")
        proc.stdin.write_eof()
        await asyncio.wait_for(proc.wait_closed(), 20)
        err = await proc.stderr.read()
        assert "Cannot allocate memory" in err
        # another source IP is not affected by this IP's share
        assert not h.sensor.over_budget("198.51.100.30")
        conn.close()


# ---- H2: shell CPU -------------------------------------------------------------------------
async def test_cpu_budget_is_fair_across_ips() -> None:
    budget = CpuBudget(0.3, 0.05)
    stop = time.monotonic() + 2.0
    heavy_runs = 0

    async def heavy() -> None:
        nonlocal heavy_runs
        while time.monotonic() < stop:
            if await budget.acquire("198.51.100.1", 10):
                heavy_runs += 1
                budget.spend("198.51.100.1", 0.05)
            await asyncio.sleep(0)

    waits: list[float] = []

    async def light() -> None:
        while time.monotonic() < stop:
            t = time.monotonic()
            assert await budget.acquire("203.0.113.5", 10)
            waits.append(time.monotonic() - t)
            budget.spend("203.0.113.5", 0.001)
            await asyncio.sleep(0.1)

    tasks = [asyncio.create_task(heavy()) for _ in range(40)]
    await light()
    counted = heavy_runs
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    heavy_runs = counted
    assert heavy_runs > 0 and len(waits) >= 10
    assert max(waits) < 0.6, max(waits)
    # the heavy IP used at most its refill rate (plus the burst and one overshoot)
    assert heavy_runs * 0.05 <= 0.3 * 2.0 + 0.05 + 0.2


async def test_cpu_budget_refuses_after_max_wait() -> None:
    budget = CpuBudget(0.1, 0.05)
    budget.spend("198.51.100.1", 1.0)  # deep debt: about 10 s to repay
    assert not await budget.acquire("198.51.100.2", 0.2)
    assert budget.refused == 1
    assert budget.stats()["cpu_waiting"] == 0


async def test_busy_channels_do_not_block_the_loop(make_harness, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    slow_lines(monkeypatch, 0.1)  # each line blocks the loop for 100 ms
    async with make_harness(shell_cpu_share=0.3, shell_cpu_burst=0.2, max_per_ip=40) as h:
        conns = [await h.connect() for _ in range(20)]
        procs = [await c.create_process(None, encoding=None) for c in conns for _ in range(2)]
        readers = [asyncio.create_task(drain_output(p)) for p in procs]
        lags: list[float] = []

        async def heartbeat() -> None:
            last = time.monotonic()
            while True:
                await asyncio.sleep(0.05)
                now = time.monotonic()
                lags.append(now - last - 0.05)
                last = now

        beat = asyncio.create_task(heartbeat())
        start = time.monotonic()
        # big writes: few SSH packets, so the shell (not the in-process client's crypto) is
        # what would load the loop
        await asyncio.gather(*(flood(p, 3.0, b"echo busy\n" * 200) for p in procs))
        elapsed = time.monotonic() - start
        beat.cancel()
        for r in readers:
            r.cancel()
        for c in conns:
            c.close()
        # 40 channels x 100 ms would stall the loop for 4 s per round without the budget
        assert max(lags) < 1.0, max(lags)
        assert h.sensor.cpu.spent <= 0.3 * elapsed + 0.2 + 0.3


async def test_cpu_refusal_looks_like_fork_failure(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(shell_cpu_share=0.05, shell_cpu_burst=0.05) as h:
        h.sensor.cpu.spend("127.0.0.1", 1.0)
        server_mod._CPU_MAX_WAIT, old = 0.2, server_mod._CPU_MAX_WAIT
        try:
            conn = await h.connect()
            r = await conn.run("id")
        finally:
            server_mod._CPU_MAX_WAIT = old
        assert "fork: retry: Resource temporarily unavailable" in str(r.stderr)
        assert r.exit_status == 254
        conn.close()


# ---- H3: event bytes -----------------------------------------------------------------------
def _sink(**kw: Any) -> tuple[EventSink, FakePublisher]:
    pub = FakePublisher()
    params: dict[str, Any] = {
        "valuable_rate": 1e6,
        "valuable_burst": 1e6,
        "global_rate": 1e6,
        "global_burst": 1e6,
        **kw,
    }
    return EventSink(pub, **params), pub


def _command(sink: EventSink, ip: str, output: str, session: str = "s1") -> bool:
    return sink.emit(
        session_id=session,
        src_ip=ip,
        src_port=1,
        type_=EventType.command,
        data={"input": "cat x", "output": output, "output_preview": output[:1024], "status": 0},
        max_string=8192,
    )


def _queued(sink: EventSink) -> list[dict[str, Any]]:
    items = []
    while not sink._queue.empty():
        event, _ = sink._queue.get_nowait()
        items.append(event.data)
    return items


def test_per_ip_event_bytes_degrade_then_drop() -> None:
    sink, _ = _sink(ip_bytes_rate=1.0, ip_bytes_burst=22_000.0)
    out = "z" * 8000
    results = [_command(sink, "198.51.100.7", out) for _ in range(6)]
    data = _queued(sink)
    full = [d for d in data if "output" in d]
    degraded = [d for d in data if d.get("output_omitted")]
    assert len(full) == 2  # ~9.3 KB each, then ~3 KB left: room for degraded events only
    assert degraded and all(len(d["output_preview"]) == 1024 and d["input"] for d in degraded)
    assert results.count(False) >= 1 and sink.byte_limited >= 1
    assert sink.end_session("s1") == results.count(False)
    # another IP has its own budget
    assert _command(sink, "203.0.113.8", out)
    assert "output" in _queued(sink)[0]


def test_global_event_bytes_and_priority() -> None:
    sink, _ = _sink(global_bytes_rate=1.0, global_bytes_burst=30_000.0)
    out = "q" * 8000
    ips = [f"198.51.100.{i}" for i in range(1, 20)]
    sent = [_command(sink, ip, out, session=ip) for ip in ips]
    assert sent.count(False) > 0  # the global budget caps all IPs together
    # the reserve of the global budget is kept for priority events
    assert sink.emit(
        session_id="p",
        src_ip="192.0.2.1",
        src_port=1,
        type_=EventType.disconnect,
        data={"reason": "closed by client", "commands": 3},
        priority=True,
    )


def test_event_queue_is_capped_in_bytes() -> None:
    sink, _ = _sink(queue_bytes=50_000)
    sent = [_command(sink, f"198.51.100.{i}", "w" * 8000, session=str(i)) for i in range(20)]
    assert sent.count(True) <= 6 and sink.queue_full > 0
    assert sink.queued_bytes <= 50_000


def test_disconnect_replay_is_dropped_before_the_event() -> None:
    sink, _ = _sink(global_bytes_rate=1.0, global_bytes_burst=10_000.0)
    replay = [[0.1, "o", "r" * 4000] for _ in range(4)]
    assert sink.emit(
        session_id="d",
        src_ip="198.51.100.9",
        src_port=1,
        type_=EventType.disconnect,
        data={"reason": "closed by client", "replay": replay},
        cap_data=False,
        priority=True,
    )
    (data,) = _queued(sink)
    assert data.get("replay_omitted") and "replay" not in data


def test_approx_size_tracks_json_size() -> None:
    import json

    sample = {"a": "x" * 1000, "b": [1, 2, {"c": "é" * 100}], "d": None}
    real = len(json.dumps(sample, ensure_ascii=False).encode())
    assert 0.8 * real <= approx_size(sample) <= 1.3 * real


async def test_repeated_lines_collapse_into_one_counted_event(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        conn = await h.connect()
        proc = await conn.create_process(None, encoding="utf-8")
        proc.stdin.write("uname -a\n" * 50 + "id\n")
        proc.stdin.write_eof()
        await asyncio.wait_for(proc.wait_closed(), 10)
        conn.close()
        await asyncio.wait_for(conn.wait_closed(), 5)
        cmds = await h.events(EventType.command)
        disc = await h.events(EventType.disconnect)
    inputs = [(e.data["input"], e.data.get("repeat_count")) for e in cmds]
    assert inputs == [("uname -a", None), ("uname -a", 49), ("id", None)]
    counted = cmds[1].data
    assert counted["first_ts"] <= counted["last_ts"] and "Linux" in counted["output_preview"]
    assert disc[-1].data["commands"] == 51


def test_new_settings_from_env() -> None:
    cfg = Config.from_env(
        {
            "SSH_CHANNEL_WINDOW_KB": "32",
            "SSH_SHELL_CPU_SHARE": "5",
            "SSH_MEMORY_PRESSURE": "0.6",
            "SSH_MEMORY_SHARE_PER_IP": "0.5",
            "SSH_IP_EVENT_BYTES_PER_SEC": "10",
        }
    )
    assert cfg.channel_window == 32 * 1024
    assert cfg.shell_cpu_share == 0.9  # clamped
    assert cfg.memory_pressure == 0.6 and cfg.memory_share_per_ip == 0.5
    assert cfg.ip_event_bytes_per_sec == 1000.0  # floor
    assert cfg.max_pending_input == 4 * 32 * 1024 + cfg.max_pktsize

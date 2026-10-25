"""CPU and memory fairness: expensive statements and silent peers must never hurt the sensor."""

from __future__ import annotations

import asyncio
import socket
import sys
import time
from pathlib import Path

from conftest import HarnessFactory
from test_limits import native_response, query_packet, read_packet

from mysql_sensor import sqlish, wire
from mysql_sensor.events import Throttle
from mysql_sensor.responder import Err, Responder, ResultSet

CLIENT = str(Path(__file__).with_name("scanclient.py"))


def responder(**kw: float) -> Responder:
    return Responder(
        version="8.0.43-0ubuntu0.24.04.2",
        hostname="srv-db01",
        user="root",
        client_ip="192.0.2.10",
        client_port=40000,
        conn_id=7,
        uptime=lambda: 86400,
        seed="s" * 64,
        **kw,  # type: ignore[arg-type]
    )


def answer(r: Responder, sql: str) -> list[object]:
    return [r.respond(s, sql) for s in sqlish.split_statements(sqlish.tokenize(sql))]


def test_unfiltered_count_is_arithmetic() -> None:
    r = responder()
    r.begin_query()
    res = answer(r, "SELECT COUNT(*) FROM shop.orders")[0]
    assert isinstance(res, ResultSet) and res.rows == [("5310",)]
    assert r.steps_used <= 10  # no rows were examined


def test_fifty_full_scans_in_one_query_cost_one_scan() -> None:
    r = responder()
    r.begin_query()
    sql = ";".join(f"SELECT COUNT(*) FROM shop.orders WHERE status='zz{i}'" for i in range(50))
    results = answer(r, sql)
    assert isinstance(results[0], ResultSet) and results[0].rows == [("0",)]
    assert isinstance(results[1], Err) and results[1].code == 1317  # budget spent: interrupted
    assert r.steps_used <= r.query_steps


def test_filtered_results_are_cached_per_table_and_filter() -> None:
    r = responder()
    r.begin_query()
    first = answer(r, "SELECT COUNT(*) FROM shop.orders WHERE status='zz'")[0]
    spent = r.steps_used
    assert spent >= 5000
    r.begin_query()
    again = answer(r, "SELECT COUNT(*) FROM shop.orders WHERE status='zz'")[0]
    assert again == first and r.steps_used <= 10
    # A filtered row query is answered from the same scan, rows generated on demand.
    r.begin_query()
    rows = answer(r, "SELECT id FROM shop.customers WHERE first_name LIKE 'a%' LIMIT 3")[0]
    assert isinstance(rows, ResultSet) and len(rows.rows) <= 3


def test_rows_beyond_the_scan_budget_are_not_examined() -> None:
    r = responder(query_steps=1000)
    r.begin_query()
    res = answer(r, "SELECT COUNT(*) FROM shop.orders WHERE status='zz'")[0]
    assert isinstance(res, Err) and res.code == 1317
    assert r.steps_used <= 1000


def test_sleep_is_capped_per_call_query_and_connection() -> None:
    r = responder(sleep_per_query=7.0, sleep_per_connection=9.0)
    r.begin_query()
    first = answer(r, "SELECT SLEEP(10)")[0]
    assert isinstance(first, ResultSet) and first.delay == 5.0  # the documented SLEEP(10) tell
    second = answer(r, "SELECT SLEEP(10)")[0]
    assert isinstance(second, ResultSet) and second.delay == 2.0  # per-query budget (7 s)
    r.begin_query()
    third = answer(r, "SELECT SLEEP(10)")[0]
    assert isinstance(third, ResultSet) and third.delay == 2.0  # connection budget (9 s)
    r.begin_query()
    last = answer(r, "SELECT SLEEP(10)")[0]
    assert isinstance(last, ResultSet) and last.delay == 0.0


def test_throttle_serves_a_key_at_its_rate() -> None:
    t = Throttle(rate=1000.0, burst=500.0)
    assert t.reserve("a", 500, now=0.0) == 0.0  # inside the burst
    assert t.reserve("a", 500, now=0.0) == 0.5  # backlog: 1000 steps at 1000/s, minus the burst
    assert t.reserve("b", 100, now=0.0) == 0.0  # other keys are independent
    assert t.reserve("a", 1000, now=10.0) == 0.5


async def lag_probe(stop: asyncio.Event, out: list[float]) -> None:
    """Records how long the loop was blocked, as seen by a 20 ms timer.

    A timer can fire late because the loop was busy (what matters) or because the whole
    process was descheduled by a loaded host (what does not). The CPU time the loop thread
    used while the timer waited tells them apart: a real block of B seconds needs at least B
    seconds of CPU, so ``min(lateness, cpu time)`` never under-reports it.
    """
    while not stop.is_set():
        t, c = time.monotonic(), time.thread_time()
        await asyncio.sleep(0.02)
        out.append(min(time.monotonic() - t - 0.02, time.thread_time() - c))


async def spawn(port: int, src: str, conns: int, secs: float) -> asyncio.subprocess.Process:
    return await asyncio.create_subprocess_exec(
        sys.executable, "-I", CLIENT, "127.0.0.1", str(port), src, str(conns), str(secs),
        stdout=asyncio.subprocess.PIPE,
    )  # fmt: skip


async def run_load(make_harness: HarnessFactory, secs: float) -> tuple[float, int]:
    async with make_harness(max_per_ip=8) as h:
        lags: list[float] = []
        stop = asyncio.Event()
        probe = asyncio.create_task(lag_probe(stop, lags))
        procs = [
            await spawn(h.port, "127.0.0.1", 8, secs),
            await spawn(h.port, "127.0.0.2", 8, secs),
            await spawn(h.port, "127.0.0.3", 8, secs),
        ]
        answered = 0
        for p in procs:
            out, _ = await p.communicate()
            answered += int(out.decode().split("=")[1])
        stop.set()
        await probe
        assert h.sensor.errors == 0
        return max(lags), answered


async def test_full_scan_statements_do_not_block_the_loop(make_harness: HarnessFactory) -> None:
    """H1: 3 sources x 8 connections x 50 full-scan statements per COM_QUERY for 30 s.

    Before the work budget, one such connection cost the loop ~1.2 s per query and three of
    them tripped the watchdog. The loop must stay responsive (lag < 1 s) and nothing may fail.
    """
    worst, answered = await run_load(make_harness, 30.0)
    print(f"worst loop lag {worst:.3f}s, answered {answered}")
    assert worst < 1.0
    assert answered > 0


def rss() -> int:
    return int(Path("/proc/self/statm").read_text().split()[1]) * 4096


async def test_non_reading_connections_stay_below_the_memory_limit(
    make_harness: HarnessFactory,
) -> None:
    """Lesson 17: 200 connections over 25 sources ask for big results and never read them."""
    limit = 256 * 1024 * 1024
    async with make_harness(max_connections=200, max_per_ip=8, write_timeout=60.0) as h:
        before = rss()
        socks: list[asyncio.StreamWriter] = []
        for k in range(200):
            sock = socket.socket()
            sock.setblocking(False)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            sock.bind((f"127.0.0.{2 + k % 25}", 0))
            await asyncio.get_running_loop().sock_connect(sock, ("127.0.0.1", h.port))
            reader, writer = await asyncio.open_connection(sock=sock)
            await read_packet(reader)
            writer.write(wire.pack(1, native_response()))
            await read_packet(reader)
            writer.write(query_packet("select * from shop.customers limit 200") * 30)
            socks.append(writer)  # kept open, and nothing ever reads the replies
        await asyncio.sleep(3.0)
        assert h.sensor.total == 200
        pending = sum(s.out_charge for s in h.sensor.sessions)
        assert pending <= 200 * (h.cfg.output_cap + 16 * 1024)
        assert h.sensor.held <= 200 * h.cfg.conn_cost + pending
        assert rss() - before <= 0.7 * limit
        print(f"held {h.sensor.held >> 10} KiB, rss growth {(rss() - before) >> 20} MiB")
        for w in socks:
            w.transport.abort()

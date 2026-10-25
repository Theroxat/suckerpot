"""Abuse resistance: non-reading and slow clients, floods, memory budget."""

from __future__ import annotations

import asyncio
import os
import socket
import time

from conftest import Harness, start


def _rss() -> int:
    with open("/proc/self/statm") as fh:
        return int(fh.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")


def _stuck(port: int, payload: bytes) -> socket.socket:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
    s.connect(("127.0.0.1", port))
    s.sendall(payload)
    return s


async def _drained(h: Harness) -> None:
    for _ in range(150):
        if h.sensor.total == 0:
            break
        await asyncio.sleep(0.1)
    assert h.sensor.total == 0 and h.sensor.budget.used == 0 and not h.sensor.live


async def test_non_reading_pipeliner_is_dropped_and_memory_bounded() -> None:
    async with start({"write_timeout": 1.0, "max_per_ip": 100}) as h:
        base = _rss()
        req = b"GET /info HTTP/1.1\r\nHost: x\r\n\r\n" * 400
        socks = await asyncio.to_thread(lambda: [_stuck(h.port, req) for _ in range(60)])
        peak = 0
        for _ in range(30):
            await asyncio.sleep(0.1)
            peak = max(peak, _rss() - base)
            assert h.sensor.budget.used <= h.sensor.budget.limit
        assert peak < 60 * 1024 * 1024, peak
        # the sensor still answers a normal client
        status, _, body = await h.http("GET", "/_ping")
        assert (status, body) == (200, b"OK")
        await asyncio.sleep(2.0)  # write_timeout: stuck writers are aborted
        for s in socks:
            s.close()
        await _drained(h)


async def test_slowloris_head_times_out() -> None:
    async with start({"head_timeout": 0.5}) as h:
        r, w = await asyncio.open_connection("127.0.0.1", h.port)
        w.write(b"GET /_ping HTTP/1.1\r\nHost: x\r\n")
        t0 = time.monotonic()
        assert await asyncio.wait_for(r.read(10), 3) == b""
        assert time.monotonic() - t0 < 2
        scans = await h.events("scan")
        assert scans[0].data["kind"] == "incomplete_request"
        await _drained(h)


async def test_slow_body_times_out() -> None:
    async with start({"body_timeout": 0.5}) as h:
        r, w = await asyncio.open_connection("127.0.0.1", h.port)
        w.write(b"POST /containers/create HTTP/1.1\r\nHost: x\r\nContent-Length: 500\r\n\r\n{")
        assert await asyncio.wait_for(r.read(10), 3) == b""
        reqs = await h.events("http_request")
        assert "incomplete_body" in reqs[-1].data["flags"]
        await _drained(h)


async def test_idle_keepalive_closes() -> None:
    async with start({"keepalive_timeout": 0.3}) as h:
        r, w = await asyncio.open_connection("127.0.0.1", h.port)
        w.write(b"GET /_ping HTTP/1.1\r\nHost: x\r\n\r\n")
        assert (await asyncio.wait_for(r.read(500), 2)).startswith(b"HTTP/1.1 200")
        assert await asyncio.wait_for(r.read(10), 2) == b""
        await _drained(h)


async def test_body_budget_refuses_not_crashes() -> None:
    # Budget fits the connections but only one in-flight body at a time.
    async with start({"memory_budget": 96 * 1024 * 3 + 500_000}) as h:
        conns = []
        for _ in range(3):
            r, w = await asyncio.open_connection("127.0.0.1", h.port)
            w.write(
                b"POST /containers/create HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n{"
            )
            conns.append((r, w))
        await asyncio.sleep(0.5)
        refused = 0
        for r, w in conns[1:]:
            data = await asyncio.wait_for(r.read(300), 2)
            refused += data.startswith(b"HTTP/1.1 503")
        assert refused >= 1
        for _, w in conns:
            w.close()
        await _drained(h)


async def test_event_budget_per_session() -> None:
    async with start({"events_per_sec": 1.0, "events_burst": 5.0}) as h:
        sink_calls = 0
        req = b"GET /_ping HTTP/1.1\r\nHost: x\r\n\r\n" * 50
        await h.raw(req + b"GET /_ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", wait=1.0)
        reqs = await h.events("http_request")
        # Identical ordinary requests are kept three times, then only counted.
        assert len(reqs) == 3
        disc = await h.events("disconnect")
        assert disc[0].data["requests"] == 51 and disc[0].data["repeats"] == 48


async def test_oversized_head_gets_431() -> None:
    async with start() as h:
        raw = await h.raw(b"GET /_ping HTTP/1.1\r\nHost: x\r\nX: " + b"a" * 40000 + b"\r\n\r\n")
        assert raw.startswith(b"HTTP/1.1 431")
        await _drained(h)


def _client(port: int, src: str) -> socket.socket:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
    s.bind((src, 0))
    s.connect(("127.0.0.1", port))
    return s


async def test_expensive_requests_from_many_ips_do_not_block_the_loop() -> None:
    """Lesson 16: 3 IPs x 8 connections of the most expensive request, latency stays low."""
    body = b'{"Image":"a","Cmd":["x"],"y":[' + b"[0]," * 40000 + b"0]}"
    req = (
        b"POST /containers/create HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % len(body)
        + body
    ) * 4
    async with start({"max_per_ip": 8, "conn_burst": 100.0}) as h:
        socks = await asyncio.to_thread(
            lambda: [_client(h.port, f"127.0.0.{ip}") for ip in (2, 3, 4) for _ in range(8)]
        )
        for s in socks:
            await asyncio.to_thread(s.sendall, req)
        worst = 0.0
        for _ in range(15):
            t0 = time.monotonic()
            r, w = await asyncio.open_connection("127.0.0.1", h.port)
            w.write(b"GET /_ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            assert (await asyncio.wait_for(r.read(300), 5)).startswith(b"HTTP/1.1 200")
            w.close()
            worst = max(worst, time.monotonic() - t0)
            await asyncio.sleep(0.2)
        assert worst < 1.0, worst
        assert h.sensor.cpu_waits > 0, h.sensor.stats()
        for s in socks:
            s.close()


async def test_url_heavy_bodies_and_pipelines_do_not_block_the_loop() -> None:
    """Lesson 16: 250 KB bodies full of URLs plus long keep-alive pipelines, from 2 IPs."""
    urls = " ".join(f"http://198.51.100.{i % 250}/a/b{i}.sh" for i in range(6000))[:240000]
    body = b'{"Image":"a","Cmd":["sh","-c","' + urls.encode() + b'"]}'
    heavy = (
        b"POST /containers/create HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % len(body)
        + body
    ) * 4
    pipeline = b"GET /containers/json?all=1 HTTP/1.1\r\nHost: x\r\n\r\n" * 150
    async with start({"max_per_ip": 8, "conn_burst": 100.0}) as h:
        socks = await asyncio.to_thread(
            lambda: [_client(h.port, f"127.0.0.{ip}") for ip in (2, 3) for _ in range(8)]
        )
        for i, s in enumerate(socks):
            await asyncio.to_thread(s.sendall, heavy if i % 2 else pipeline)
        worst = 0.0
        for _ in range(15):
            t0 = time.monotonic()
            r, w = await asyncio.open_connection("127.0.0.1", h.port)
            w.write(b"GET /_ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            assert (await asyncio.wait_for(r.read(300), 5)).startswith(b"HTTP/1.1 200")
            w.close()
            worst = max(worst, time.monotonic() - t0)
            await asyncio.sleep(0.2)
        assert worst < 1.0, worst
        for s in socks:
            s.close()
        await _drained(h)


async def test_many_non_reading_clients_over_many_ips() -> None:
    """Lesson 17: 200 non-reading connections over 25 IPs stay far below the memory limit."""
    async with start({"max_connections": 200, "max_per_ip": 8, "conn_burst": 100.0}) as h:
        base = _rss()
        req = b"GET /info HTTP/1.1\r\nHost: x\r\n\r\n" * 200

        def open_all() -> list[socket.socket]:
            socks = []
            for ip in range(2, 27):
                for _ in range(8):
                    s = _client(h.port, f"127.0.0.{ip}")
                    s.sendall(req)
                    socks.append(s)
            return socks

        socks = await asyncio.to_thread(open_all)
        peak = 0
        for _ in range(30):
            await asyncio.sleep(0.1)
            peak = max(peak, _rss() - base)
            assert h.sensor.budget.used <= h.sensor.budget.limit
        assert peak < 0.7 * 256 * 1024 * 1024, peak
        assert h.sensor.total <= 200
        for s in socks:
            s.close()
        await _drained(h)


async def test_flooding_ip_cannot_starve_a_victim_ip() -> None:
    """Lesson 18: a flooding IP and a victim IP; every victim event reaches the publisher."""

    from suckerpot_common import Event

    from docker_sensor.events import EventSink

    class Slow:
        def __init__(self) -> None:
            self.events: list[Event] = []

        async def publish(self, event: Event) -> bool:
            await asyncio.sleep(0.002)
            self.events.append(event)
            return True

        async def close(self) -> None:
            return None

    pub = Slow()
    sink = EventSink(pub, rate=1e6, burst=1e6, global_rate=1e6, global_burst=1e6)
    sink.start()
    from suckerpot_common import EventType

    def emit(ip: str, sid: str, t: EventType, important: bool = False) -> None:
        sink.emit(
            session_id=sid,
            src_ip=ip,
            src_port=1,
            dst_port=2375,
            type_=t,
            data={"n": 1, "pad": "p" * 500},
            important=important,
        )

    victim = 0
    for i in range(20000):
        emit("203.0.113.9", f"f{i % 50}", EventType.http_request)
        emit("203.0.113.9", f"f{i % 50}", EventType.command, important=True)
        if i % 500 == 0:
            for t in (EventType.connect, EventType.login_attempt, EventType.download_attempt):
                emit("198.51.100.5", "v1", t)
                victim += 1
            emit("198.51.100.5", "v1", EventType.command, important=True)
            victim += 1
            emit("198.51.100.5", "v1", EventType.http_request)
            victim += 1
        if i % 100 == 0:
            await asyncio.sleep(0.005)
    emit("198.51.100.5", "v1", EventType.disconnect)
    victim += 1
    await sink.flush(30)
    got = [e for e in pub.events if str(e.src_ip) == "198.51.100.5"]
    assert len(got) == victim, (len(got), victim)
    assert sink.queued_bytes == 0
    await sink.close()


async def test_every_flood_session_closes_or_is_summarised() -> None:
    """Lesson 18: sessions of a flooding IP get their disconnect or are covered by a summary."""
    from suckerpot_common import Event, EventType

    from docker_sensor.events import EventSink

    class Pub:
        def __init__(self) -> None:
            self.events: list[Event] = []

        async def publish(self, event: Event) -> bool:
            await asyncio.sleep(0.001)
            self.events.append(event)
            return True

        async def close(self) -> None:
            return None

    pub = Pub()
    sink = EventSink(pub, queue_size=400, disc_ip_burst=30.0, disc_ip_rate=1.0)
    sink.start()
    sessions = 300
    for n in range(sessions):
        sid = f"s{n}"
        for _ in range(40):
            sink.emit(
                session_id=sid,
                src_ip="203.0.113.9",
                src_port=1,
                dst_port=2375,
                type_=EventType.command,
                data={"input": "x" * 300},
                important=True,
            )
        sink.emit(
            session_id=sid,
            src_ip="203.0.113.9",
            src_port=1,
            dst_port=2375,
            type_=EventType.disconnect,
            data={"requests": 40},
        )
        if n % 20 == 0:
            await asyncio.sleep(0.01)
    sink.flush_overflow()
    await sink.flush(30)
    closed = sum(1 for e in pub.events if e.type == EventType.disconnect)
    summaries = [e for e in pub.events if e.data.get("kind") == "events_suppressed"]
    lost = sum(int(e.data["disconnects_lost"]) for e in summaries)
    assert closed + lost == sessions, (closed, lost, sink.stats())
    assert len(summaries) == 1  # one summary per IP, not one per dropped event
    assert closed >= 30  # the per-IP reserve keeps the first sessions closing
    await sink.close()


async def test_replies_are_bounded_and_budget_returns_to_zero() -> None:
    """Lesson 17: a worst-case state yields a bounded /containers/json and no leaked budget."""
    big = {
        "Image": "alpine",
        "Cmd": ["sh", "-c", "x" * 4000],
        "Env": ["A=" + "y" * 3000] * 20,
        "HostConfig": {"Binds": ["/:/mnt"] * 20},
    }
    async with start({"state_per_ip": 24}) as h:
        for _ in range(24):
            await h.http("POST", "/containers/create", big)
        status, _, body = await h.http("GET", "/containers/json?all=1")
        assert status == 200
        assert len(body) < 96 * 1024, len(body)
        await _drained(h)

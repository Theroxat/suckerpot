"""Connection caps, admission rate limiting and floods."""

from __future__ import annotations

import asyncio
import os
import time

from conftest import HarnessFactory

from rdp_sensor.protocol import build_connection_request


async def test_per_ip_cap(make_harness: HarnessFactory) -> None:
    async with make_harness(max_per_ip=2, first_data_timeout=5.0) as h:
        conns = [await asyncio.open_connection("127.0.0.1", h.port) for _ in range(2)]
        await asyncio.sleep(0.1)
        reader, writer = await asyncio.open_connection("127.0.0.1", h.port)
        writer.write(build_connection_request(protocols=3))
        t0 = time.monotonic()
        async with asyncio.timeout(3):
            assert await reader.read(10) == b""  # refused: no answer, closed after a delay
        assert time.monotonic() - t0 >= 0.2
        writer.close()
        assert h.sensor.rejected == 1
        for _, w in conns:
            w.close()
        await h.wait_disconnects(2)
        assert h.sensor.total == 0 and h.sensor.per_ip == {}


async def test_global_cap_evicts_oldest_idle(make_harness: HarnessFactory) -> None:
    async with make_harness(max_connections=3, max_per_ip=100, first_data_timeout=5.0) as h:
        conns = [await asyncio.open_connection("127.0.0.1", h.port) for _ in range(3)]
        await asyncio.sleep(0.1)
        reader, writer = await asyncio.open_connection("127.0.0.1", h.port)
        writer.write(build_connection_request(protocols=0))
        async with asyncio.timeout(2):
            assert len(await reader.read(64)) == 19  # the newcomer is served
            assert await conns[0][0].read(10) == b""  # the oldest idle one was dropped
        writer.close()
        assert h.sensor.evicted == 1
        for _, w in conns:
            w.close()
        disc = await h.wait_disconnects(4)
        assert sum(d.data["reason"] == "evicted" for d in disc) == 1


async def test_global_cap_refuses_when_nobody_is_idle(make_harness: HarnessFactory) -> None:
    async with make_harness(max_connections=2, max_per_ip=100, handshake_timeout=5.0) as h:
        conns = []
        for _ in range(2):
            r, w = await asyncio.open_connection("127.0.0.1", h.port)
            w.write(b"\x03\x00\x00\x2a")  # busy: half a TPKT
            conns.append((r, w))
        await asyncio.sleep(0.1)
        reader, writer = await asyncio.open_connection("127.0.0.1", h.port)
        async with asyncio.timeout(4):
            assert await reader.read(10) == b""
        writer.close()
        assert h.sensor.rejected == 1 and h.sensor.evicted == 0
        for _, w in conns:
            w.close()
        await h.wait_disconnects(2)


async def test_admission_rate_limit_and_summary(make_harness: HarnessFactory) -> None:
    async with make_harness(sink_kw={"per_ip_rate": 0.001, "per_ip_burst": 3.0}) as h:
        for _ in range(10):
            reader, writer = await asyncio.open_connection("127.0.0.1", h.port)
            writer.write(build_connection_request(cookie=b"Cookie: mstshash=root", protocols=0))
            # Unrecorded connections get exactly the same answer.
            assert len(await reader.read(64)) == 19
            writer.close()
        await asyncio.sleep(0.2)
        assert len(await h.events("connect")) == 3
        assert len(await h.events("login_attempt")) == 3
        assert h.sink.flush_suppressed(60.0) == 1
        summary = [e for e in await h.events("scan") if e.data.get("kind") == "rate_limited"]
        assert summary[0].data["suppressed_connections"] == 7
        assert h.sink.flush_suppressed(60.0) == 0


def test_summary_top_n_and_aggregate() -> None:
    from rdp_sensor import events

    pub = __import__("conftest").FakePublisher()
    sink = events.EventSink(pub)
    for i in range(events.SUMMARY_MAX_IPS + 50):
        for _ in range(1 + (i % 5)):
            sink.note_suppressed(f"198.51.100.{i % 250}" if i < 250 else f"203.0.113.{i}")
    sent = sink.flush_suppressed(60.0)
    assert sent == events.SUMMARY_MAX_IPS + 1
    queued = [sink._queue.get_nowait() for _ in range(sent)]
    per_ip = [e for e in queued if e.data["kind"] == "rate_limited"]
    agg = [e for e in queued if e.data["kind"] == "rate_limited_aggregate"]
    assert len(per_ip) == events.SUMMARY_MAX_IPS and len(agg) == 1
    assert min(e.data["suppressed_connections"] for e in per_ip) >= max(
        1, agg[0].data["suppressed_connections"] // max(1, agg[0].data["source_ips"]) - 4
    )
    total = sum(e.data["suppressed_connections"] for e in queued)
    assert total == sum(1 + (i % 5) for i in range(events.SUMMARY_MAX_IPS + 50))
    assert agg[0].data["source_ips"] == 50


async def test_parallel_flood(make_harness: HarnessFactory) -> None:
    """150 parallel clients mixing valid, malformed and garbage traffic: all served, state freed."""
    # All from one loopback IP, so the per-IP event budgets are made generous here; the
    # per-IP fairness itself is exercised across distinct source IPs in test_fairness.py.
    sink_kw = {
        "global_rate": 1000.0,
        "global_burst": 1000.0,
        "events_rate": 1000.0,
        "events_burst": 1000.0,
        "priority_rate": 1000.0,
        "priority_burst": 1000.0,
        "per_ip_events_rate": 1000.0,
        "per_ip_events_burst": 1000.0,
        "per_ip_priority_rate": 1000.0,
        "per_ip_priority_burst": 1000.0,
    }
    async with make_harness(sink_kw=sink_kw, max_per_ip=200, handshake_timeout=1.0) as h:

        async def client(i: int) -> None:
            reader, writer = await asyncio.open_connection("127.0.0.1", h.port)
            kind = i % 3
            if kind == 0:
                writer.write(
                    build_connection_request(cookie=b"Cookie: mstshash=u%d" % i, protocols=1)
                )
            elif kind == 1:
                writer.write(b"\x03\x00\x00\x2a")
            else:
                writer.write(os.urandom(8192))
            try:
                async with asyncio.timeout(5):
                    while await reader.read(4096):
                        pass
            except (ConnectionError, OSError):
                pass
            writer.close()

        t0 = time.monotonic()
        await asyncio.gather(*(client(i) for i in range(150)))
        await h.wait_disconnects(150, timeout=10)
        assert time.monotonic() - t0 < 8
        assert h.sensor.total == 0
        assert len(await h.events("login_attempt")) == 50
        assert h.sensor.errors == 0
        assert len(h.publisher.events) <= 150 * 3


async def test_global_admission_caps_recorded_sessions(make_harness: HarnessFactory) -> None:
    """With the default global budget (burst 100), a 150-connection burst records ~100.

    Per-IP event budgets are made generous so the quantity measured is the *global admission*
    cap, not the per-IP event fairness (which test_fairness.py covers across many IPs).
    """
    generous = {
        "events_rate": 1000.0,
        "events_burst": 1000.0,
        "priority_rate": 1000.0,
        "priority_burst": 1000.0,
        "per_ip_events_rate": 1000.0,
        "per_ip_events_burst": 1000.0,
        "per_ip_priority_rate": 1000.0,
        "per_ip_priority_burst": 1000.0,
    }
    async with make_harness(sink_kw=generous, max_per_ip=200) as h:

        async def client() -> None:
            reader, writer = await asyncio.open_connection("127.0.0.1", h.port)
            writer.write(build_connection_request(protocols=0))
            await reader.read(64)
            writer.close()

        await asyncio.gather(*(client() for _ in range(150)))
        await asyncio.sleep(0.3)
        recorded = len(await h.events("connect"))
        assert 100 <= recorded < 110
        assert h.sink.sessions_suppressed == 150 - recorded
        h.sink.flush_suppressed(60.0)
        summary = [e for e in await h.events("scan") if e.data.get("kind") == "rate_limited"]
        assert summary[0].data["suppressed_connections"] == 150 - recorded


async def test_per_ip_tls_slot_cap(make_harness: HarnessFactory) -> None:
    """Regression (review MEDIUM): one source cannot hold more than its share of TLS slots."""
    import ssl

    def ctx() -> ssl.SSLContext:
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        return c

    async with make_harness(max_tls_per_ip=2, credssp_timeout=5.0, max_tls_handshakes=32) as h:
        held = []
        for _ in range(2):  # two concurrent TLS handshakes from this IP: both get a slot
            r, w = await asyncio.open_connection("127.0.0.1", h.port)
            w.write(build_connection_request(cookie=b"Cookie: mstshash=a", protocols=0x0B))
            await w.drain()
            await r.readexactly(19)
            await w.start_tls(ctx())  # parks in the CredSSP read, holding its per-IP slot
            held.append((r, w))
        # The third from the same IP is refused a TLS slot right after the confirm.
        r3, w3 = await asyncio.open_connection("127.0.0.1", h.port)
        w3.write(build_connection_request(protocols=0x0B))
        async with asyncio.timeout(3):
            assert len(await reader_all(r3)) == 19  # confirm, then closed before TLS
        w3.close()
        for _, w in held:
            w.close()
        disc = await h.wait_disconnects(3)
        assert "tls_busy" in [d.data["reason"] for d in disc]
        assert h.sensor.tls_limited >= 1


async def reader_all(reader: asyncio.StreamReader, timeout: float = 3.0) -> bytes:
    out = b""
    with __import__("contextlib").suppress(Exception):
        async with asyncio.timeout(timeout):
            while chunk := await reader.read(4096):
                out += chunk
    return out

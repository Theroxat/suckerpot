"""Lessons 16-18: CPU fairness, bounded output memory, event fairness between sources."""

from __future__ import annotations

import asyncio
import socket
import time

from suckerpot_common import EventType

from sip_sensor.sip import MAX_MESSAGE
from tests.conftest import HarnessFactory, digest_header, make_sensor, sip_request, udp_exchange


def expensive_request(i: int) -> bytes:
    """A near-4 KB request with 60 headers and a large digest, the costliest shape we parse."""
    extra = tuple(f"X-Pad-{n}: {'p' * 40}" for n in range(45))
    auth = digest_header("1000", "x", "asterisk", "0" * 8, "INVITE", "sip:a@b")
    return sip_request("INVITE", cseq=i, extra=(*extra, f"Proxy-Authorization: {auth}"))[
        :MAX_MESSAGE
    ]


async def test_two_flooding_ips_cannot_stall_the_loop(make_harness: HarnessFactory) -> None:
    """Floods from two sources (127.0.0.2/3) at full speed: latency stays low, a third source
    is still answered, and the event loop never blocks (watchdog limit is 10 s)."""
    async with make_harness() as h:
        loop = asyncio.get_running_loop()
        stop = False

        async def flood(src: str) -> None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((src, 0))
            sock.setblocking(False)
            pool = [expensive_request(n) for n in range(40)]
            i = 0
            while not stop:
                for _ in range(200):
                    try:
                        sock.sendto(pool[i % 40], ("127.0.0.1", h.port))
                    except BlockingIOError:
                        break
                    i += 1
                await asyncio.sleep(0)
            sock.close()

        tasks = [asyncio.create_task(flood("127.0.0.2")), asyncio.create_task(flood("127.0.0.3"))]
        worst = 0.0
        try:
            end = loop.time() + 3.0
            while loop.time() < end:
                t = loop.time()
                await asyncio.sleep(0.05)
                worst = max(worst, loop.time() - t - 0.05)
        finally:
            stop = True
            await asyncio.gather(*tasks)
        assert worst < 1.0, worst
        s = h.sensor
        assert s.cpu_dropped + s.udp_dropped > 0  # the budgets did bite
        # the victim (127.0.0.1) is still served
        await asyncio.sleep(0.3)
        (reply,) = await udp_exchange(h.port, sip_request("OPTIONS"), wait=1.0)
        assert reply.startswith(b"SIP/2.0 200")


def test_cpu_budget_is_per_source(profile) -> None:  # type: ignore[no-untyped-def]
    _cfg, _pub, _sink, _tracker, sensor = make_sensor(
        profile, allow_private=True, pps_per_ip=1e9, pps_per_ip_burst=1e9, cpu_per_ip_rate=0.001,
        cpu_per_ip_burst=0.002, cpu_global_rate=10.0, cpu_global_burst=10.0,
    )  # fmt: skip
    for i in range(3000):
        sensor.on_datagram(expensive_request(i), ("198.51.100.1", 5060))
    assert sensor.cpu_dropped > 0
    before = sensor.cpu_dropped
    assert sensor.on_datagram(sip_request("OPTIONS"), ("198.51.100.2", 5060)) is not None
    assert sensor.cpu_dropped == before


async def test_non_reading_tcp_clients_keep_output_and_memory_bounded(
    make_harness: HarnessFactory,
) -> None:
    """100 connections over 25 source addresses send requests and never read the answers."""
    async with make_harness(write_timeout=0.5, max_per_ip=4, max_connections=100) as h:
        socks: list[socket.socket] = []
        req = sip_request("OPTIONS", extra=("X-Pad: " + "p" * 3000,)).replace(b"UDP", b"TCP")
        for ip_n in range(25):
            for _ in range(4):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
                s.bind((f"127.0.1.{ip_n + 1}", 0))
                s.setblocking(False)
                await asyncio.get_running_loop().sock_connect(s, ("127.0.0.1", h.tcp_port))
                socks.append(s)
        loop = asyncio.get_running_loop()
        for _ in range(60):
            for s in socks:
                try:
                    await loop.sock_sendall(s, req)
                except OSError:
                    pass
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.2)
        writers = list(h.sensor.tcp_writers)
        pending = [w.transport.get_write_buffer_size() for w in writers]
        assert max(pending, default=0) <= 64 * 1024
        assert sum(pending) <= 100 * 64 * 1024
        await asyncio.sleep(1.5)  # write_timeout aborts the peers that do not read
        assert h.sensor.tcp_total <= 100
        for s in socks:
            s.close()
        await asyncio.sleep(0.5)
        assert h.sensor.tcp_total == 0 and not h.sensor.tcp_per_ip


async def test_victim_events_arrive_during_a_flood(profile) -> None:  # type: ignore[no-untyped-def]
    """One source floods with INVITEs and OPTIONS while a victim does a normal REGISTER and
    INVITE: every victim event (connect, login_attempt, command, disconnect) must be queued."""
    _cfg, pub, sink, tracker, sensor = make_sensor(
        profile, allow_private=True,
        cpu_per_ip_rate=1e3, cpu_per_ip_burst=1e3, cpu_global_rate=1e3, cpu_global_burst=1e3,
        global_events_per_sec=50.0, priority_events_per_sec=50.0, quota_priority=100000,
    )  # fmt: skip
    sink.start()
    flood, victim = "198.51.100.1", "198.51.100.2"
    auth = digest_header("100", "x", "asterisk", "0" * 8, "REGISTER", "sip:pbx.example.net")
    for i in range(20000):
        sensor.on_datagram(sip_request("INVITE", cseq=i), (flood, 5060))
        sensor.on_datagram(sip_request("OPTIONS", cseq=i), (flood, 5060))
        if i == 10000:
            sensor.on_datagram(
                sip_request("REGISTER", "sip:pbx.example.net", extra=(f"Authorization: {auth}",)),
                (victim, 5060),
            )
            sensor.on_datagram(sip_request("INVITE", "sip:0041791234567@pbx"), (victim, 5060))
        if i % 500 == 0:
            await asyncio.sleep(0)
    tracker.close_all("test")
    await sink.flush()
    mine = [e for e in pub.events if str(e.src_ip) == victim]
    kinds = [e.type for e in mine]
    assert EventType.connect in kinds and EventType.login_attempt in kinds
    assert EventType.command in kinds and EventType.disconnect in kinds
    theirs = [e for e in pub.events if str(e.src_ip) == flood]
    assert len(theirs) < 400  # the flooding source is held to its own per-IP budgets
    assert sensor.udp_dropped > 1000
    await sink.close()


async def test_important_events_overtake_queued_scans(profile) -> None:  # type: ignore[no-untyped-def]
    _cfg, pub, sink, _tracker, _sensor = make_sensor(profile)
    for i in range(50):
        sink.emit(session_id="s", src_ip=f"198.51.100.{i + 1}", src_port=1,
                  type_=EventType.scan, data={"n": i}, force=True)  # fmt: skip
    sink.emit(session_id="s2", src_ip="198.51.100.200", src_port=1, type_=EventType.login_attempt,
              data={"u": 1}, priority=True)  # fmt: skip
    sink.start()
    await sink.flush()
    assert pub.events[0].type == EventType.login_attempt
    assert time.monotonic() > 0
    await sink.close()


async def test_sink_per_ip_budget_protects_the_shared_budget(profile) -> None:  # type: ignore[no-untyped-def]
    """A source hammering the sink cannot use up the global budget meant for everyone."""
    _cfg, pub, sink, _tracker, _sensor = make_sensor(profile)
    sink.start()
    for i in range(20000):
        sink.emit(session_id="f", src_ip="198.51.100.1", src_port=1, type_=EventType.login_attempt,
                  data={"i": i}, priority=True)  # fmt: skip
    for n in range(4):
        assert sink.emit(session_id="v", src_ip="198.51.100.2", src_port=1,
                         type_=EventType.login_attempt, data={"n": n}, priority=True)  # fmt: skip
    await sink.flush()
    assert sum(1 for e in pub.events if str(e.src_ip) == "198.51.100.2") == 4
    assert sum(1 for e in pub.events if str(e.src_ip) == "198.51.100.1") < 200
    await sink.close()

from __future__ import annotations

import asyncio
import contextlib
import struct
import time
from pathlib import Path

import smb_client
from conftest import HarnessFactory

from smb_sensor import framing, smb
from smb_sensor.memguard import MemoryGuard


def _fake_cgroup(path: Path, current: int, limit: int) -> Path:
    (path / "memory.current").write_text(f"{current}\n")
    (path / "memory.max").write_text(f"{limit}\n")
    (path / "memory.stat").write_text("inactive_file 0\n")
    return path


async def test_per_ip_connection_cap(make_harness: HarnessFactory) -> None:
    async with make_harness(max_per_ip=3) as h:
        conns = []
        try:
            for _ in range(3):
                conns.append(await smb_client.Conn.open(h.port))
            await asyncio.sleep(0.1)
            assert h.sensor.per_ip.get("127.0.0.1") == 3
            # A fourth connection is refused (slow reject, then closed).
            extra = await smb_client.Conn.open(h.port)
            conns.append(extra)
            await asyncio.sleep(0.1)
            assert h.sensor.rejected >= 1
        finally:
            for c in conns:
                await c.close()


async def test_oversized_pdu_is_scanned_and_closed(make_harness: HarnessFactory) -> None:
    async with make_harness(max_pdu_bytes=4096) as h:
        conn = await smb_client.Conn.open(h.port)
        try:
            # NetBIOS header declaring a length well past the cap.
            await conn.send_raw(bytes([0x00, 0x01, 0x00, 0x00]) + b"\xfeSMB" + b"\x00" * 60)
        finally:
            await conn.close()
        scans = await h.wait_events("scan", 1)
        assert scans[0].data["kind"] == "oversized_pdu"


async def test_netbios_control_message_closes(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        conn = await smb_client.Conn.open(h.port)
        try:
            await conn.send_raw(bytes([0x81, 0x00, 0x00, 0x04]) + b"ABCD")  # session request
        finally:
            await conn.close()
        scans = await h.wait_events("scan", 1)
        assert scans[0].data["kind"] == "netbios_control"


async def test_max_pdus_limit(make_harness: HarnessFactory) -> None:
    async with make_harness(max_pdus=3) as h:
        conn = await smb_client.Conn.open(h.port)
        try:
            for _ in range(3):
                await conn.send(smb_client.negotiate_request([0x0202]))
            # The 4th PDU should not be answered; the connection is closed.
            await conn.send_raw(smb_client.negotiate_request([0x0202]))
            await asyncio.sleep(0.2)
        finally:
            await conn.close()
        disconnects = await h.wait_events("disconnect", 1)
        assert disconnects[0].data["reason"] == "max_pdus"


async def test_memory_guard_refuses_when_over_threshold(make_harness: HarnessFactory) -> None:
    guard = MemoryGuard(fallback_limit=1 << 20)
    guard.refusing = True  # pretend memory pressure
    async with make_harness(guard=guard) as h:
        conn = await smb_client.Conn.open(h.port)
        try:
            await asyncio.sleep(0.1)
            assert h.sensor.rejected >= 1
            assert guard.refused >= 1
        finally:
            await conn.close()


def test_negotiate_request_parse_timing_bounded() -> None:
    # A pathological dialect/context blob must parse in linear, bounded time.
    header = b"\xfeSMB" + b"\x00" * 60
    body = struct.pack("<HHHHI16sQ", 36, 0xFFFF, 1, 0, 0, b"\x00" * 16, 0) + b"\x02\x03" * 40000
    payload = header + body
    start = time.perf_counter()
    for _ in range(50):
        smb.parse_negotiate_request(payload)
    assert time.perf_counter() - start < 1.0


def test_smb1_dialect_parse_timing_bounded() -> None:
    payload = b"\xffSMB" + bytes([smb.SMB1_NEGOTIATE]) + b"\x00" * 27
    payload += b"\x00" + struct.pack("<H", 0xFFFF) + b"\x02A\x00" * 20000
    start = time.perf_counter()
    for _ in range(50):
        smb.parse_smb1_negotiate_dialects(payload)
    assert time.perf_counter() - start < 1.0


async def test_slowloris_header_times_out(make_harness: HarnessFactory) -> None:
    async with make_harness(first_data_timeout=0.3) as h:
        conn = await smb_client.Conn.open(h.port)
        try:
            await conn.send_raw(b"\x00\x00")  # partial NetBIOS header, then nothing
            disconnects = await h.wait_events("disconnect", 1, timeout=3.0)
            assert disconnects[0].data["reason"] in ("no_data", "timeout")
        finally:
            await conn.close()


async def test_framing_build_message_used_on_wire(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        reply = await smb_client.exchange(h.port, smb_client.negotiate_request([0x0202]))
        # The reply we read back was itself NetBIOS-framed (read_pdu consumed the header).
        reframed = framing.build_message(reply)
        assert reframed[0] == framing.SESSION_MESSAGE


async def test_loop_stays_responsive_under_hammering(make_harness: HarnessFactory) -> None:
    """Lesson 16: concurrent connections hammering the most expensive request (3.1.1 negotiate,
    which builds negotiate contexts) must not block the loop; a probe round-trips well under 1 s.
    """
    # A high CPU budget isolates this from the per-IP CPU limiter (all in-process traffic shares
    # 127.0.0.1); the limiter itself is covered by test_cpu_rate_limit_trips.
    async with make_harness(cpu_per_sec_per_ip=1e9, cpu_burst_per_ip=1e9) as h:

        async def hammer(stop: float) -> None:
            conn = await smb_client.Conn.open(h.port)
            try:
                with contextlib.suppress(Exception):
                    while time.monotonic() < stop:
                        await conn.send(smb_client.negotiate_request([0x0311], contexts=True))
            finally:
                await conn.close()

        stop = time.monotonic() + 1.0
        tasks = [asyncio.create_task(hammer(stop)) for _ in range(16)]
        worst = 0.0
        while time.monotonic() < stop:
            probe = await smb_client.Conn.open(h.port)
            try:
                t0 = time.monotonic()
                await probe.send(smb_client.negotiate_request([0x0311], contexts=True))
                worst = max(worst, time.monotonic() - t0)
            finally:
                await probe.close()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        assert worst < 1.0, worst
        assert h.sensor.errors == 0


async def test_memory_guard_samples_on_admission(
    make_harness: HarnessFactory, tmp_path: Path
) -> None:
    """Lesson 17: the guard is sampled on admission, so a cgroup already over the refuse
    threshold refuses new connections without waiting for the periodic guard loop."""
    cgroup = _fake_cgroup(tmp_path, current=900_000, limit=1_000_000)  # 90% > 70% refuse
    guard = MemoryGuard(fallback_limit=1_000_000, cgroup=cgroup)
    async with make_harness(guard=guard) as h:
        conn = await smb_client.Conn.open(h.port)
        try:
            await asyncio.sleep(0.1)
            assert guard.refusing is True
            assert h.sensor.rejected >= 1
        finally:
            await conn.close()


async def test_pending_output_budget_does_not_leak(make_harness: HarnessFactory) -> None:
    """Lesson 17: output charged to the global budget is released once drained; after a burst
    of connections the buffered total returns to zero (no leak)."""
    async with make_harness() as h:
        for _ in range(30):
            await smb_client.exchange(h.port, smb_client.negotiate_request([0x0311]))
        await asyncio.sleep(0.1)
        assert h.sensor.buffered == 0
        assert h.sensor.buffered <= h.cfg.max_buffered


async def test_cpu_rate_limit_trips(make_harness: HarnessFactory) -> None:
    """Lesson 16: expensive responses are charged to a per-IP CPU token bucket; a source that
    exceeds its burst is cut with reason 'cpu_rate_limited'."""
    async with make_harness(cpu_per_sec_per_ip=1.0, cpu_burst_per_ip=3.0, max_pdus=100) as h:
        conn = await smb_client.Conn.open(h.port)
        try:
            with contextlib.suppress(Exception):
                for _ in range(20):
                    await conn.send(smb_client.negotiate_request([0x0311], contexts=True))
        finally:
            await conn.close()
        disconnects = await h.wait_events("disconnect", 1)
        assert disconnects[0].data["reason"] == "cpu_rate_limited"
        assert h.sensor.cpu_limited >= 1

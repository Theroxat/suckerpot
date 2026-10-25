"""Contract lessons 16 and 18 against the real listener.

* CPU fairness (16): many IPs running the full, expensive CredSSP NTLM exchange must not make a
  quiet victim's cheap handshake slow.
* Event fairness (18): flooding IPs must not cost a quiet victim IP any of its events.

Every source is a distinct loopback address (127.0.0.0/8 is routable to the local host).
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import struct
import time
from collections import Counter

import rdp_client
from conftest import HarnessFactory

from rdp_sensor import credssp
from rdp_sensor.protocol import build_connection_request

# Production default event budgets (see __main__.run).
PROD_SINK = {
    "per_ip_rate": 2.0,
    "per_ip_burst": 30.0,
    "global_rate": 50.0,
    "global_burst": 100.0,
    "events_rate": 200.0,
    "events_burst": 400.0,
    "priority_rate": 80.0,
    "priority_burst": 160.0,
    "per_ip_events_rate": 20.0,
    "per_ip_events_burst": 60.0,
    "per_ip_priority_rate": 10.0,
    "per_ip_priority_burst": 30.0,
}


def _ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _negotiate_ts() -> bytes:
    msg = b"NTLMSSP\x00" + struct.pack("<II", 1, 0xE2088297) + b"\0" * 16
    msg += struct.pack("<BBH", 10, 0, 22621) + b"\x00\x00\x00\x0f"
    return credssp.build_nego_token(msg, 6)


async def _full_ntlm(port: int, source: str) -> None:
    """One complete CredSSP NTLM exchange (the sensor's most expensive path)."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port, local_addr=(source, 0))
    try:
        writer.write(build_connection_request(cookie=b"Cookie: mstshash=z", protocols=0x0B))
        await writer.drain()
        await reader.readexactly(19)
        await writer.start_tls(_ctx())
        writer.write(_negotiate_ts())
        await writer.drain()
        await reader.read(4096)  # challenge
        auth = rdp_client.build_authenticate_v2("user", "CORP", "WS", b"\x00" * 8, "x")
        writer.write(credssp.build_nego_token(auth, 6))
        await writer.drain()
        await reader.read(4096)  # logon failure
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def test_cpu_fairness_keeps_victim_handshake_fast(make_harness: HarnessFactory) -> None:
    async with make_harness(sink_kw=PROD_SINK) as h:
        end = time.monotonic() + 2.5
        worst = 0.0

        async def flood(source: str) -> None:
            while time.monotonic() < end:
                with contextlib.suppress(Exception):
                    await _full_ntlm(h.port, source)

        async def victim() -> None:
            nonlocal worst
            await asyncio.sleep(0.3)
            while time.monotonic() < end - 0.3:
                t0 = time.monotonic()
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", h.port, local_addr=("127.0.0.80", 0)
                )
                writer.write(build_connection_request(protocols=0))  # cheap: refused at X.224
                await reader.readexactly(19)
                worst = max(worst, time.monotonic() - t0)
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
                await asyncio.sleep(0.05)

        floods = [flood(f"127.0.0.{10 + k}") for k in range(2) for _ in range(8)]
        await asyncio.gather(victim(), *floods)
        assert worst < 1.0, worst
        assert h.sensor.errors == 0


async def test_flooding_ips_do_not_starve_a_victim(make_harness: HarnessFactory) -> None:
    VICTIM = "127.0.0.99"
    async with make_harness(sink_kw=PROD_SINK) as h:
        end = time.monotonic() + 3.0

        async def one(source: str) -> None:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", h.port, local_addr=(source, 0)
            )
            with contextlib.suppress(Exception):
                writer.write(build_connection_request(cookie=b"Cookie: mstshash=u", protocols=0))
                await reader.readexactly(19)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

        async def flood(source: str) -> None:
            while time.monotonic() < end:
                with contextlib.suppress(Exception):
                    await one(source)

        victim_sessions = 0

        async def victim() -> None:
            nonlocal victim_sessions
            await asyncio.sleep(0.4)  # let the flood saturate the shared budgets first
            while time.monotonic() < end - 0.4:
                await one(VICTIM)
                victim_sessions += 1
                await asyncio.sleep(0.5)

        floods = [flood(f"127.0.1.{k}") for k in range(8)]
        await asyncio.gather(victim(), *floods)
        await asyncio.sleep(0.2)
        await h.sink.flush()
        got = Counter(e.type.value for e in h.publisher.events if str(e.src_ip) == VICTIM)
        assert victim_sessions >= 2
        # The flood really was throttled (otherwise the test proves nothing)...
        assert h.sink.priority_limited > 0 or h.sink.sessions_suppressed > 0
        # ...yet every victim connect / login / disconnect arrived.
        assert got["connect"] == victim_sessions
        assert got["login_attempt"] == victim_sessions
        assert got["disconnect"] == victim_sessions

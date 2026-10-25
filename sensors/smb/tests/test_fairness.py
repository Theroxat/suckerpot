"""Contract lesson 18 end to end: several flooding IPs must not cost a quiet victim IP any
event. Runs against the real listener with the production default budgets; every source is a
distinct loopback address (127.0.0.0/8 is routable to the local host on Linux)."""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections import Counter

import smb_client
from conftest import HarnessFactory

VICTIM = "127.0.0.99"
LOGINS = 8

# Production defaults (see __main__.run: burst = rate x 15 per IP, x 2 globally).
PROD_SINK = {
    "per_ip_rate": 2.0,
    "per_ip_burst": 30.0,
    "global_rate": 50.0,
    "global_burst": 100.0,
    "events_rate": 200.0,
    "events_burst": 400.0,
    "priority_rate": 80.0,
    "priority_burst": 160.0,
}


async def _session(port: int, source: str) -> None:
    conn = await smb_client.Conn.open(port, source=source)
    try:
        await conn.send(smb_client.negotiate_request([0x0311]))
        await conn.send(smb_client.session_setup_request(smb_client.ntlm_negotiate(), message_id=1))
        for i in range(LOGINS):
            auth = smb_client.ntlm_authenticate("CORP", f"user{i}", "WS01")
            await conn.send(smb_client.session_setup_request(auth, message_id=2 + i))
    finally:
        await conn.close()


async def test_flooding_ips_do_not_starve_a_victim(make_harness: HarnessFactory) -> None:
    async with make_harness(sink_kw=PROD_SINK) as h:
        end = time.monotonic() + 3.5

        async def flood(source: str) -> None:
            while time.monotonic() < end:
                try:
                    await _session(h.port, source)
                except (OSError, asyncio.IncompleteReadError, TimeoutError):
                    await asyncio.sleep(0.01)

        victim_sessions = 0

        async def victim() -> None:
            nonlocal victim_sessions
            await asyncio.sleep(0.3)  # let the flood saturate the shared budgets first
            while time.monotonic() < end - 0.5:
                await _session(h.port, VICTIM)
                victim_sessions += 1
                await asyncio.sleep(1.0)

        floods = [flood(f"127.0.0.{10 + k}") for k in range(6) for _ in range(4)]
        await asyncio.gather(victim(), *floods)
        await asyncio.sleep(0.3)
        with contextlib.suppress(TimeoutError):
            await h.sink.flush()
        got = Counter(e.type.value for e in h.publisher.events if str(e.src_ip) == VICTIM)
        assert victim_sessions >= 2
        # The flood really was throttled (otherwise the test proves nothing)...
        assert h.sink.priority_limited > 0 or h.sink.sessions_suppressed > 0
        # ...yet every victim event arrived.
        assert got["connect"] == victim_sessions
        assert got["login_attempt"] == victim_sessions * LOGINS
        assert got["disconnect"] == victim_sessions

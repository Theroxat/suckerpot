"""The network node reads real sessions only: a demo session is never submitted or flagged."""

import json
import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from ingest.network.scheduler import day_start
from ingest.network.source import SqlSource
from ingest.network.store import SqlStore

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

NOW = datetime.now(UTC)
REAL_IP = "198.51.100.7"
DEMO_IP = "203.0.113.9"
MIXED_IP = "192.0.2.44"


async def add_session(engine: AsyncEngine, sid: str, ip: str, *, demo: bool) -> None:
    started = NOW - timedelta(hours=1)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                """
                INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, started_at,
                                      last_event_at, login_attempts)
                VALUES (:sid, 'ssh', CAST(:ip AS inet), 40000, 22, :t, :t, 3)
                """
            ),
            {"sid": sid, "ip": ip, "t": started},
        )
        await conn.execute(
            text(
                """
                INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, dst_port, data)
                VALUES (:t, 'ssh', :sid, 'login_attempt', CAST(:ip AS inet), 40000, 22,
                        CAST(:data AS jsonb))
                """
            ),
            {
                "t": started,
                "sid": sid,
                "ip": ip,
                "data": json.dumps({"demo": True} if demo else {}),
            },
        )


async def test_demo_sessions_are_never_submitted(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    await add_session(engine, "real-1", REAL_IP, demo=False)
    await add_session(engine, "demo-1", DEMO_IP, demo=True)
    await add_session(engine, "mixed-1", MIXED_IP, demo=False)
    await add_session(engine, "mixed-2", MIXED_IP, demo=True)
    day = (NOW - timedelta(hours=1)).date()
    assert day_start(day) <= NOW - timedelta(hours=1)
    facts = await SqlSource(factory).sessions(day)
    by_ip = {f.ip: f.sessions for f in facts}
    assert by_ip == {REAL_IP: 1, MIXED_IP: 1}


async def test_a_demo_address_is_not_flagged_as_mine(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    await add_session(engine, "real-1", REAL_IP, demo=False)
    await add_session(engine, "demo-1", DEMO_IP, demo=True)
    async with engine.begin() as conn:
        await conn.execute(text("TRUNCATE network_targets"))
        for n, ip in enumerate((REAL_IP, DEMO_IP)):
            await conn.execute(
                text(
                    """
                    INSERT INTO network_targets (hub_id, kind, value, state, nodes, first_day,
                                                 last_day, services, activity, tags, families)
                    VALUES (:id, 'ip', :ip, 'confirmed', 2, current_date, current_date,
                            '{}', '{}', '{}', '{}')
                    """
                ),
                {"id": f"t_{n:012x}", "ip": ip},
            )
    await SqlStore(factory).refresh_mine()
    async with engine.connect() as conn:
        rows = (await conn.execute(text("SELECT value, mine FROM network_targets"))).all()
    assert {r.value: r.mine for r in rows} == {REAL_IP: True, DEMO_IP: False}

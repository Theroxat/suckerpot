"""End-to-end against a real TimescaleDB (set POSTGRES_* to enable).

Runs the Alembic migration, writes through the ingest writer and reads through the API.
"""

import os
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from api.main import create_app
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from suckerpot_db import create_engine, create_session_factory, database_url_from_env

from ingest.writer import write_batch

from .helpers import make_event

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

DB_DIR = Path(os.environ.get("DB_DIR", Path(__file__).resolve().parents[2] / "db"))


ROLE_ENV = {
    "POSTGRES_INGEST_USER": "suckerpot_ingest",
    "POSTGRES_INGEST_PASSWORD": "ingest pw/with:odd@chars",
    "POSTGRES_API_USER": "suckerpot_api",
    "POSTGRES_API_PASSWORD": "api-test-password",
}


def _role_url(kind: str) -> str:
    return database_url_from_env(
        {
            **os.environ,
            "POSTGRES_USER": ROLE_ENV[f"POSTGRES_{kind}_USER"],
            "POSTGRES_PASSWORD": ROLE_ENV[f"POSTGRES_{kind}_PASSWORD"],
        }
    )


@pytest.fixture(scope="session")
def migrated() -> None:
    env = {**os.environ, **ROLE_ENV}
    for _ in range(2):  # second run proves idempotence
        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=DB_DIR,
            env=env,
            check=True,
            timeout=120,
        )


@pytest.fixture
async def engine(migrated: None) -> AsyncIterator[AsyncEngine]:
    """Owner connection (test setup only)."""
    eng = create_engine(pool_size=2)
    async with eng.begin() as conn:
        await conn.execute(text("TRUNCATE events, sessions"))
    yield eng
    await eng.dispose()


@pytest.fixture
async def factory(engine: AsyncEngine) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """Writer connections AS the ingest role."""
    eng = create_engine(_role_url("INGEST"), pool_size=2)
    yield create_session_factory(eng)
    await eng.dispose()


@pytest.fixture
async def client(engine: AsyncEngine) -> AsyncIterator[httpx.AsyncClient]:
    """API client connected AS the read-only api role."""
    eng = create_engine(_role_url("API"), pool_size=2)
    app = create_app(create_session_factory(eng))
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            yield c
    await eng.dispose()


async def test_roles_are_least_privilege(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    async with engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole FROM pg_roles "
                    "WHERE rolname IN ('suckerpot_ingest', 'suckerpot_api')"
                )
            )
        ).all()
    assert len(rows) == 2
    assert all(not any(r[1:]) for r in rows)

    # ingest role: inserts work, including into brand-new chunks (events 3 days apart)
    await write_batch(
        factory,
        [
            make_event("connect", sid="r1", offset_s=0),
            make_event("connect", sid="r2", offset_s=3 * 86400),
        ],
    )
    async with engine.connect() as conn:
        chunks = await conn.scalar(
            text(
                "SELECT count(*) FROM timescaledb_information.chunks WHERE hypertable_name='events'"
            )
        )
    assert chunks is not None and chunks >= 2

    # api role: reads fine, writes denied
    api_eng = create_engine(_role_url("API"), pool_size=1)
    try:
        async with api_eng.connect() as conn:
            assert await conn.scalar(text("SELECT count(*) FROM sessions")) == 2
            assert await conn.scalar(text("SHOW statement_timeout")) == "5s"
        for stmt in (
            "INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, started_at, "
            "last_event_at) VALUES ('x','ssh','192.0.2.1',1,2,now(),now())",
            "DELETE FROM events",
            "UPDATE sessions SET commands = 1",
            "DROP TABLE events",
        ):
            async with api_eng.connect() as conn:
                with pytest.raises(DBAPIError):
                    await conn.execute(text(stmt))
    finally:
        await api_eng.dispose()

    # ingest role cannot delete or create roles
    async with factory() as s:
        assert await s.scalar(text("SHOW statement_timeout")) == "30s"
        with pytest.raises(DBAPIError):
            await s.execute(text("DELETE FROM events"))


async def test_schema(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        hyper = await conn.scalar(
            text(
                "SELECT count(*) FROM timescaledb_information.hypertables "
                "WHERE hypertable_name = 'events'"
            )
        )
        interval = await conn.scalar(
            text(
                "SELECT time_interval FROM timescaledb_information.dimensions "
                "WHERE hypertable_name = 'events'"
            )
        )
        idx = {
            r[0]
            for r in await conn.execute(
                text("SELECT indexname FROM pg_indexes WHERE tablename IN ('events','sessions')")
            )
        }
    assert hyper == 1
    assert str(interval) == "1 day, 0:00:00"
    assert {
        "ix_events_session_id_ts",
        "ix_events_src_ip_ts",
        "ix_events_sensor_ts",
        "ix_events_tags",
        "ix_sessions_started_at",
        "ix_sessions_sensor_started_at",
        "ix_sessions_src_ip",
        "ix_sessions_tags",
        "ix_sessions_country",
    } <= idx


async def test_write_and_query(
    factory: async_sessionmaker[AsyncSession], client: httpx.AsyncClient
) -> None:
    batch1 = [
        make_event("connect", offset_s=0),
        make_event("login_attempt", offset_s=1, data={"success": False, "username": "root\x00"}),
        make_event("login_attempt", offset_s=2, data={"success": True}),
    ]
    batch2 = [
        make_event("command", offset_s=3, data={"input": "uname -a"}),
        make_event("download_attempt", offset_s=4, data={"url": "http://198.51.100.9/x.sh"}),
        make_event("disconnect", offset_s=9),
        make_event("http_request", sid="s2", offset_s=100, sensor="web", ip="192.0.2.5"),
    ]
    await write_batch(factory, batch1)
    await write_batch(factory, batch2)
    # out-of-order late event for s1 must not move started_at/ended_at backwards
    await write_batch(factory, [make_event("command", offset_s=-5)])

    r = await client.get("/api/v1/sessions/s1")
    assert r.status_code == 200
    s = r.json()
    assert s["event_count"] == 7
    assert (s["login_attempts"], s["commands"], s["downloads"]) == (2, 2, 1)
    assert s["login_success"] is True
    assert s["src_ip"] == "203.0.113.7" and s["sensor"] == "ssh"
    assert s["started_at"].startswith("2026-10-24T09:59:55")
    assert s["ended_at"].startswith("2026-10-24T10:00:09")
    assert s["country"] is None and s["tags"] == []

    r = await client.get("/api/v1/sessions", params={"sensor": "web"})
    assert [i["session_id"] for i in r.json()["items"]] == ["s2"]
    r = await client.get("/api/v1/sessions", params={"src_ip": "203.0.113.7"})
    assert [i["session_id"] for i in r.json()["items"]] == ["s1"]
    r = await client.get("/api/v1/sessions", params={"since": "2026-10-24T10:01:00Z"})
    assert [i["session_id"] for i in r.json()["items"]] == ["s2"]

    r = await client.get("/api/v1/sessions/s1/events", params={"limit": 3})
    page = r.json()
    assert [e["type"] for e in page["items"]] == ["command", "connect", "login_attempt"]
    assert page["next_cursor"]
    assert page["items"][1]["data"] == {}
    r = await client.get(
        "/api/v1/sessions/s1/events", params={"limit": 50, "cursor": page["next_cursor"]}
    )
    rest = r.json()
    assert len(rest["items"]) == 4 and rest["next_cursor"] is None
    assert rest["items"][0]["data"]["success"] is True
    assert (await client.get("/api/v1/sessions/nope/events")).status_code == 404
    assert (await client.get("/api/v1/sessions/nope")).status_code == 404


async def test_pagination_walks_all_sessions(
    factory: async_sessionmaker[AsyncSession], client: httpx.AsyncClient
) -> None:
    # Identical timestamps force the session_id tie-break.
    events = [make_event("connect", sid=f"sess-{i:03d}", offset_s=i // 10) for i in range(25)]
    await write_batch(factory, events)
    seen: list[str] = []
    cursor: str | None = None
    for _ in range(10):
        params: dict[str, str | int] = {"limit": 7}
        if cursor:
            params["cursor"] = cursor
        body = (await client.get("/api/v1/sessions", params=params)).json()
        seen += [i["session_id"] for i in body["items"]]
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert len(seen) == 25 and len(set(seen)) == 25
    assert seen == sorted(seen, key=lambda s: (int(s[5:]) // 10, s), reverse=True)


async def test_stats_summary(
    factory: async_sessionmaker[AsyncSession], client: httpx.AsyncClient
) -> None:
    from datetime import UTC, datetime

    from suckerpot_common import Event

    now = datetime.now(UTC)

    def ev(sid: str, etype: str, sensor: str, ip: str) -> Event:
        return Event.model_validate(
            {
                "ts": now,
                "sensor": sensor,
                "session_id": sid,
                "src_ip": ip,
                "src_port": 1,
                "dst_port": 2,
                "type": etype,
            }
        )

    await write_batch(
        factory,
        [
            ev("a", "connect", "ssh", "198.51.100.1"),
            ev("a", "command", "ssh", "198.51.100.1"),
            ev("b", "download_attempt", "web", "198.51.100.1"),
            ev("c", "connect", "telnet", "198.51.100.2"),
        ],
    )
    body = (await client.get("/api/v1/stats/summary")).json()
    assert body["events"] == 4 and body["sessions"] == 3 and body["unique_ips"] == 2
    assert body["sessions_with_commands"] == 1 and body["download_attempts"] == 1
    assert body["by_sensor"]["ssh"] == {"events": 2, "sessions": 1}
    assert (await client.get("/healthz")).json() == {"status": "ok", "db": "ok"}

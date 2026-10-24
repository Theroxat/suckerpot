"""Analytics validation and query-building tests that need no database."""

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import httpx
import pytest
from sqlalchemy import Select, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import create_async_engine
from suckerpot_db import create_session_factory
from suckerpot_db.models import SessionRow

from api import analytics_queries as q
from api.cursor import InvalidCursorError, encode_cursor
from api.main import create_app

T0 = datetime(2026, 10, 24, 10, 7, 33, tzinfo=UTC)


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    engine = create_async_engine(
        "postgresql+asyncpg://u:p@127.0.0.1:1/d", connect_args={"timeout": 1}
    )
    app = create_app(create_session_factory(engine), enable_live=False)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            yield c
    await engine.dispose()


@pytest.mark.parametrize(
    "url",
    [
        "/stats/timeseries?bucket=2h",
        "/stats/timeseries?sensor=nope",
        "/stats/timeseries?since=2026-10-24T10:00:00",  # naive
        "/stats/timeseries?since=2026-10-24T10:00:00Z&until=2026-10-24T09:00:00Z",
        "/stats/timeseries?bucket=5m&since=2026-10-20T00:00:00Z&until=2026-10-24T00:00:00Z",
        "/stats/timeseries?bucket=1d&since=2026-08-01T00:00:00Z&until=2026-10-24T00:00:00Z",
        "/stats/top",
        "/stats/top?field=passwd",
        "/stats/top?field=username&limit=0",
        "/stats/top?field=username&limit=101",
        "/stats/top?field=username;drop&limit=5",
        "/stats/heatmap?sensor=x",
        "/stats/heatmap?since=2026-01-01T00:00:00Z&until=2026-10-24T00:00:00Z",
        "/attackers?sort=password",
        "/attackers?order=sideways",
        "/attackers?limit=201",
        "/attackers?country=USA",
        "/attackers?tag=Bad Tag",
        "/attackers?q=1.2.3.4%27--",
        "/attackers?asn=-1",
        "/attackers/not-an-ip",
        "/attackers/1.2.3.4;x",
        "/asns?sort=name",
        "/asns?limit=0",
        "/asns?since=yesterday",
    ],
)
async def test_validation_is_422(client: httpx.AsyncClient, url: str) -> None:
    r = await client.get("/api/v1" + url)
    assert r.status_code == 422, r.text


async def test_bad_attacker_cursor_is_400(client: httpx.AsyncClient) -> None:
    for cursor in ("garbage", encode_cursor(["sessions", "desc", "x", "1.2.3.4"])):
        r = await client.get("/api/v1/attackers", params={"cursor": cursor, "sort": "sessions"})
        assert r.status_code == 400, r.text


def test_window_defaults_and_caps() -> None:
    w = q.resolve_window(None, None, now=T0)
    assert (w.until, w.since) == (T0, T0 - timedelta(hours=24))
    assert q.resolve_window(T0 - timedelta(days=30), T0).until == T0
    with pytest.raises(q.WindowError):
        q.resolve_window(T0 - timedelta(days=30, seconds=1), T0)
    with pytest.raises(q.WindowError):
        q.resolve_window(T0, T0)


def test_window_normalises_offsets_to_utc() -> None:
    tz = timezone(timedelta(hours=2))
    w = q.resolve_window(datetime(2026, 10, 24, 12, 0, tzinfo=tz), T0)
    assert w.since == datetime(2026, 10, 24, 10, 0, tzinfo=UTC)
    assert w.since.utcoffset() == timedelta(0)


def test_bucket_helpers() -> None:
    step = timedelta(hours=1)
    assert q.floor_to_bucket(T0, step) == datetime(2026, 10, 24, 10, tzinfo=UTC)
    assert q.floor_to_bucket(T0, timedelta(days=1)) == datetime(2026, 10, 24, tzinfo=UTC)
    w = q.Window(T0 - timedelta(hours=24), T0)
    assert len(q.bucket_starts(w, step)) == 25
    q.check_point_count(w, "1h")
    with pytest.raises(q.WindowError):
        q.check_point_count(q.Window(T0 - timedelta(days=3), T0), "5m")


def _sql(stmt: Select[Any]) -> str:
    return str(stmt.compile(dialect=postgresql.dialect()))  # type: ignore[no-untyped-call]


def test_top_stmt_binds_values_and_truncates() -> None:
    w = q.Window(T0 - timedelta(hours=1), T0)
    sql = _sql(q.top_stmt("username", w, "ssh", 10))
    assert "left(" in sql and "256" in sql
    assert "ssh" not in sql and "login_attempt" not in sql  # bound, not inlined
    assert "LIMIT" in sql
    # session-based fields read the sessions table
    assert "FROM sessions" in _sql(q.top_stmt("tag", w, None, 5))
    with pytest.raises(ValueError):
        q.top_stmt("bogus", w, None, 5)


def test_url_field_covers_http_and_downloads() -> None:
    w = q.Window(T0 - timedelta(hours=1), T0)
    sql = _sql(q.top_stmt("url", w, None, 5))
    assert "CASE WHEN" in sql
    assert "'path'" not in sql  # JSON keys are bound parameters


def test_attackers_stmt_injection_safe() -> None:
    sql = _sql(
        q.attackers_stmt(
            sort="sessions", order="asc", limit=5, q="1.2.3.%'; DROP TABLE x;--", tag="t"
        )
    )
    assert "DROP" not in sql
    assert "GROUP BY sessions.src_ip" in sql


def test_attacker_cursor_roundtrip() -> None:
    ts = T0
    cur = q.attacker_cursor("last_seen", "desc", ts, "203.0.113.7")
    assert q.parse_attacker_cursor(cur, "last_seen", "desc") == (ts, "203.0.113.7")
    cur = q.attacker_cursor("sessions", "asc", 42, "2001:db8::1")
    assert q.parse_attacker_cursor(cur, "sessions", "asc") == (42, "2001:db8::1")
    for bad in (
        (cur, "events", "asc"),  # sort mismatch
        (cur, "sessions", "desc"),  # order mismatch
    ):
        with pytest.raises(InvalidCursorError):
            q.parse_attacker_cursor(*bad)
    for values in (
        ["sessions", "asc", "x", "1.2.3.4"],
        ["sessions", "asc", -1, "1.2.3.4"],
        ["sessions", "asc", 1, "not-ip"],
        ["last_seen", "asc", "2026-10-24T10:00:00", "1.2.3.4"],  # naive
        ["sessions", "asc", 1],
    ):
        with pytest.raises(InvalidCursorError):
            q.parse_attacker_cursor(encode_cursor(values), values[0], "asc")  # type: ignore[arg-type]


@pytest.mark.parametrize("name", ["username", "password", "command", "url"])
@pytest.mark.parametrize("value", ["", "x" * 257])
async def test_sessions_value_filters_validated(
    client: httpx.AsyncClient, name: str, value: str
) -> None:
    r = await client.get("/api/v1/sessions", params={name: value})
    assert r.status_code == 422


def test_session_has_value_sql_is_bound_exists() -> None:
    sql = _sql(select(SessionRow.session_id).where(q.session_has_value("command", "x'; --")))
    assert "EXISTS" in sql and "events.session_id = sessions.session_id" in sql
    assert "DROP" not in sql and "x'" not in sql

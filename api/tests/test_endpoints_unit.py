"""Endpoint validation tests that need no database."""

from collections.abc import AsyncIterator

import httpx
import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from suckerpot_db import create_session_factory

from api.cursor import encode_cursor
from api.main import create_app


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    # Nothing listens on port 1: any real query fails fast, validation errors never reach it.
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
    "query",
    [
        "limit=0",
        "limit=201",
        "limit=abc",
        "src_ip=not-an-ip",
        "src_ip=1.2.3.4;drop",
        "sensor=nope",
        "since=yesterday",
        "since=2026-10-24T10:00:00",  # naive
    ],
)
async def test_session_list_validation(client: httpx.AsyncClient, query: str) -> None:
    r = await client.get(f"/api/v1/sessions?{query}")
    assert r.status_code == 422


async def test_bad_cursor_is_400(client: httpx.AsyncClient) -> None:
    r = await client.get("/api/v1/sessions?cursor=garbage")
    assert r.status_code == 400
    r = await client.get("/api/v1/sessions/abc/events?cursor=" + encode_cursor(["x", "y"]))
    assert r.status_code == 400


async def test_bad_session_id_is_422(client: httpx.AsyncClient) -> None:
    r = await client.get("/api/v1/sessions/abc/events?limit=500")
    assert r.status_code == 422


async def test_healthz_degraded_when_db_down(client: httpx.AsyncClient) -> None:
    r = await client.get("/healthz")
    assert r.status_code == 503
    assert r.json() == {"status": "degraded", "db": "error"}


async def test_docs_disabled_by_default(client: httpx.AsyncClient) -> None:
    for url in ("/openapi.json", "/docs", "/redoc"):
        assert (await client.get(url)).status_code == 404


@pytest.mark.parametrize(("value", "enabled"), [("true", True), ("1", True), ("false", False)])
async def test_docs_env_switch(monkeypatch: pytest.MonkeyPatch, value: str, enabled: bool) -> None:
    monkeypatch.setenv("API_ENABLE_DOCS", value)
    app = create_app(None)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get("/openapi.json")
    assert (r.status_code == 200) is enabled
    if enabled:
        assert r.json()["info"]["title"] == "API"


@pytest.mark.parametrize("sid", ["a.b", "a%20b", "x" * 65, "a;b"])
async def test_session_id_path_validation(client: httpx.AsyncClient, sid: str) -> None:
    assert (await client.get(f"/api/v1/sessions/{sid}")).status_code == 422
    assert (await client.get(f"/api/v1/sessions/{sid}/events")).status_code == 422


@pytest.mark.parametrize("eid", [-1, 2**63, 2**80])
async def test_event_cursor_id_bounds(client: httpx.AsyncClient, eid: int) -> None:
    cur = encode_cursor(["2026-10-24T10:00:00+00:00", eid])
    assert (await client.get(f"/api/v1/sessions/abc/events?cursor={cur}")).status_code == 400


@pytest.mark.parametrize("ts", ["0001-01-01T00:00:00%2B05:00", "9999-12-31T23:59:59-23:59"])
async def test_extreme_cursor_and_since_are_client_errors(
    client: httpx.AsyncClient, ts: str
) -> None:
    cur = encode_cursor([ts.replace("%2B", "+"), "a"])
    assert (await client.get(f"/api/v1/sessions?cursor={cur}")).status_code == 400
    # since/until: out-of-range instants are rejected before any DB access
    assert (await client.get(f"/api/v1/sessions?since={ts}")).status_code == 422

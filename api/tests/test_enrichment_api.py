"""Session filters (tag, country, asn) and the enrichment settings endpoint."""

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from suckerpot_db import SessionRow, create_engine, create_session_factory

from api.main import create_app

NOW = datetime.now(UTC)


@pytest.fixture
async def unit_client() -> AsyncIterator[httpx.AsyncClient]:
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine("postgresql+asyncpg://u:p@127.0.0.1:1/d")
    app = create_app(create_session_factory(engine), enable_live=False)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c,
    ):
        yield c
    await engine.dispose()


@pytest.mark.parametrize(
    "query",
    ["tag=Bad Tag", "tag=" + "x" * 33, "tag=a;b", "country=NLD", "country=1", "country=",
     "asn=-1", "asn=abc", "asn=4294967296"],
)  # fmt: skip
async def test_filter_validation(unit_client: httpx.AsyncClient, query: str) -> None:
    assert (await unit_client.get(f"/api/v1/sessions?{query}")).status_code == 422


def session_row(sid: str, **kw: Any) -> SessionRow:
    base: dict[str, Any] = dict(
        session_id=sid, sensor="ssh", src_ip="203.0.113.7", src_port=1, dst_port=2,
        started_at=NOW, last_event_at=NOW,
    )  # fmt: skip
    return SessionRow(**{**base, **kw})


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    engine = create_engine(pool_size=2)
    factory = create_session_factory(engine)
    async with engine.begin() as conn:
        await conn.execute(
            text("TRUNCATE events, sessions, ip_reputation, enrichment_quota, enrichment_status")
        )
    async with factory() as s, s.begin():
        s.add(session_row("a", country="NL", asn=64496, tags=["recon", "mirai"], started_at=NOW))
        s.add(session_row("b", country="CH", asn=64497, tags=["recon"],
                          started_at=NOW - timedelta(minutes=1)))  # fmt: skip
        s.add(session_row("c", country="NL", asn=64497, tags=[],
                          started_at=NOW - timedelta(minutes=2)))  # fmt: skip
        s.add(session_row("d", country=None, asn=None, tags=["crypto-miner"],
                          started_at=NOW - timedelta(minutes=3)))  # fmt: skip
    app = create_app(factory, enable_live=False)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c,
    ):
        yield c
    await engine.dispose()


async def ids(client: httpx.AsyncClient, **params: Any) -> list[str]:
    r = await client.get("/api/v1/sessions", params=params)
    assert r.status_code == 200, r.text
    return [i["session_id"] for i in r.json()["items"]]


@pytest.mark.integration
@pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set")
async def test_filters(client: httpx.AsyncClient) -> None:
    assert await ids(client, tag="recon") == ["a", "b"]
    assert await ids(client, tag="mirai") == ["a"]
    assert await ids(client, tag="nope") == []
    assert await ids(client, country="NL") == ["a", "c"]
    assert await ids(client, country="nl") == ["a", "c"]
    assert await ids(client, asn=64497) == ["b", "c"]
    assert await ids(client, tag="recon", country="NL", asn=64496) == ["a"]
    items = (await client.get("/api/v1/sessions", params={"tag": "mirai"})).json()["items"]
    assert items[0]["country"] == "NL" and items[0]["asn"] == 64496 and items[0]["tags"] == [
        "recon", "mirai",
    ]  # fmt: skip


@pytest.mark.integration
@pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set")
async def test_settings_enrichment(client: httpx.AsyncClient) -> None:
    empty = (await client.get("/api/v1/settings/enrichment")).json()
    assert empty["geoip"]["provider"] == "unknown" and empty["geoip"]["available"] is False
    assert empty["abuseipdb"] == {
        "configured": False, "daily_quota": None, "used_today": 0, "disabled": None,
        "paused": False, "last_error": None, "source": None, "last4": None, "updated_at": None,
        "secret_error": None, "pending_apply": False, "test": None, "test_pending": False,
        "test_requested_at": None,
    }  # fmt: skip
    assert empty["nvd"]["source"] is None and empty["github"]["configured"] is False
    assert empty["maxmind"]["source"] is None and empty["key_editing"]["enabled"] is False

    engine = create_engine(pool_size=1)
    updated = (NOW - timedelta(days=3)).isoformat()
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO enrichment_status (name, detail) VALUES "
                "('geoip', CAST(:g AS jsonb)), ('abuseipdb', CAST(:a AS jsonb))"
            ),
            {
                "g": '{"provider": "dbip", "available": true, "refresh_days": 30, "files": '
                '{"city": {"file": "dbip-city-lite.mmdb", "bytes": 123, "updated_at": "'
                + updated
                + '"}}, "last_error": null}',
                "a": '{"configured": true, "daily_quota": 1000, "paused": true, '
                '"last_error": "rate_limited", "disabled": null}',
            },
        )
        await conn.execute(
            text(
                "INSERT INTO enrichment_quota (provider, day, used) VALUES "
                "('abuseipdb', current_date, 17), ('abuseipdb', current_date - 1, 900)"
            )
        )
    await engine.dispose()

    body = (await client.get("/api/v1/settings/enrichment")).json()
    geo = body["geoip"]
    assert geo["provider"] == "dbip" and geo["available"] is True
    assert "db-ip.com" in geo["attribution"] and "CC BY 4.0" in geo["attribution"]
    assert geo["files"]["city"]["age_days"] == pytest.approx(3.0, abs=0.1)
    assert body["abuseipdb"]["used_today"] == 17 and body["abuseipdb"]["paused"] is True
    assert body["abuseipdb"]["last_error"] == "rate_limited"
    assert body["greynoise"]["configured"] is False
    assert body["abuseipdb"]["source"] == "env" and body["abuseipdb"]["last4"] is None
    assert body["reported_at"] is not None

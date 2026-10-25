"""Insights and site settings against a real TimescaleDB with a hand-checked dataset."""

import os
import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from analytics_seed import Seed, api_engine, login, owner_engine
from insights_seed import m7_dataset
from suckerpot_db import create_session_factory

from api.main import create_app

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]


async def make_client(seed: Seed) -> AsyncIterator[httpx.AsyncClient]:
    async with owner_engine() as owner:
        await seed.write(owner)
    engine = api_engine()
    app = create_app(create_session_factory(engine), enable_live=False)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t/api/v1"
        ) as c:
            yield c
    await engine.dispose()


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async for c in make_client(m7_dataset(datetime.now(UTC))):
        yield c


async def test_top_three_ranked_with_evidence(client: httpx.AsyncClient) -> None:
    r = await client.get("/insights")
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"
    body: dict[str, Any] = r.json()
    items = body["items"]
    assert [i["id"] for i in items] == [
        "surge-tag-php2shell",
        "exploit-first-malware-drop",
        "success-spike",
    ]
    surge = items[0]
    assert surge["kind"] == "surge" and surge["severity"] == "severe"
    assert re.fullmatch(
        r"PHP2Shell exploit attempts tripled since [A-Z][a-z]{2} \d{1,2} \(30 vs 10\)\.",
        surge["sentence"],
    )
    assert surge["evidence"] == {
        "metric": "sessions_by_tag",
        "current": 30,
        "previous": 10,
        "ratio": 3.0,
    }
    assert surge["link"].startswith("/attacks?tag=php2shell&since=")
    assert items[1]["severity"] == "severe"
    assert items[1]["link"].startswith("/attacks?tag=malware-drop&")
    assert items[2]["sentence"].startswith("Successful logins up 4x since")
    assert datetime.fromisoformat(body["generated_at"]).tzinfo is not None


async def test_explicit_window_and_new_values(client: httpx.AsyncClient) -> None:
    # The never-seen command is only a candidate (rank below the top 3) but must be computed.
    now = datetime.now(UTC)
    r = await client.get(
        "/insights",
        params={"since": (now - timedelta(days=7)).isoformat(), "until": now.isoformat()},
    )
    assert r.status_code == 200
    assert len(r.json()["items"]) == 3


async def test_quiet_deployment_returns_nothing() -> None:
    now = datetime.now(UTC)
    seed = Seed()
    for i in range(4):
        seed.session(
            f"q{i}", "ssh", "203.0.113.9", now - timedelta(hours=i + 1), [(0.0, "connect", {})]
        )
    async for c in make_client(seed):
        assert (await c.get("/insights")).json()["items"] == []


async def test_empty_database() -> None:
    async for c in make_client(Seed()):
        assert (await c.get("/insights")).json()["items"] == []


async def test_site_settings(client: httpx.AsyncClient) -> None:
    body = (await client.get("/settings/site")).json()
    assert body == {"home": {"lat": 46.8, "lon": 8.2, "label": "Switzerland"}}


async def test_brute_force_insight_from_events() -> None:
    now = datetime.now(UTC)
    seed = Seed()
    for i in range(120):  # one login per connection, as MySQL does
        seed.session(
            f"bf{i}",
            "mysql",
            "192.0.2.9",
            now - timedelta(minutes=i + 1),
            [(0.0, "connect", {}), login("root", f"pw{i}")],
        )
    async for c in make_client(seed):
        items = (await c.get("/insights")).json()["items"]
        [bf] = [i for i in items if i["kind"] == "brute_force"]
        assert bf["id"] == "brute-force-mysql-192.0.2.9"
        assert "120 times on MySQL" in bf["sentence"]

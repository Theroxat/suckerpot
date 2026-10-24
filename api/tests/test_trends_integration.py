"""Trends endpoints against a real TimescaleDB."""

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from analytics_seed import Seed, api_engine, login, owner_engine
from insights_seed import CMD, m7_dataset
from suckerpot_db import create_session_factory

from api.main import create_app

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

NOW = datetime.now(UTC)


def dataset() -> Seed:
    seed = m7_dataset(NOW)
    # Lookback boundaries: seen 60 d ago and again now -> not new; seen 100 d ago -> still new.
    for name, age in (("old60", 60), ("old100", 100)):
        seed.session(
            f"o-{name}",
            "ssh",
            "192.0.2.77",
            NOW - timedelta(days=age),
            [(0.0, "connect", {}), login(name, "x"), (2.0, "command", {"input": name})],
            geo=(None, None, 64500, "Example Net"),
        )
        seed.session(
            f"n-{name}",
            "ssh",
            "192.0.2.78",
            NOW - timedelta(hours=3),
            [(0.0, "connect", {}), login(name, "y"), (2.0, "command", {"input": name})],
            geo=(None, None, 64500, "Example Net"),
        )
    # ten distinct tags with counts 10, 9, ..., 1 inside a dedicated day
    day = NOW - timedelta(days=20)
    for t in range(1, 11):
        for k in range(11 - t):
            seed.session(
                f"t{t}-{k}",
                "web",
                "192.0.2.80",
                day + timedelta(seconds=k),
                [(0.0, "connect", {})],
                tags=[f"tag{t:02d}"],
            )
    return seed


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with owner_engine() as owner:
        await dataset().write(owner)
    engine = api_engine()
    app = create_app(create_session_factory(engine), enable_live=False)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t/api/v1"
        ) as c:
            yield c
    await engine.dispose()


async def test_new_commands_respects_90d_lookback(client: httpx.AsyncClient) -> None:
    r = await client.get("/trends/new", params={"field": "command", "days": 7})
    assert r.status_code == 200
    body = r.json()
    assert body["field"] == "command"
    got = {i["value"]: i["count"] for i in body["items"]}
    assert got == {CMD: 12, "old100": 1}
    assert "old60" not in got
    assert body["items"][0]["count"] >= body["items"][1]["count"]
    assert body["items"][0]["first_seen"].endswith(("Z", "+00:00"))


async def test_new_usernames_urls_and_asn(client: httpx.AsyncClient) -> None:
    users = (await client.get("/trends/new", params={"field": "username"})).json()["items"]
    assert {i["value"] for i in users} == {"old100"}
    urls = (await client.get("/trends/new", params={"field": "url"})).json()["items"]
    assert {i["value"]: i["count"] for i in urls} == {
        "/index.php": 30,
        "http://192.0.2.50/m0.sh": 4,
        "http://192.0.2.50/m1.sh": 4,
        "http://192.0.2.50/m2.sh": 4,
    }
    paths = (await client.get("/trends/new", params={"field": "url", "limit": 1})).json()["items"]
    assert len(paths) == 1
    # With a 30 day window the 60 day old AS64500 session is in the lookback, so it is not new,
    # while 14061 and 15169 (first seen 9-10 days ago) are.
    month = (await client.get("/trends/new", params={"field": "asn", "days": 30})).json()["items"]
    assert {i["value"] for i in month} == {"14061", "15169"}
    # 14061 and 15169 also appear in the previous window, so they are not new in the last 7 days
    last7 = (await client.get("/trends/new", params={"field": "asn", "days": 7})).json()["items"]
    assert last7 == []  # 64500 was last seen 60 days ago, inside the 90 day lookback


async def test_new_user_agents_and_passwords(client: httpx.AsyncClient) -> None:
    ua = (await client.get("/trends/new", params={"field": "user_agent"})).json()["items"]
    assert {i["value"] for i in ua} == {"bot/1"}
    pw = (await client.get("/trends/new", params={"field": "password"})).json()["items"]
    assert {i["value"]: i["count"] for i in pw} == {"admin": 12, "y": 2}


async def test_tags_over_time_top8_and_other(client: httpx.AsyncClient) -> None:
    since = (NOW - timedelta(days=21)).isoformat()
    until = (NOW - timedelta(days=19)).isoformat()
    body = (
        await client.get("/trends/tags", params={"bucket": "1d", "since": since, "until": until})
    ).json()
    assert body["series"] == [f"tag{t:02d}" for t in range(1, 9)] + ["other"]
    assert len(body["points"]) in (2, 3)
    totals: dict[str, int] = {}
    for p in body["points"]:
        assert set(p["tags"]) == set(body["series"])
        for k, v in p["tags"].items():
            totals[k] = totals.get(k, 0) + v
    assert totals["tag01"] == 10 and totals["tag08"] == 3 and totals["other"] == 3


async def test_tags_default_window_zero_filled(client: httpx.AsyncClient) -> None:
    body = (await client.get("/trends/tags")).json()
    assert body["bucket"] == "1d"
    assert 7 <= len(body["points"]) <= 8
    assert body["series"][:2] == ["php2shell", "malware-drop"]
    assert sum(p["tags"]["php2shell"] for p in body["points"]) == 30
    assert sum(p["tags"]["malware-drop"] for p in body["points"]) == 12
    hourly = (
        await client.get(
            "/trends/tags",
            params={
                "bucket": "1h",
                "since": (NOW - timedelta(days=1, hours=2)).isoformat(),
                "until": NOW.isoformat(),
            },
        )
    ).json()
    assert sum(p["tags"].get("php2shell", 0) for p in hourly["points"]) > 0

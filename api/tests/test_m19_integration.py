"""Search, Today and the research-scanner filter against a real TimescaleDB (M19)."""

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from analytics_seed import Seed, api_engine, login, owner_engine
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine
from suckerpot_db import create_session_factory

from api.main import create_app

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

NOW = datetime.now(UTC)
NL = ("NL", "Amsterdam", 14061, "DigitalOcean, LLC")
HASH = "d41d8cd98f00b204e9800998ecf8427e"


def dataset() -> Seed:
    seed = Seed()
    seed.session(
        "m1",
        "ssh",
        "203.0.113.7",
        NOW - timedelta(hours=2),
        [(0.0, "connect", {}), login("root", "admin", True), (3.0, "command", {"input": "uname"})],
        tags=["recon"],
        geo=NL,
        success=True,
    )
    seed.session(
        "m2",
        "telnet",
        "198.51.100.9",
        NOW - timedelta(hours=3),
        [(0.0, "connect", {}), (2.0, "download_attempt", {"url": "http://192.0.2.50/x.sh"})],
        tags=["malware-drop"],
        geo=NL,
    )
    seed.session(
        "b1",
        "web",
        "192.0.2.200",
        NOW - timedelta(hours=1),
        [(0.0, "connect", {}), (1.0, "http_request", {"path": "/", "user_agent": "CensysInspect"})],
        geo=("US", "Ann Arbor", 398324, "Censys, Inc."),
    )
    for row in [*seed.sessions, *seed.events]:
        row["benign"] = row.get("session_id") == "b1"
    for row in seed.sessions:
        row["scanner_name"] = "Censys" if row["benign"] else None
    return seed


async def extra_rows(owner: AsyncEngine) -> None:
    async with owner.begin() as conn:
        await conn.execute(text("TRUNCATE indicators, campaigns, cve, inventory_services CASCADE"))
        await conn.execute(
            text(
                "INSERT INTO indicators (type, value, role, host, first_seen, last_seen, sightings,"
                " sensors) VALUES ('domain', 'files.badhost.example', 'download_host',"
                " 'files.badhost.example', :t, :t, 5, '{telnet}'),"
                " ('hash', :h, 'hash', NULL, :t, :t, 2, '{ssh}')"
            ),
            {"t": NOW - timedelta(hours=2), "h": HASH},
        )
        await conn.execute(
            text(
                "INSERT INTO campaigns (name, status, first_seen, last_seen, sessions, sources)"
                " VALUES ('Mirai loader over Telnet #41', 'active', :t, :n, 12, 5),"
                " ('Mirai old merged', 'merged', :t, :n, 3, 2)"
            ),
            {"t": NOW - timedelta(hours=3), "n": NOW - timedelta(minutes=5)},
        )
        await conn.execute(
            text("INSERT INTO cve (cve_id, title) VALUES ('CVE-2026-109618', 'PHP2Shell RCE')")
        )
        await conn.execute(
            text(
                "INSERT INTO inventory_services (name, service, product, version, exposure,"
                " created_by) VALUES ('Public web server', 'web', 'Apache', '2.4.58', 'internet',"
                " 'tester')"
            )
        )


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with owner_engine() as owner:
        # Sessions reference campaigns: clear those first (TRUNCATE ... CASCADE empties sessions).
        await extra_rows(owner)
        await dataset().write(owner)
    engine = api_engine()
    app = create_app(create_session_factory(engine), enable_live=False)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t/api/v1"
        ) as c:
            yield c
    await engine.dispose()


async def get(client: httpx.AsyncClient, path: str, **params: Any) -> Any:
    r = await client.get(path, params=params)
    assert r.status_code == 200, r.text
    return r.json()


def ids(page: dict[str, Any]) -> set[str]:
    return {s["session_id"] for s in page["items"]}


# --------------------------------------------------------------------------- include_benign


async def test_sessions_hide_research_scanners_unless_asked(client: httpx.AsyncClient) -> None:
    assert ids(await get(client, "/sessions")) == {"m1", "m2"}
    shown = await get(client, "/sessions", include_benign="true")
    assert ids(shown) == {"m1", "m2", "b1"}
    b1 = next(s for s in shown["items"] if s["session_id"] == "b1")
    assert (b1["benign"], b1["scanner_name"]) == (True, "Censys")
    # Asking for one address by name is on purpose: it is shown whatever the switch says.
    assert ids(await get(client, "/sessions", src_ip="192.0.2.200")) == {"b1"}
    assert (await client.get("/sessions/b1")).json()["benign"] is True


async def test_charts_and_lists_follow_the_switch(client: httpx.AsyncClient) -> None:
    assert (await get(client, "/stats/summary"))["sessions"] == 2
    assert (await get(client, "/stats/summary", include_benign="true"))["sessions"] == 3
    hidden_ips = {a["ip"] for a in (await get(client, "/attackers"))["items"]}
    assert hidden_ips == {"203.0.113.7", "198.51.100.9"}
    all_ips = {a["ip"] for a in (await get(client, "/attackers", include_benign="true"))["items"]}
    assert "192.0.2.200" in all_ips
    top = await get(client, "/stats/top", field="src_ip")
    assert {i["value"] for i in top["items"]} == hidden_ips
    since = (NOW - timedelta(hours=6)).isoformat()
    for flag, expected in (("false", 2), ("true", 3)):
        series = await get(
            client, "/stats/timeseries", bucket="1h", since=since, include_benign=flag
        )
        assert sum(sum(p["sessions"].values()) for p in series["points"]) == expected
    assert [a["asn"] for a in (await get(client, "/asns"))["items"]] == [14061]
    assert {a["asn"] for a in (await get(client, "/asns", include_benign="true"))["items"]} == {
        14061,
        398324,
    }
    recent = await get(client, "/events/recent")
    assert {e["session_id"] for e in recent["items"]} == {"m1", "m2"}
    recent = await get(client, "/events/recent", include_benign="true")
    assert {e["session_id"] for e in recent["items"] if e["benign"]} == {"b1"}


async def test_the_hidden_count(client: httpx.AsyncClient) -> None:
    assert await get(client, "/stats/benign") == {"window_hours": 24, "sessions": 1, "sources": 1}


# --------------------------------------------------------------------------- search


def group(result: dict[str, Any], kind: str) -> dict[str, Any]:
    (found,) = [g for g in result["groups"] if g["kind"] == kind]
    return dict(found)


async def test_search_finds_each_kind(client: httpx.AsyncClient) -> None:
    ip = group(await get(client, "/search", q="203.0.113.7"), "ip")
    assert [(h["value"], h["count"]) for h in ip["hits"]] == [("203.0.113.7", 1)]
    prefix = group(await get(client, "/search", q="203.0.113."), "ip")
    assert [h["value"] for h in prefix["hits"]] == ["203.0.113.7"]
    # A research scanner is still found by address, and says what it is.
    scanner = group(await get(client, "/search", q="192.0.2.200"), "ip")
    assert scanner["hits"][0]["benign"] is True

    hit = group(await get(client, "/search", q=HASH[:10]), "hash")["hits"][0]
    assert hit["label"] == HASH and hit["kind"] == "hash"
    dom = group(await get(client, "/search", q="files.bad"), "domain")["hits"][0]
    assert dom["label"] == "files[.]badhost[.]example"  # always defanged
    pasted = group(await get(client, "/search", q="files[.]badhost"), "domain")
    assert pasted["hits"]
    cve = group(await get(client, "/search", q="cve-2026-109618"), "cve")["hits"][0]
    assert (cve["value"], cve["detail"]) == ("CVE-2026-109618", "PHP2Shell RCE")
    camp = group(await get(client, "/search", q="Mirai"), "campaign")
    assert [h["label"] for h in camp["hits"]] == [
        "Mirai loader over Telnet #41"
    ]  # not the merged one


async def test_search_limits_and_hostile_input(client: httpx.AsyncClient) -> None:
    assert (await get(client, "/search", q="x"))["groups"] == []
    assert (await get(client, "/search", q="%"))["groups"] == []
    assert (await get(client, "/search", q="_____"))["groups"] == []
    assert (await get(client, "/search", q="'; DROP TABLE sessions;--"))["groups"] == []
    assert (await client.get("/search", params={"q": "a" * 600})).status_code == 422
    assert (await client.get("/search")).status_code == 422
    assert (await client.get("/search", params={"q": "a" * 500})).status_code == 200
    assert await get(client, "/stats/benign")  # the table is still there


async def test_search_returns_at_most_five_hits_per_group(client: httpx.AsyncClient) -> None:
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO campaigns (name, status, first_seen, last_seen, sessions, sources)"
                " SELECT 'Mirai bulk #' || g, 'active', now(), now(), 1, 1"
                " FROM generate_series(1, 9) g"
            )
        )
    camp = group(await get(client, "/search", q="mirai bulk"), "campaign")
    assert len(camp["hits"]) == 5 and camp["more"] is True


# --------------------------------------------------------------------------- today


async def test_today_cards(client: httpx.AsyncClient) -> None:
    body = await get(client, "/today")
    cards = {c["id"]: c for c in body["cards"]}
    assert list(cards) == ["happened", "campaigns", "act", "new_week", "exposure"]
    assert body["hidden_benign"] == 1 and body["window_hours"] == 24

    happened = cards["happened"]
    assert happened["sentence"].startswith("2 attacks came from 2 addresses")
    assert {i["kind"] for i in happened["items"]} <= {"sensor", "country", "tag"}
    assert len(happened["items"]) <= 3

    assert cards["campaigns"]["items"][0]["to"].startswith("/campaigns/")
    assert cards["campaigns"]["sentence"].startswith("1 new campaign formed")

    act = cards["act"]
    assert act["items"][0]["label"] == "files[.]badhost[.]example"
    assert act["action"]["to"] == "/defend/blocklists"

    assert cards["new_week"]["items"]
    # The only web traffic is the hidden scanner, so the web server was not "targeted" ...
    assert cards["exposure"]["empty"] is True
    assert cards["exposure"]["sentence"].startswith("None of the 1 service")
    for card in cards.values():
        assert len(card["items"]) <= 3 and card["action"]["to"].startswith("/")


async def test_today_with_scanners_included(client: httpx.AsyncClient) -> None:
    body = await get(client, "/today", include_benign="true")
    cards = {c["id"]: c for c in body["cards"]}
    assert body["hidden_benign"] == 0
    assert cards["happened"]["sentence"].startswith("3 attacks came from 3 addresses")
    assert cards["exposure"]["items"][0]["to"] == "/attacks?sensor=web"


async def test_today_without_an_inventory_has_no_exposure_card(client: httpx.AsyncClient) -> None:
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(text("TRUNCATE inventory_services"))
    body = await get(client, "/today")
    assert [c["id"] for c in body["cards"]] == ["happened", "campaigns", "act", "new_week"]

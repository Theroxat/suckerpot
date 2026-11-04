"""The community lists API and the local mirror (design M30 section 10.5).

The first half needs no database (state rules, file names, rendering, roles, routing). The second
half (marked ``integration``) runs the routes against a real TimescaleDB as the API role.
Documentation addresses and example.org names only.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from datetime import UTC, date, datetime, timedelta
from types import SimpleNamespace
from typing import Any, get_args

import httpx
import pytest
from analytics_seed import api_engine, owner_engine
from argon2 import PasswordHasher
from fastapi import FastAPI
from sqlalchemy import text
from starlette.testclient import TestClient
from suckerpot_db import create_session_factory
from suckerpot_netproto import defaults

from api import feed_tokens, network_feed
from api.auth import AuthSettings, Principal, SessionInfo
from api.defend import TokenKind
from api.deps import get_session
from api.main import create_app

PASSWORD = "correct horse battery staple"
HASH = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(PASSWORD)
NONCE = "nonce-for-tests"
BASE = "https://feeds.example.org/v1"
NOW = datetime.now(UTC).replace(microsecond=0)
TODAY = NOW.date()


# -- pure rules --------------------------------------------------------------------------------


def state_row(**kw: Any) -> Any:
    base: dict[str, Any] = {
        "serial": 4812, "generated_at": NOW, "valid_until": NOW + timedelta(days=2),
        "last_ok_at": NOW, "error_code": None,
    }  # fmt: skip
    return SimpleNamespace(**{**base, **kw})


def test_the_feed_state_follows_the_flag_the_data_and_the_clock() -> None:
    d = network_feed.derive_state
    assert d(False, state_row(), NOW).state == "disabled"
    assert d(True, None, NOW).state == "never"
    assert d(True, state_row(serial=None), NOW).state == "never"
    assert d(True, state_row(serial=None, error_code="egress_closed"), NOW).state == "error"
    # After a disable, only the last serial is kept (rollback protection): no lists yet.
    wiped = state_row(generated_at=None, valid_until=None, last_ok_at=None)
    assert d(True, wiped, NOW).state == "never"
    assert d(True, state_row(), NOW).state == "ok"
    ok = d(True, state_row(error_code="http_503"), NOW)
    assert (ok.state, ok.error_code) == ("error", "http_503")
    old = d(True, state_row(valid_until=NOW - timedelta(hours=1), error_code="feed_expired"), NOW)
    assert (old.state, old.error_code) == ("stale", "feed_expired")  # N15 beats the error
    assert d(True, state_row(), NOW).error_code is None


def test_the_public_files_come_from_the_fixed_names() -> None:
    out = network_feed.files_for("outbound", BASE)
    names = {f["name"] for f in out}
    assert {
        "outbound.txt",
        "outbound-high.nft",
        "outbound.stix.json",
        "outbound-high.stix.json",
    } <= names
    assert {f["tier"] for f in out if "-high" in f["name"]} == {"high"}
    assert {f["tier"] for f in out if "-high" not in f["name"]} == {"standard"}
    assert all(f["url"] == f"{BASE}/{f['name']}" for f in out)
    inbound = network_feed.files_for("inbound", BASE)
    assert not any("stix" in f["name"] for f in inbound) and len(inbound) == 16
    domains = network_feed.files_for("outbound-domains", BASE)
    assert [f["name"] for f in domains] == [
        "outbound-domains.txt", "outbound-domains.csv", "outbound-domains.json"
    ]  # fmt: skip
    assert network_feed.files_for("inbound", None) == []


def test_only_an_https_address_is_a_public_base(monkeypatch: pytest.MonkeyPatch) -> None:
    placeholders = defaults.from_text(
        "NETWORK_DEFAULTS_VERSION=1\nNETWORK_HUB_URL=<A>\nNETWORK_HUB_KEY=<B>\n"
        "NETWORK_FEED_URL=<C>\nNETWORK_FEED_KEY=<D>\n"
    )
    monkeypatch.setattr(defaults, "load", lambda: placeholders)
    for value, expected in (
        (BASE + "/", BASE), ("", None), ("http://feeds.example.org/v1", None),
        ("https://feeds.example.org/v 1", None), ("https://x.example.org/" + "a" * 300, None),
    ):  # fmt: skip
        monkeypatch.setenv("NETWORK_FEED_URL", value)
        assert network_feed.public_base_url() == expected


def test_mirror_names_are_a_closed_set() -> None:
    p = network_feed.parse_mirror_name
    assert p("outbound.txt") == ("outbound", None, "ip", "txt")
    assert p("outbound-high.csv") == ("outbound", "high", "ip", "csv")
    assert p("inbound-high.txt") == ("inbound", "high", "ip", "txt")
    assert p("outbound-domains.txt") == ("outbound-domains", None, "domain", "txt")
    for bad in (
        "outbound.json", "outbound.nft", "outbound-domains-high.txt", "../outbound.txt",
        "outbound", "OUTBOUND.txt", ".txt", "outbound.txt.txt", "",
    ):  # fmt: skip
        assert p(bad) is None, bad


def test_the_token_kinds_accept_network() -> None:
    assert set(feed_tokens.TOKEN_KINDS) == set(get_args(TokenKind))
    assert "network" in feed_tokens.TOKEN_KINDS


def entry(value: str, **kw: Any) -> Any:
    base: dict[str, Any] = {
        "value": value, "family": 4, "tier": "standard", "categories": ["c2"], "tags": [],
        "families": ["mirai"], "ports": [23], "first_seen": date(2026, 10, 28),
        "last_seen": date(2026, 10, 30), "expires": date(2026, 11, 29),
    }  # fmt: skip
    return SimpleNamespace(**{**base, **kw})


def test_the_mirror_renders_lines_and_a_defused_csv() -> None:
    rows = [entry("198.51.100.9"), entry("203.0.113.50", categories=["=cmd|' /C calc'!A0"])]
    body, media = network_feed.render_mirror("txt", rows)
    assert body == "198.51.100.9\n203.0.113.50\n" and media.startswith("text/plain")
    body, media = network_feed.render_mirror("csv", rows)
    lines = body.split("\r\n")
    assert (
        lines[0] == "value,family,tier,categories,tags,families,ports,first_seen,last_seen,expires"
    )
    assert lines[1].startswith("198.51.100.9,4,standard,c2,,mirai,23,2026-10-28,")
    assert "'=cmd" in lines[2] and ",=cmd" not in lines[2]
    assert media.startswith("text/csv") and body.endswith("\r\n")
    assert network_feed.render_mirror("txt", []) == ("", "text/plain; charset=utf-8")


def test_the_mirror_orders_addresses_numerically() -> None:
    keys = sorted(
        ["203.0.113.5", "198.51.100.20", "2001:db8::1", "198.51.100.3"], key=network_feed._sort_key
    )
    assert keys == ["198.51.100.3", "198.51.100.20", "203.0.113.5", "2001:db8::1"]


# -- routes without a database -----------------------------------------------------------------


@asynccontextmanager
async def no_database() -> AsyncIterator[None]:
    yield


class NoDb:
    async def execute(self, *_: Any, **__: Any) -> Any:
        raise AssertionError("this request must not reach the database")


@pytest.fixture
def rig(monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    monkeypatch.setenv("NETWORK_FEED_ENABLED", "true")
    monkeypatch.setenv("NETWORK_FEED_URL", BASE)
    app: FastAPI = create_app(
        no_database,  # type: ignore[arg-type]
        enable_live=False,
        auth_settings=AuthSettings(password_hash=HASH, secret=b"k" * 40),
    )

    async def fake_session() -> AsyncIterator[NoDb]:
        yield NoDb()

    app.dependency_overrides[get_session] = fake_session

    async def state(*_: Any, **__: Any) -> network_feed.FeedInfo:
        return network_feed.derive_state(True, state_row(), NOW)

    async def member(*_: Any, **__: Any) -> bool:
        return True

    async def counts(*_: Any, **__: Any) -> dict[str, tuple[int, int, int]]:
        return {"outbound": (812, 120, 41), "inbound": (14230, 900, 7)}

    async def helped(*_: Any, **__: Any) -> dict[str, int]:
        return {"outbound": 3}

    monkeypatch.setattr(network_feed, "load_state", state)
    monkeypatch.setattr(network_feed, "is_member", member)
    monkeypatch.setattr(network_feed, "_counts", counts)
    monkeypatch.setattr(network_feed, "_helped_counts", helped)

    def client(role: str | None = "viewer") -> TestClient:
        async def resolve(*_: object) -> Principal | None:
            if role is None:
                return None
            info = SessionInfo("u7", 0, 0, 2**40, NONCE)
            return Principal(
                app.state.auth.settings.username, "Owner", role, role == "admin", None, False, info
            )

        monkeypatch.setattr(app.state.auth, "resolve", resolve)
        return TestClient(app, base_url="https://testserver", raise_server_exceptions=False)

    yield SimpleNamespace(client=client, app=app)


STATUS_KEYS = {
    "enabled_env", "configured", "state", "error_code", "serial", "generated_at", "valid_until",
    "last_ok_at", "signature", "member", "public_base_url", "lists", "local_mirror",
}  # fmt: skip


def test_the_status_is_open_to_a_viewer_and_has_the_documented_shape(rig: Any) -> None:
    r = rig.client("viewer").get("/api/v1/network/feed/status")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    body = r.json()
    assert set(body) == STATUS_KEYS
    assert body["state"] == "ok" and body["signature"] == "verified" and body["member"] is True
    assert body["public_base_url"] == BASE and body["configured"] is True
    assert body["local_mirror"] == {"feeds_enabled": False}
    assert [lst["id"] for lst in body["lists"]] == ["inbound", "outbound", "outbound-domains"]
    outbound = body["lists"][1]
    assert set(outbound) == {"id", "direction", "entries", "high", "seen_here", "helped", "files"}
    assert (outbound["entries"], outbound["high"], outbound["seen_here"]) == (812, 120, 41)
    assert outbound["helped"] == 3 and body["lists"][0]["helped"] == 0
    assert set(outbound["files"][0]) == {"name", "format", "tier", "url"}
    assert body["lists"][2]["entries"] == 0 and body["lists"][2]["direction"] == "outbound"


def test_a_signed_out_caller_gets_nothing(rig: Any) -> None:
    c = rig.client(None)
    assert c.get("/api/v1/network/feed/status").status_code == 401
    assert c.get("/api/v1/network/feed/entries").status_code == 401


def test_the_feed_routes_cannot_write(rig: Any) -> None:
    c = rig.client("viewer")
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        assert c.request(method, "/api/v1/network/feed/status").status_code in (403, 405)


def test_entries_refuse_unknown_filters_and_bad_cursors(rig: Any) -> None:
    c = rig.client("viewer")
    url = "/api/v1/network/feed/entries"
    assert c.get(url, params={"list": "everything"}).status_code == 422
    assert c.get(url, params={"tier": "gold"}).status_code == 422
    assert c.get(url, params={"limit": 101}).status_code == 422
    assert c.get(url, params={"limit": 0}).status_code == 422
    assert c.get(url, params={"q": "x" * 65}).status_code == 422
    assert c.get(url, params={"cursor": "not-a-cursor"}).status_code == 400


def test_the_mirror_is_not_served_unless_feeds_are_on(
    rig: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FEEDS_ENABLED", raising=False)
    app = create_app(no_database, enable_live=False)  # type: ignore[arg-type]
    c = TestClient(app, base_url="https://testserver")
    assert c.get("/feeds/network/outbound.txt").status_code == 404
    assert c.get(f"/feeds/{'a' * 43}/network/outbound.txt").status_code == 404


def test_a_wrong_token_on_the_mirror_is_the_same_plain_404(
    rig: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FEEDS_ENABLED", "true")
    app = create_app(no_database, enable_live=False)  # type: ignore[arg-type]

    async def fake_session() -> AsyncIterator[NoDb]:
        yield NoDb()

    app.dependency_overrides[get_session] = fake_session
    c = TestClient(app, base_url="https://testserver")
    for r in (
        c.get("/feeds/network/outbound.txt"),
        c.get("/feeds/network/outbound.txt", headers={"Authorization": "Bearer " + "B" * 43}),
        c.get(f"/feeds/{'B' * 43}/network/outbound.txt"),
        c.get("/feeds/" + "z" * 3000 + "/network/outbound.txt"),
        c.get("/feeds/network/" + "z" * 3000),
    ):
        assert r.status_code == 404 and r.json() == {"detail": "Not Found"}


# -- against a real database -------------------------------------------------------------------

needs_db = pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set")
ENTRY_SQL = (
    'INSERT INTO network_feed_entries ("list", value, family, tier, categories, services, tags, '
    "families, ports, first_seen, last_seen, expires, reported, seen_here) VALUES (:list, :value, "
    ":family, :tier, CAST(:categories AS text[]), CAST(:services AS text[]), "
    "CAST(:tags AS text[]), CAST(:families AS text[]), CAST(:ports AS int[]), :first, :last, "
    ":expires, :reported, :seen)"
)


def row(
    list_id: str, value: str, *, tier: str = "standard", last: int = 1, seen: bool = False,
    family: int | None = 4,
) -> dict[str, Any]:  # fmt: skip
    return {
        "list": list_id, "value": value, "family": family, "tier": tier,
        "categories": ["c2"] if list_id != "inbound" else ["attack_source"],
        "services": ["ssh"], "tags": ["mirai"], "families": ["mirai"], "ports": [23],
        "first": TODAY - timedelta(days=9), "last": TODAY - timedelta(days=last),
        "expires": TODAY + timedelta(days=9), "reported": False, "seen": seen,
    }  # fmt: skip


ROWS = [
    row("outbound", "203.0.113.50", tier="high", last=1, seen=True),
    row("outbound", "198.51.100.9", last=2),
    row("outbound", "198.51.100.10", last=2),
    row("outbound", "203.0.113.7", last=2),  # the administrator allowed this one
    row("outbound", "2001:db8::50", last=3, family=6),
    row("outbound", "100.64.0.5", last=3),  # not a global address: never served
    row("inbound", "192.0.2.77", tier="high", last=1),
    row("inbound", "192.0.2.78", last=4),
    row("outbound-domains", "dl.c2.example.org", last=1, family=None),
]


@pytest.fixture
async def client(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[httpx.AsyncClient]:
    monkeypatch.setenv("FEEDS_ENABLED", "true")
    monkeypatch.setenv("NETWORK_FEED_ENABLED", "true")
    monkeypatch.setenv("NETWORK_FEED_URL", BASE)
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE network_feed_entries, network_feed_state, network_targets, "
                "blocklist_overrides, feed_tokens, audit_log"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO network_feed_state (id, serial, generated_at, valid_until, key_id, "
                "last_fetch_at, last_ok_at) VALUES (1, 4812, :g, :v, 'abcd', :g, :g)"
            ),
            {"g": NOW, "v": NOW + timedelta(days=2)},
        )
        for r in ROWS:
            await conn.execute(text(ENTRY_SQL), r)
        await conn.execute(
            text(
                "INSERT INTO blocklist_overrides (kind, value, action, note, created_by) "
                "VALUES ('ip', '203.0.113.7', 'allow', 'ours', 'owner')"
            )
        )
        await conn.execute(text("UPDATE network_membership SET desired = 'off', state = 'off'"))
    engine = api_engine()
    app = create_app(create_session_factory(engine), enable_live=False)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        ) as c:
            yield c
    await engine.dispose()


async def make_member() -> None:
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text("UPDATE network_membership SET desired = 'member', state = 'member'")
        )
        await conn.execute(
            text(
                "INSERT INTO network_targets (hub_id, kind, value, state, nodes, countries, "
                "first_day, last_day, mine) VALUES ('t_0123456789ab', 'c2_ip', '198.51.100.9', "
                "'confirmed', 2, 3, :d, :d, true)"
            ),
            {"d": TODAY},
        )


async def token(c: httpx.AsyncClient, kinds: list[str]) -> str:
    r = await c.post(
        "/api/v1/defend/feed-tokens", json={"name": "fw", "kinds": kinds, "password": "x"}
    )
    assert r.status_code == 201, r.text
    return str(r.json()["token"])


async def set_state(**sets: Any) -> None:
    cols = ", ".join(f"{k} = :{k}" for k in sets)
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(text(f"UPDATE network_feed_state SET {cols}"), sets)  # noqa: S608


@pytest.mark.integration
@needs_db
async def test_status_counts_and_hides_the_helped_figure_from_non_members(
    client: httpx.AsyncClient,
) -> None:
    body = (await client.get("/api/v1/network/feed/status")).json()
    assert body["state"] == "ok" and body["member"] is False and body["serial"] == 4812
    by_id = {lst["id"]: lst for lst in body["lists"]}
    assert (by_id["outbound"]["entries"], by_id["outbound"]["high"]) == (6, 1)
    assert by_id["outbound"]["seen_here"] == 1 and by_id["inbound"]["entries"] == 2
    assert by_id["outbound-domains"]["entries"] == 1
    assert all(lst["helped"] is None for lst in body["lists"])
    await make_member()
    body = (await client.get("/api/v1/network/feed/status")).json()
    by_id = {lst["id"]: lst for lst in body["lists"]}
    assert body["member"] is True and by_id["outbound"]["helped"] == 1
    assert by_id["inbound"]["helped"] == 0


@pytest.mark.integration
@needs_db
async def test_entries_are_paginated_filtered_and_newest_first(client: httpx.AsyncClient) -> None:
    url = "/api/v1/network/feed/entries"
    seen: list[str] = []
    cursor = None
    for _ in range(10):
        page = (
            await client.get(url, params={"limit": 4, **({"cursor": cursor} if cursor else {})})
        ).json()
        assert len(page["items"]) <= 4
        seen += [f"{i['list']}/{i['value']}" for i in page["items"]]
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert len(seen) == len(ROWS) == len(set(seen))
    first = (await client.get(url, params={"limit": 100})).json()["items"]
    assert [i["last_seen"] for i in first] == sorted((i["last_seen"] for i in first), reverse=True)
    assert set(first[0]) == {
        "list", "value", "family", "tier", "categories", "services", "tags", "families", "ports",
        "first_seen", "last_seen", "expires", "reported", "seen_here", "helped",
    }  # fmt: skip
    assert all(i["helped"] is None for i in first)
    high = (await client.get(url, params={"list": "outbound", "tier": "high"})).json()["items"]
    assert [i["value"] for i in high] == ["203.0.113.50"]
    here = (await client.get(url, params={"seen_here": "1"})).json()["items"]
    assert [i["value"] for i in here] == ["203.0.113.50"]
    q = (await client.get(url, params={"q": "C2.EXAMPLE"})).json()["items"]
    assert [i["value"] for i in q] == ["dl.c2.example.org"] and q[0]["family"] is None
    wild = (await client.get(url, params={"q": "%"})).json()["items"]
    assert wild == []  # the wildcard is literal
    assert (await client.get(url, params={"cursor": "e30"})).status_code == 400
    await make_member()
    helped = {
        i["value"]: i["helped"]
        for i in (await client.get(url, params={"limit": 100})).json()["items"]
    }
    assert helped["198.51.100.9"] is True and helped["198.51.100.10"] is False


@pytest.mark.integration
@needs_db
async def test_the_mirror_serves_verified_entries_to_a_network_token_only(
    client: httpx.AsyncClient,
) -> None:
    tok = await token(client, ["network"])
    body = (await client.get(f"/feeds/{tok}/network/outbound.txt")).text
    # Sorted numerically. Left out: the allowed host, the private address and the documentation
    # IPv6 address (not a global address, so the last check refuses it).
    assert body == "198.51.100.9\n198.51.100.10\n203.0.113.50\n"
    r = await client.get("/feeds/network/outbound.txt", headers={"Authorization": f"Bearer {tok}"})
    assert r.text == body and r.headers["x-entry-count"] == "3"
    assert r.headers["cache-control"] == "private, max-age=300"
    again = await client.get(
        f"/feeds/{tok}/network/outbound.txt", headers={"If-None-Match": r.headers["etag"]}
    )
    assert again.status_code == 304
    assert (await client.get(f"/feeds/{tok}/network/outbound-high.txt")).text == "203.0.113.50\n"
    assert (
        await client.get(f"/feeds/{tok}/network/inbound.txt")
    ).text == "192.0.2.77\n192.0.2.78\n"
    assert (
        await client.get(f"/feeds/{tok}/network/outbound-domains.txt")
    ).text == "dl.c2.example.org\n"
    csv_body = (await client.get(f"/feeds/{tok}/network/outbound.csv")).text
    assert csv_body.startswith("value,family,tier,") and "\r\n203.0.113.50,4,high,c2" in csv_body
    for bad in ("outbound.json", "outbound-domains-high.txt", "nope.txt"):
        assert (await client.get(f"/feeds/{tok}/network/{bad}")).status_code == 404
    # A token of kind network reads nothing else, and other tokens read no mirror.
    assert (await client.get(f"/feeds/{tok}/ip.txt")).status_code == 404
    other = await token(client, ["ip"])
    assert (await client.get(f"/feeds/{other}/network/outbound.txt")).status_code == 404
    assert (await client.get(f"/feeds/{other}/ip.txt")).status_code == 200
    assert (await client.get("/feeds/network/outbound.txt")).status_code == 404


@pytest.mark.integration
@needs_db
async def test_the_mirror_is_empty_when_stale_never_fetched_or_switched_off(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    tok = await token(client, ["network"])
    url = f"/feeds/{tok}/network/outbound.txt"
    assert (await client.get(url)).text != ""
    await set_state(valid_until=NOW - timedelta(minutes=1))
    r = await client.get(url)
    assert r.status_code == 200 and r.text == "" and r.headers["x-entry-count"] == "0"
    status = (await client.get("/api/v1/network/feed/status")).json()
    assert status["state"] == "stale" and status["signature"] == "verified"
    assert status["lists"][1]["entries"] == 6  # still shown, no longer served
    await set_state(valid_until=NOW + timedelta(days=2), serial=None)
    assert (await client.get(url)).text == ""
    await set_state(serial=4812)
    assert (await client.get(url)).text != ""
    monkeypatch.setenv("NETWORK_FEED_ENABLED", "false")
    assert (await client.get(url)).text == ""
    off = (await client.get("/api/v1/network/feed/status")).json()
    assert off["state"] == "disabled" and off["lists"][1]["entries"] == 0
    assert (await client.get("/api/v1/network/feed/entries")).json()["items"] == []

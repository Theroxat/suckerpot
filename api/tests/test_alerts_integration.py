"""Alert channels, rules, watched CVEs, outbox and reports against a real TimescaleDB."""

import base64
import json
import os
from collections.abc import AsyncIterator

import httpx
import pytest
from analytics_seed import api_engine, owner_engine
from argon2 import PasswordHasher
from sqlalchemy import text
from suckerpot_db import create_session_factory
from suckerpot_db.alert_targets import decrypt_target
from suckerpot_db.secretbox import ENV_VAR, SecretBox

import api.auth as auth_mod
from api.auth import AuthSettings
from api.main import create_app

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

PASSWORD = "correct horse battery staple"
HASH = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(PASSWORD)
MASTER = bytes(range(32))
ORIGIN = "https://testserver"
TOKEN = "S" * 30
HOOK = f"https://discord.com/api/webhooks/123456789012345678/{TOKEN}"
RESET = (
    "TRUNCATE alert_outbox, alert_test_requests, weekly_reports, alert_channels, watched_cves, "
    "audit_log, enrichment_status RESTART IDENTITY CASCADE"
)


async def reset() -> None:
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(text(RESET))
        await conn.execute(text("UPDATE alert_rules SET enabled = false, channel_ids = '{}'"))


@pytest.fixture
async def client(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[httpx.AsyncClient]:
    monkeypatch.setattr(auth_mod, "FAILURE_DELAY_S", 0.0)
    monkeypatch.setenv(ENV_VAR, base64.b64encode(MASTER).decode())
    await reset()
    engine = api_engine()
    settings = AuthSettings(password_hash=HASH, secret=b"k" * 40)
    app = create_app(create_session_factory(engine), enable_live=False, auth_settings=settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as c,
    ):
        r = await c.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": PASSWORD},
            headers={"Origin": ORIGIN},
        )
        assert r.status_code == 204
        c.headers.update({"Origin": ORIGIN, "X-CSRF-Token": c.cookies["__Host-sp_csrf"]})
        yield c
    await engine.dispose()
    await reset()


async def make_channel(c: httpx.AsyncClient, **over: object) -> dict[str, object]:
    body = {"kind": "discord", "name": "Security", "target": HOOK, "password": PASSWORD}
    r = await c.post("/api/v1/alerts/channels", json={**body, **over})
    assert r.status_code == 201, r.text
    out: dict[str, object] = r.json()
    return out


async def test_channel_lifecycle_never_returns_the_target(client: httpx.AsyncClient) -> None:
    created = await make_channel(client)
    assert created["target_hint"] == "discord.com" and created["mask_ips"] is True
    listing = (await client.get("/api/v1/alerts/channels")).json()
    assert TOKEN not in json.dumps(listing) and TOKEN not in json.dumps(created)
    async with owner_engine() as owner, owner.connect() as conn:
        blob = (
            await conn.execute(text("SELECT target_ciphertext FROM alert_channels"))
        ).scalar_one()
        query = text("SELECT action, details::text FROM audit_log WHERE action LIKE 'alert_%'")
        audit = (await conn.execute(query)).all()
    assert TOKEN.encode() not in bytes(blob)
    assert decrypt_target(SecretBox(MASTER), int(str(created["id"])), bytes(blob)) == HOOK
    assert [a[0] for a in audit] == ["alert_channel.create"] and TOKEN not in str(audit)

    r = await client.patch(f"/api/v1/alerts/channels/{created['id']}", json={"mask_ips": False})
    assert r.status_code == 200 and r.json()["mask_ips"] is False
    url = f"/api/v1/alerts/channels/{created['id']}"
    other = HOOK.replace("1234567890", "9999999999")
    assert (await client.patch(url, json={"target": other})).status_code == 401  # no password
    wrong = await client.patch(url, json={"target": other, "password": "wrong password"})
    assert wrong.status_code in (401, 403)
    ok = await client.patch(url, json={"target": other, "password": PASSWORD})
    assert ok.status_code == 200
    async with owner_engine() as owner, owner.connect() as conn:
        blob = (
            await conn.execute(text("SELECT target_ciphertext FROM alert_channels"))
        ).scalar_one()
    assert decrypt_target(SecretBox(MASTER), int(str(created["id"])), bytes(blob)) == other
    assert (await client.delete(f"/api/v1/alerts/channels/{created['id']}")).status_code == 204
    assert (await client.get("/api/v1/alerts/channels")).json() == []


async def test_bad_targets_and_wrong_password_are_refused(client: httpx.AsyncClient) -> None:
    for kind, target in [
        ("discord", HOOK.replace("discord.com", "evil.example")),
        ("discord", HOOK.replace("https", "http")),
        ("discord", "https://192.0.2.1/api/webhooks/123456789012345678/" + TOKEN),
        ("teams", HOOK),
        ("email", "a@example.org\nBcc: b@example.org"),
    ]:
        r = await client.post(
            "/api/v1/alerts/channels",
            json={"kind": kind, "name": "x", "target": target, "password": PASSWORD},
        )
        assert r.status_code == 422, (kind, target)
        assert r.json()["code"] == "invalid_target" or "detail" in r.json()
        assert TOKEN not in r.text
    r = await client.post(
        "/api/v1/alerts/channels",
        json={"kind": "discord", "name": "x", "target": HOOK, "password": "wrong password"},
    )
    assert r.status_code in (401, 403)
    assert (await client.get("/api/v1/alerts/channels")).json() == []


async def test_rules_need_an_enabled_channel(client: httpx.AsyncClient) -> None:
    rules = (await client.get("/api/v1/alerts/rules")).json()
    assert [r["kind"] for r in rules] == [
        "new_campaign", "new_download_host", "malware_drop", "watched_cve_seen", "weekly_report",
    ]  # fmt: skip
    assert not any(r["enabled"] for r in rules)
    r = await client.put("/api/v1/alerts/rules/malware_drop", json={"enabled": True})
    assert r.status_code == 422 and r.json()["code"] == "no_channel"
    r = await client.put(
        "/api/v1/alerts/rules/malware_drop", json={"enabled": True, "channel_ids": [999]}
    )
    assert r.status_code == 422
    ch = await make_channel(client)
    r = await client.put(
        "/api/v1/alerts/rules/malware_drop",
        json={"enabled": True, "channel_ids": [ch["id"]], "min_severity": "severe"},
    )
    assert r.status_code == 200 and r.json()["enabled"] is True
    async with owner_engine() as owner, owner.connect() as conn:
        stamp = (
            await conn.execute(
                text("SELECT enabled_at FROM alert_rules WHERE kind = 'malware_drop'")
            )
        ).scalar_one()
    assert stamp is not None  # ingest restarts its cursor from here
    # disabling the channel switches the rule off
    r = await client.patch(f"/api/v1/alerts/channels/{ch['id']}", json={"enabled": False})
    assert r.status_code == 200
    rule = next(
        x for x in (await client.get("/api/v1/alerts/rules")).json() if x["kind"] == "malware_drop"
    )
    assert rule["enabled"] is False and rule["channel_ids"] == []
    assert (
        await client.put("/api/v1/alerts/rules/bogus", json={"enabled": False})
    ).status_code == 422


async def test_send_test_is_gated_and_rate_limited(client: httpx.AsyncClient) -> None:
    ch = await make_channel(client)
    url = f"/api/v1/alerts/channels/{ch['id']}/test"
    assert (await client.post(url)).json()["code"] == "alerts_disabled"
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO enrichment_status (name, detail) VALUES "
                "('alerts', '{\"enabled\": true, \"smtp_configured\": false}')"
            )
        )
    assert (await client.post(url)).status_code == 202
    again = await client.post(url)
    assert again.status_code == 429 and again.json()["code"] == "pending"
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(text("UPDATE alert_test_requests SET state = 'done', detail = 'sent'"))
    listing = (await client.get("/api/v1/alerts/channels")).json()
    assert listing[0]["last_test"]["state"] == "done"
    assert (await client.post(url)).json()["code"] == "cooldown"
    assert (await client.post("/api/v1/alerts/channels/9999/test")).status_code == 404


async def test_watched_cves(client: httpx.AsyncClient) -> None:
    assert (await client.put("/api/v1/alerts/watched-cves/CVE-2026-0001")).status_code == 200
    assert (await client.put("/api/v1/alerts/watched-cves/CVE-2026-0001")).status_code == 200
    assert (await client.put("/api/v1/alerts/watched-cves/not-a-cve")).status_code == 422
    items = (await client.get("/api/v1/alerts/watched-cves")).json()
    assert [i["cve_id"] for i in items] == ["CVE-2026-0001"]
    assert (await client.delete("/api/v1/alerts/watched-cves/CVE-2026-0001")).status_code == 204
    assert (await client.get("/api/v1/alerts/watched-cves")).json() == []


async def test_outbox_is_paginated_and_shows_only_titles(client: httpx.AsyncClient) -> None:
    ch = await make_channel(client)
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO alert_outbox (rule_kind, dedupe_key, channel_id, payload, state, "
                "created_at) SELECT 'new_campaign', 'k' || g, :c, "
                "jsonb_build_object('title', 'Alert ' || g, 'summary', 's', 'severity', 'severe', "
                "'facts', jsonb_build_array(jsonb_build_array('Source', '1.2.x.x'))), 'sent', "
                "now() - make_interval(mins => g) FROM generate_series(1, 7) g"
            ),
            {"c": ch["id"]},
        )
    page1 = (await client.get("/api/v1/alerts/outbox?limit=3")).json()
    assert [i["title"] for i in page1["items"]] == ["Alert 1", "Alert 2", "Alert 3"]
    assert "facts" not in page1["items"][0] and page1["items"][0]["channel_name"] == "Security"
    page2 = (
        await client.get(f"/api/v1/alerts/outbox?limit=3&cursor={page1['next_cursor']}")
    ).json()
    assert [i["title"] for i in page2["items"]] == ["Alert 4", "Alert 5", "Alert 6"]
    page3 = (
        await client.get(f"/api/v1/alerts/outbox?limit=3&cursor={page2['next_cursor']}")
    ).json()
    assert [i["title"] for i in page3["items"]] == ["Alert 7"] and page3["next_cursor"] is None
    assert (await client.get("/api/v1/alerts/outbox?cursor=garbage")).status_code == 400
    assert (await client.get("/api/v1/alerts/outbox?limit=101")).status_code == 422
    assert (await client.get("/api/v1/alerts/outbox?state=failed")).json()["items"] == []


async def test_reports_are_listed_and_served_under_a_strict_csp(client: httpx.AsyncClient) -> None:
    totals = {"sessions": 5, "sources": 2, "malware": 0, "change_pct": None}
    summary = {"week_end": "2026-10-18", "headline": "Quiet.", "totals": totals}
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO weekly_reports (week_start, html, summary) VALUES "
                "('2026-10-12', '<!doctype html><title>t</title><p>hello</p>', CAST(:s AS jsonb)),"
                "('2026-10-05', '<p>older</p>', CAST(:s AS jsonb))"
            ),
            {"s": json.dumps(summary)},
        )
    listing = (await client.get("/api/v1/reports?limit=1")).json()
    assert [i["week_start"] for i in listing["items"]] == ["2026-10-12"]
    assert listing["items"][0]["sessions"] == 5 and listing["items"][0]["headline"] == "Quiet."
    older = (await client.get(f"/api/v1/reports?limit=1&cursor={listing['next_cursor']}")).json()
    assert [i["week_start"] for i in older["items"]] == ["2026-10-05"]
    assert (await client.get("/api/v1/reports/2026-10-12")).json()["summary"][
        "headline"
    ] == "Quiet."
    page = await client.get("/api/v1/reports/2026-10-12/html")
    assert page.status_code == 200 and "<p>hello</p>" in page.text
    csp = page.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "script-src" not in csp and "sandbox" in csp
    assert "frame-ancestors 'self'" in csp
    assert page.headers["content-type"].startswith("text/html")
    assert page.headers["x-content-type-options"] == "nosniff"
    assert (await client.get("/api/v1/reports/2026-01-01/html")).status_code == 404
    assert (await client.get("/api/v1/reports/not-a-date")).status_code == 422
    assert (await client.get("/api/v1/reports/2026-13-45")).status_code == 404


async def test_status_reports_what_ingest_published(client: httpx.AsyncClient) -> None:
    r = (await client.get("/api/v1/alerts/status")).json()
    assert r["alerts"]["enabled"] is False and r["editing_enabled"] is True
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO enrichment_status (name, detail) VALUES "
                '(\'alerts\', \'{"enabled": true, "smtp_configured": true, "can_decrypt": true}\')'
            )
        )
    r = (await client.get("/api/v1/alerts/status")).json()
    assert (
        r["alerts"]["enabled"] and r["alerts"]["smtp_configured"] and r["limits"]["per_day"] == 100
    )

"""Takedown statistics, targets and the two admin actions against a real TimescaleDB."""

# ruff: noqa: F811  (the imported `client` fixture is requested by name)
import base64
import hashlib
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from analytics_seed import owner_engine
from sqlalchemy import text
from test_abuse_integration import client  # noqa: F401  (the seeded, signed-in admin client)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]
NOW = datetime.now(UTC).replace(microsecond=0)


@pytest.fixture(autouse=True)
def _key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", base64.b64encode(bytes(range(32, 72))).decode())


async def add(
    age_h: float,
    down_after_h: float | None = None,
    *,
    role: str = "payload_url",
    kind: str = "url",
    value: str | None = None,
    provider: str = "as64500",
    channels: tuple[str, ...] = ("mail",),
    state: str = "unknown",
    **kw: Any,
) -> int:
    reported = NOW - timedelta(hours=age_h)
    value = value or f"http://files.example.net/{age_h}-{down_after_h}-{provider}-{role}"
    params: dict[str, Any] = {
        "kind": kind, "role": role, "value": value,
        "key": hashlib.sha256(f"{kind}:{value}".encode()).hexdigest(), "prov": provider,
        "rep": reported, "channels": list(channels), "until": reported + timedelta(days=30),
        "state": state,
        "down": None if down_after_h is None else reported + timedelta(hours=down_after_h),
        "dbr": kw.get("down_before_report", False), "demo": kw.get("demo", False),
        "tracking": kw.get("tracking", True), "elig": kw.get("elig", False),
        "name": kw.get("name", "EXAMPLE-NET"),
    }  # fmt: skip
    async with owner_engine() as owner, owner.begin() as conn:
        return int(
            await conn.scalar(
                text(
                    "INSERT INTO takedown_targets (kind, role, value, target_key, provider_key, "
                    "provider_name, reported_at, channels, track_until, state, first_down_at, "
                    "down_before_report, demo, tracking, http_eligible) VALUES (:kind, :role, "
                    ":value, :key, :prov, :name, :rep, CAST(:channels AS text[]), :until, :state, "
                    ":down, :dbr, :demo, :tracking, :elig) RETURNING id"
                ),
                params,
            )
            or 0
        )


@pytest.fixture
async def world(client: httpx.AsyncClient) -> httpx.AsyncClient:
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE takedown_target_links, takedown_checks, takedown_targets, "
                "outcome_rollup_monthly, abusech_submissions, abusech_submission CASCADE"
            )
        )
    return client


async def test_the_summary_leaves_young_targets_out_of_the_denominator(
    world: httpx.AsyncClient,
) -> None:
    for i in range(3):  # old and down within 48 h
        await add(200 + i, 12, value=f"http://a.example.net/{i}")
    for i in range(3):  # old and still up
        await add(200 + i, None, value=f"http://b.example.net/{i}")
    for i in range(6):  # younger than 48 h, none down
        await add(10 + i, None, value=f"http://c.example.net/{i}")
    await add(300, 0.1, value="http://d.example.net/x", down_before_report=True)  # not a statistic
    got = (await world.get("/api/v1/takedown/summary")).json()
    urls = got["urls"]
    assert urls["tracked"] == 12
    assert (urls["eligible_48h"], urls["down_48h"]) == (6, 3)
    assert (urls["eligible_30d"], urls["down_30d"]) == (3, 3)  # the rest was seen for 8 days
    assert urls["ttd_p50_s"] is None and urls["ttd_n"] == 3  # fewer than five values
    assert got["hosts"]["tracked"] == 0
    assert got["reports"]["sent"] == 0


async def test_median_needs_five_and_states_of_other_roles(world: httpx.AsyncClient) -> None:
    for i, h in enumerate((2, 4, 6, 8, 10)):
        await add(200, h, value=f"http://m.example.net/{i}")
    await add(100, role="attack_source", kind="ip", value="198.51.100.7", state="up")
    await add(100, role="attack_source", kind="ip", value="198.51.100.8", state="down")
    await add(100, role="c2", kind="ip", value="203.0.113.9", state="up")
    await add(100, role="c2", kind="ip", value="203.0.113.10", state="unknown")
    got = (await world.get("/api/v1/takedown/summary")).json()
    assert (got["urls"]["ttd_p50_s"], got["urls"]["ttd_n"]) == (6 * 3600, 5)
    assert got["attack_sources"] == {"tracked": 2, "quiet": 1, "active": 1}
    assert got["c2"] == {"tracked": 2, "still_used": 1}
    only_mail = (await world.get("/api/v1/takedown/summary?channel=urlhaus")).json()
    assert only_mail["urls"]["tracked"] == 0


async def test_the_curve_is_cumulative_and_censored(world: httpx.AsyncClient) -> None:
    await add(500, 0.5, value="http://k.example.net/1")
    await add(500, 5, value="http://k.example.net/2")
    await add(500, None, value="http://k.example.net/3")
    await add(2, None, value="http://k.example.net/4")
    got = (await world.get("/api/v1/takedown/curve")).json()
    urls = next(s for s in got["series"] if s["kind"] == "url")
    points = {p["hours"]: p for p in urls["points"]}
    assert [p["hours"] for p in urls["points"]] == [1, 6, 24, 48, 72, 168, 336, 720]
    assert points[1]["eligible"] == 4 and points[1]["down"] == 1
    assert points[48]["eligible"] == 3 and points[48]["percent"] == pytest.approx(66.7, abs=0.1)
    hosts = next(s for s in got["series"] if s["kind"] == "host")
    assert all(p["percent"] is None for p in hosts["points"])


async def test_providers_are_ranked_and_limited(world: httpx.AsyncClient) -> None:
    for i in range(4):
        await add(200, 6 if i < 3 else None, provider="as64500", value=f"http://p1.example.net/{i}")
    for i in range(2):
        await add(200, None, provider="as64501", value=f"http://p2.example.net/{i}", name="OTHER")
    got = (await world.get("/api/v1/takedown/providers")).json()["items"]
    assert [p["provider_key"] for p in got] == ["as64500", "as64501"]
    first = got[0]
    assert first["targets"] == 4 and first["percent_48h"] == 75.0 and first["name"] == "EXAMPLE-NET"
    assert (await world.get("/api/v1/takedown/providers?limit=1")).json()["items"][0][
        "targets"
    ] == 4
    assert (await world.get("/api/v1/takedown/providers?limit=500")).status_code == 422


async def test_targets_paginate_and_filter(world: httpx.AsyncClient) -> None:
    for i in range(7):
        await add(i + 1, value=f"http://list.example.net/{i}", state="up" if i % 2 else "down")
    await add(3, role="c2", kind="ip", value="203.0.113.9")
    first = (await world.get("/api/v1/takedown/targets?limit=3")).json()
    assert len(first["items"]) == 3 and first["next_cursor"]
    second = (
        await world.get(f"/api/v1/takedown/targets?limit=3&cursor={first['next_cursor']}")
    ).json()
    ids = [t["id"] for t in first["items"] + second["items"]]
    assert len(set(ids)) == 6
    only_c2 = (await world.get("/api/v1/takedown/targets?role=c2")).json()["items"]
    assert [t["value"] for t in only_c2] == ["203.0.113.9"]
    up = (await world.get("/api/v1/takedown/targets?state=up&kind=url")).json()["items"]
    assert up and all(t["state"] == "up" for t in up)
    found = (await world.get("/api/v1/takedown/targets?q=list.example")).json()["items"]
    assert len(found) == 7
    assert (await world.get("/api/v1/takedown/targets?q=%25")).json()["items"] == []
    assert (await world.get("/api/v1/takedown/targets?limit=101")).status_code == 422
    assert (await world.get("/api/v1/takedown/targets?cursor=garbage")).status_code == 400
    assert (await world.get("/api/v1/takedown/targets?state=weird")).status_code == 422


async def test_a_target_page_has_children_checks_links_and_bounds(
    world: httpx.AsyncClient,
) -> None:
    host = await add(50, 20, role="payload_host", kind="ip", value="198.51.100.7")
    kid = await add(50, 20, value="http://198.51.100.7/a.sh", elig=True)
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text("UPDATE takedown_targets SET parent_id = :h, last_up_at = :u WHERE id = :k"),
            {"h": host, "k": kid, "u": NOW - timedelta(hours=40)},
        )
        for i, outcome in enumerate(("same", "http_404", "http_404")):
            await conn.execute(
                text(
                    "INSERT INTO takedown_checks (target_id, checked_at, method, outcome, "
                    "http_status, detail) VALUES (:t, :at, 'http', :o, 404, '{\"redirects\": 1}')"
                ),
                {"t": kid, "at": NOW - timedelta(hours=40 - i * 10), "o": outcome},
            )
    got = (await world.get(f"/api/v1/takedown/targets/{host}")).json()
    assert got["target"]["value"] == "198.51.100.7" and [c["id"] for c in got["children"]] == [kid]
    detail = (await world.get(f"/api/v1/takedown/targets/{kid}")).json()
    assert [c["outcome"] for c in detail["checks"]] == [
        "http_404",
        "http_404",
        "same",
    ]  # newest first
    assert detail["checks"][0]["detail"] == {"redirects": 1}
    assert detail["ttd"]["seconds"] == 20 * 3600 and detail["ttd"]["down_after"] is not None
    assert (await world.get("/api/v1/takedown/targets/999999")).status_code == 404


async def test_recheck_moves_the_due_dates_and_is_rate_limited(world: httpx.AsyncClient) -> None:
    quiet = await add(100, elig=True, value="http://r.example.net/a")
    fresh = await add(100, elig=True, value="http://r.example.net/b")
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "UPDATE takedown_targets SET http_next_at = now() + interval '1 day', "
                "listing_next_at = now() + interval '1 day'"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO takedown_checks (target_id, checked_at, method, outcome) VALUES "
                "(:a, now() - interval '3 hours', 'http', 'same'), "
                "(:b, now() - interval '5 minutes', 'http', 'same')"
            ),
            {"a": quiet, "b": fresh},
        )
    ok = await world.post(f"/api/v1/takedown/targets/{quiet}/recheck")
    assert ok.status_code == 200 and ok.json() == {"id": quiet, "http": True, "listing": True}
    async with owner_engine() as owner, owner.connect() as conn:
        due = (
            await conn.execute(
                text("SELECT id, http_next_at <= now() AS due FROM takedown_targets ORDER BY id")
            )
        ).all()
    assert {r.id: r.due for r in due} == {quiet: True, fresh: False}
    too_soon = await world.post(f"/api/v1/takedown/targets/{fresh}/recheck")
    assert too_soon.status_code == 429 and too_soon.json()["code"] == "too_soon"
    assert (await world.post("/api/v1/takedown/targets/999999/recheck")).status_code == 404


async def test_a_demo_target_cannot_be_rechecked_and_stop_is_audited(
    world: httpx.AsyncClient,
) -> None:
    demo = await add(10, demo=True, value="http://demo.example.net/x")
    # Demo targets are hidden unless the demo flag is on (the seeded client turns it on).
    assert (await world.post(f"/api/v1/takedown/targets/{demo}/recheck")).status_code == 409
    real = await add(10, value="http://s.example.net/x")
    stop = await world.post(f"/api/v1/takedown/targets/{real}/stop")
    assert stop.status_code == 200 and stop.json() == {"id": real, "tracking": False}
    again = await world.post(f"/api/v1/takedown/targets/{real}/stop")
    assert again.status_code == 200
    async with owner_engine() as owner, owner.connect() as conn:
        row = (
            await conn.execute(
                text("SELECT tracking, stopped_at, stopped_by FROM takedown_targets WHERE id = :i"),
                {"i": real},
            )
        ).one()
        audits = (
            await conn.execute(
                text("SELECT action FROM audit_log WHERE action LIKE 'takedown.%' ORDER BY id")
            )
        ).scalars().all()  # fmt: skip
    assert row.tracking is False and row.stopped_at is not None and row.stopped_by
    assert audits == ["takedown.stop"]  # the second stop changed nothing, so it logs nothing
    gone = await world.post(f"/api/v1/takedown/targets/{real}/recheck")
    assert gone.status_code == 409 and gone.json()["code"] == "not_tracked"


async def test_old_months_come_from_the_rollup(world: httpx.AsyncClient) -> None:
    await add(10, value="http://live.example.net/x")
    async with owner_engine() as owner, owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO outcome_rollup_monthly (month, provider_key, kind, channel, targets, "
                "targets_eligible_48h, targets_down_48h) VALUES "
                "(date_trunc('month', now() - interval '300 days')::date, 'as64509', "
                "'payload_url', 'mail', 8, 8, 6)"
            )
        )
    since = (NOW - timedelta(days=400)).isoformat()
    got = (await world.get("/api/v1/takedown/providers", params={"since": since})).json()["items"]
    old = next(p for p in got if p["provider_key"] == "as64509")
    assert (old["targets"], old["eligible_48h"], old["down_48h"]) == (8, 8, 6)
    summary = (await world.get("/api/v1/takedown/summary", params={"since": since})).json()
    assert summary["urls"]["eligible_48h"] >= 8

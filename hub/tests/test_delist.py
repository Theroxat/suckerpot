"""Public delisting, lookup and the operator commands (design M30 section 9 and 7.5)."""

from __future__ import annotations

import os
import stat
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from suckerpot_netproto import pow, sign
from suckerpot_netproto.feeds import minisign

from hub import admin
from hub.feeds import filter as feed_filter
from hub.retention import DELIST_EVIDENCE_DAYS

from .conftest import Env
from .seed import TODAY, add_nodes

HERE = Path(__file__).resolve().parent.parent
BOTS = "192.0.2.10"
OTHER = "192.0.2.11"
C2 = "198.51.100.20"
DOMAIN = "dropper.example.org"
DIFFICULTY = 4


async def add_entry(
    env: Env,
    value: str,
    list_id: str = "inbound",
    state: str = "listed",
    reason: str | None = None,
    target_id: str | None = None,
    removed: bool = False,
) -> None:
    async with env.owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO feed_entries (list, value, family, tier, state, first_seen, last_seen, "
                "expires, removed_day, removed_reason, target_id) VALUES (:l, :v, 4, 'standard', :s, "
                ":d, :d, :e, :rd, :rr, :t)"
            ),
            {
                "l": list_id,
                "v": value,
                "s": state,
                "d": TODAY,
                "e": TODAY + timedelta(days=7),
                "rd": TODAY if removed else None,
                "rr": reason,
                "t": target_id,
            },
        )


async def solve(env: Env) -> tuple[str, str]:
    r = await env.http.post("/v1/delist/challenge", json={})
    assert r.status_code == 200
    data = r.json()
    assert set(data) == {"challenge", "difficulty", "expires_in"}
    nonce = pow.solve_pow(sign.b64u_decode(data["challenge"]), b"", data["difficulty"])
    assert nonce is not None
    return data["challenge"], sign.b64u_encode(nonce)


async def ask(env: Env, value: str, **over: Any) -> httpx.Response:
    challenge, nonce = await solve(env)
    body = {
        "challenge": challenge,
        "pow_nonce": nonce,
        "value": value,
        "category": "cleaned_up",
        **over,
    }
    return await env.http.post("/v1/delist", json=body)


async def rows(env: Env, sql: str, **params: Any) -> list[Any]:
    async with env.owner.connect() as conn:
        return list((await conn.execute(text(sql), params)).all())


@pytest.fixture
async def d_env(env_factory: Any, monkeypatch: pytest.MonkeyPatch) -> Env:
    built: Env = await env_factory(delist_pow_difficulty=DIFFICULTY)
    monkeypatch.setattr(admin, "utcnow", built.clock)  # the CLI shares the test clock
    return built


# --- proof of work and storage ----------------------------------------------------------------


@pytest.mark.integration
async def test_round_trip_and_status_token(d_env: Env) -> None:
    env = d_env
    await add_entry(env, BOTS)
    r = await ask(env, BOTS, evidence="it was a compromised box", contact="ops@example.org")
    assert r.status_code == 200
    out = r.json()
    assert out["listed"] is True and out["state"] == "suppressed" and out["sla_hours"] == 72
    assert out["id"].startswith("d_") and len(out["id"]) == 18
    stored = await rows(env, "SELECT * FROM delist_requests")
    assert len(stored) == 1 and stored[0].value == BOTS
    # Only a hash of the token is stored.
    assert out["status_token"].encode() not in bytes(stored[0].token_hash)
    assert (
        bytes(stored[0].token_hash)
        == __import__("hashlib").sha256(sign.b64u_decode(out["status_token"])).digest()
    )
    ok = await env.http.get(
        f"/v1/delist/{out['id']}", headers={"Authorization": f"Bearer {out['status_token']}"}
    )
    assert ok.status_code == 200
    assert set(ok.json()) == {"id", "state", "outcome", "public_note", "created_day", "decided_day"}


@pytest.mark.integration
async def test_status_needs_the_token(d_env: Env) -> None:
    env = d_env
    await add_entry(env, BOTS)
    out = (await ask(env, BOTS)).json()
    url = f"/v1/delist/{out['id']}"
    other = sign.b64u_encode(os.urandom(32))
    for headers in ({}, {"Authorization": f"Bearer {other}"}, {"Authorization": "Bearer !!"}):
        r = await env.http.get(url, headers=headers)
        assert r.status_code == 404
    unknown = await env.http.get(
        "/v1/delist/d_0000000000000000", headers={"Authorization": f"Bearer {other}"}
    )
    assert unknown.status_code == 404 and unknown.json() == r.json()


@pytest.mark.integration
async def test_bad_pow_and_replayed_or_expired_challenge(d_env: Env) -> None:
    env = d_env
    await add_entry(env, BOTS)
    ch = (await env.http.post("/v1/delist/challenge", json={})).json()
    raw = sign.b64u_decode(ch["challenge"])
    bad = next(
        n.to_bytes(8, "big")
        for n in range(10000)
        if not pow.verify_pow(raw, b"", n.to_bytes(8, "big"), DIFFICULTY)
    )
    body = {
        "challenge": ch["challenge"],
        "pow_nonce": sign.b64u_encode(bad),
        "value": BOTS,
        "category": "other",
    }
    assert (await env.http.post("/v1/delist", json=body)).json() == {"error": "pow_invalid"}
    # The challenge was burned by the failed attempt.
    good = pow.solve_pow(raw, b"", DIFFICULTY)
    assert good is not None
    body["pow_nonce"] = sign.b64u_encode(good)
    assert (await env.http.post("/v1/delist", json=body)).json() == {"error": "challenge_expired"}
    # An old challenge expires.
    ch2 = (await env.http.post("/v1/delist/challenge", json={})).json()
    nonce = pow.solve_pow(sign.b64u_decode(ch2["challenge"]), b"", DIFFICULTY)
    assert nonce is not None
    env.clock.advance(minutes=11)
    r = await env.http.post(
        "/v1/delist",
        json={**body, "challenge": ch2["challenge"], "pow_nonce": sign.b64u_encode(nonce)},
    )
    assert r.json() == {"error": "challenge_expired"}
    assert await rows(env, "SELECT 1 FROM delist_requests") == []


@pytest.mark.integration
async def test_unlisted_value_stores_nothing(d_env: Env) -> None:
    env = d_env
    r = await ask(env, OTHER)
    assert r.status_code == 200 and r.json() == {"listed": False, "state": "not_listed"}
    assert await rows(env, "SELECT 1 FROM delist_requests") == []
    # A removed (not listed) value is not listed either.
    await add_entry(env, BOTS, state="removed", reason="expired", removed=True)
    assert (await ask(env, BOTS)).json()["listed"] is False
    assert await rows(env, "SELECT 1 FROM delist_requests") == []


@pytest.mark.integration
async def test_invalid_input_is_refused(d_env: Env) -> None:
    env = d_env
    for value in ("not a host", "192.0.2.0/24", "100.64.0.1", "fd00::1", "localhost", ""):
        r = await ask(env, value)
        assert r.status_code == 400, value
    assert (await ask(env, BOTS, category="whatever")).status_code == 400
    assert (await ask(env, BOTS, evidence="x" * 2001)).status_code == 400
    assert (await ask(env, BOTS, evidence="a\x00b")).status_code == 400
    assert (await ask(env, BOTS, contact="not-an-address")).status_code == 400
    assert (await ask(env, BOTS, list="nope")).status_code == 400
    # The tier names are accepted and map to their base list.
    assert (await ask(env, BOTS, list="inbound-high")).status_code == 200
    assert (await ask(env, BOTS, extra=1)).status_code == 400
    assert (await env.http.post("/v1/delist", content=b"[]")).status_code == 400
    big = await env.http.post("/v1/delist", content=b"{" + b" " * 70000 + b"}")
    assert big.status_code == 413


# --- limits -------------------------------------------------------------------------------------


@pytest.mark.integration
async def test_one_open_request_per_value(d_env: Env) -> None:
    env = d_env
    await add_entry(env, BOTS)
    assert (await ask(env, BOTS)).status_code == 200
    second = await ask(env, BOTS)
    assert second.status_code == 409 and second.json() == {"error": "request_open"}
    assert len(await rows(env, "SELECT 1 FROM delist_requests")) == 1


@pytest.mark.integration
async def test_daily_cap(env_factory: Any) -> None:
    env: Env = await env_factory(delist_pow_difficulty=DIFFICULTY, delist_daily_cap=2)
    for i in range(3):
        await add_entry(env, f"192.0.2.{20 + i}")
    assert (await ask(env, "192.0.2.20")).status_code == 200
    assert (await ask(env, "192.0.2.21")).status_code == 200
    assert (await ask(env, "192.0.2.22")).status_code == 429
    env.clock.advance(days=1)
    assert (await ask(env, "192.0.2.22")).status_code == 200


@pytest.mark.integration
async def test_address_rate_limit(env_factory: Any) -> None:
    env: Env = await env_factory(delist_pow_difficulty=DIFFICULTY, unsigned_per_min=3)
    codes = [(await env.http.post("/v1/delist/challenge", json={})).status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and codes[3:] == [429, 429]


# --- interim effect -----------------------------------------------------------------------------


@pytest.mark.integration
async def test_interim_suppression_is_inbound_only_and_capped(env_factory: Any) -> None:
    env: Env = await env_factory(delist_pow_difficulty=DIFFICULTY, delist_auto_suppress_daily=2)
    for v in ("192.0.2.31", "192.0.2.32", "192.0.2.33"):
        await add_entry(env, v)
    await add_entry(env, C2, "outbound")
    await add_entry(env, DOMAIN, "outbound-domains")
    await add_entry(env, "192.0.2.34", "outbound")  # a second outbound value
    states = {}
    for v in ("192.0.2.31", "192.0.2.32", "192.0.2.33", C2, DOMAIN, "192.0.2.34"):
        r = await ask(env, v)
        assert r.status_code == 200, v
        states[v] = r.json()["state"]
    assert states["192.0.2.31"] == states["192.0.2.32"] == "suppressed"
    assert states["192.0.2.33"] == "received"  # over the daily cap of hidden values
    assert states[C2] == states[DOMAIN] == "received"  # outbound is reviewed first
    assert states["192.0.2.34"] == "received"
    # A value that is on an inbound AND an outbound list is not hidden.
    env.clock.advance(days=1)
    await add_entry(env, "192.0.2.35")
    await add_entry(env, "192.0.2.35", "outbound")
    assert (await ask(env, "192.0.2.35")).json()["state"] == "received"


@pytest.mark.integration
async def test_suppressed_value_is_kept_out_of_the_lists(d_env: Env) -> None:
    env = d_env
    await add_entry(env, BOTS)
    await add_entry(env, OTHER)
    async with env.worker() as s:
        await s.execute(
            text("INSERT INTO feed_auto_ranges VALUES ('tor', '203.0.113.64/28', :d)"), {"d": TODAY}
        )
        await s.commit()
    assert (await ask(env, BOTS)).json()["state"] == "suppressed"
    async with env.worker() as s:
        excl = await feed_filter.load_exclusions(s, env.settings, TODAY)
    assert excl.classify(BOTS, is_domain=False) == "delisted"
    assert excl.classify(OTHER, is_domain=False) is None


# --- lookup -------------------------------------------------------------------------------------


@pytest.mark.integration
async def test_lookup_says_listed_removed_or_not_listed_and_nothing_else(d_env: Env) -> None:
    env = d_env
    await add_entry(env, BOTS)
    await add_entry(env, OTHER, state="removed", reason="expired", removed=True)
    await add_entry(env, "192.0.2.12", state="removed", reason="delisted", removed=True)
    await add_entry(env, "192.0.2.13", state="removed", reason="excluded", removed=True)
    await add_entry(env, "192.0.2.14", state="pending")
    expect = {
        BOTS: "listed",
        OTHER: "removed",
        "192.0.2.12": "not_listed",
        "192.0.2.13": "not_listed",
        "192.0.2.14": "not_listed",
        "192.0.2.99": "not_listed",
    }
    for value, answer in expect.items():
        r = await env.http.get("/v1/lookup", params={"value": value})
        assert r.status_code == 200
        assert r.json() == {"value": value, "status": answer}
    assert (await env.http.get("/v1/lookup", params={"value": "x y"})).status_code == 400
    assert (await env.http.get("/v1/lookup")).status_code == 400
    assert (await env.http.get("/v1/lookup", params={"value": "192.0.2.0/24"})).status_code == 400
    # A removal older than 30 days is forgotten.
    env.clock.advance(days=40)
    r = await env.http.get("/v1/lookup", params={"value": OTHER})
    assert r.json()["status"] == "not_listed"


# --- operator commands --------------------------------------------------------------------------


async def cli(env: Env, *argv: str) -> tuple[int, list[str]]:
    lines: list[str] = []
    code = await admin.run(list(argv), sessionmaker=env.worker, out=lines.append, actor="tester")
    return code, lines


async def seed_target(env: Env, value: str, tid: str) -> list[Any]:
    ids = await add_nodes(env.worker, 3)
    async with env.worker() as s:
        await s.execute(
            text(
                "INSERT INTO targets (id, kind, value, state, confirmed_day, first_day, last_day) "
                "VALUES (:i, 'ip', :v, 'confirmed', :d, :d, :d)"
            ),
            {"i": tid, "v": value, "d": TODAY},
        )
        for n in ids:
            await s.execute(
                text("INSERT INTO target_contributors VALUES (:i, :n)"), {"i": tid, "n": n}
            )
        await s.commit()
    return ids


async def reputations(env: Env) -> list[float]:
    return [float(r[0]) for r in await rows(env, "SELECT reputation FROM nodes")]


@pytest.mark.integration
async def test_each_outcome_and_its_effects(d_env: Env) -> None:
    env = d_env
    ids = await seed_target(env, BOTS, "t_000000000001")
    before = await reputations(env)
    await add_entry(env, BOTS, target_id="t_000000000001")
    await add_entry(env, OTHER)
    await add_entry(env, "192.0.2.12")
    await add_entry(env, "192.0.2.13")
    request_ids = {}
    for v in (BOTS, OTHER, "192.0.2.12", "192.0.2.13"):
        request_ids[v] = (await ask(env, v)).json()["id"]

    code, lines = await cli(env, "delist", "list")
    assert code == 0 and len(lines) == 4
    code, lines = await cli(env, "delist", "show", request_ids[BOTS])
    assert code == 0 and any(x.startswith("value: " + BOTS) for x in lines)

    # remediated: allowed 90 days, target untouched, no penalty.
    assert (
        await cli(
            env, "delist", "accept", request_ids[OTHER], "--as", "remediated", "--note", "fixed"
        )
    )[0] == 0
    assert await reputations(env) == before
    allow = {r.value: r for r in await rows(env, "SELECT * FROM feed_allow")}
    assert allow[OTHER].reason == "remediated" and allow[OTHER].source == "delist"
    assert allow[OTHER].expires_day == TODAY + timedelta(days=90)

    # policy: allowed for good and added to the never-list.
    assert (
        await cli(
            env,
            "delist",
            "accept",
            request_ids["192.0.2.12"],
            "--as",
            "policy",
            "--note",
            "resolver",
        )
    )[0] == 0
    allow = {r.value: r for r in await rows(env, "SELECT * FROM feed_allow")}
    assert allow["192.0.2.12"].reason == "policy" and allow["192.0.2.12"].expires_day is None
    assert [r.value for r in await rows(env, "SELECT value FROM never_list")] == ["192.0.2.12"]
    assert await reputations(env) == before

    # false_positive: the target is disputed and live contributors lose 0.1.
    assert (
        await cli(
            env,
            "delist",
            "accept",
            request_ids[BOTS],
            "--as",
            "false_positive",
            "--note",
            "spoofed",
        )
    )[0] == 0
    target = await rows(env, "SELECT state FROM targets WHERE id = 't_000000000001'")
    assert target[0].state == "disputed"
    after = await reputations(env)
    assert len(after) == len(ids) and all(
        abs(a - (b - 0.1)) < 1e-4 for a, b in zip(after, before, strict=True)
    )
    allow = {r.value: r for r in await rows(env, "SELECT * FROM feed_allow")}
    assert allow[BOTS].reason == "false_positive" and allow[BOTS].expires_day is None

    # rejected: nothing changes except the request.
    assert (
        await cli(
            env, "delist", "reject", request_ids["192.0.2.13"], "--note", "still serving malware"
        )
    )[0] == 0
    assert "192.0.2.13" not in {r.value for r in await rows(env, "SELECT value FROM feed_allow")}
    assert await reputations(env) == after

    done = {r.id: r for r in await rows(env, "SELECT * FROM delist_requests")}
    assert {r.outcome for r in done.values()} == {
        "remediated",
        "policy",
        "false_positive",
        "rejected",
    }
    assert done[request_ids["192.0.2.13"]].state == "rejected"
    assert done[request_ids["192.0.2.13"]].public_note == "still serving malware"
    assert all(r.decided_day == TODAY for r in done.values())
    # A decided request cannot be decided again; the requester sees the outcome with the token.
    assert (await cli(env, "delist", "reject", request_ids[BOTS], "--note", "x"))[0] == 1
    audit = await rows(
        env, "SELECT actor, action, detail::text AS detail FROM hub_audit ORDER BY id"
    )
    assert [a.action for a in audit] == ["delist.accept"] * 3 + ["delist.reject"]
    assert all(a.actor == "tester" for a in audit)
    assert not any(v in a.detail for a in audit for v in (BOTS, OTHER))


@pytest.mark.integration
async def test_false_positive_penalty_only_for_live_links(d_env: Env) -> None:
    env = d_env
    await seed_target(env, BOTS, "t_000000000001")
    before = await reputations(env)
    await add_entry(env, BOTS, target_id="t_000000000001")
    request = (await ask(env, BOTS)).json()["id"]
    async with env.worker() as s:  # the links were dropped by retention (30 days)
        await s.execute(text("DELETE FROM target_contributors"))
        await s.commit()
    await cli(env, "delist", "accept", request, "--as", "false_positive", "--note", "x")
    assert await reputations(env) == before


@pytest.mark.integration
async def test_evidence_and_contact_are_nulled_after_the_decision(d_env: Env) -> None:
    from hub import retention

    env = d_env
    await add_entry(env, BOTS)
    request = (await ask(env, BOTS, evidence="details", contact="ops@example.org")).json()["id"]
    await cli(env, "delist", "accept", request, "--as", "remediated", "--note", "ok")
    async with env.worker() as s:
        later = TODAY + timedelta(days=DELIST_EVIDENCE_DAYS + 1)
        await retention.run_retention(s, env.settings, env.clock() + timedelta(days=31), later)
    row = (await rows(env, "SELECT evidence, contact, state FROM delist_requests"))[0]
    assert (row.evidence, row.contact, row.state) == (None, None, "accepted")


@pytest.mark.integration
async def test_allow_commands(d_env: Env) -> None:
    env = d_env
    assert (
        await cli(env, "allow", "add", "198.51.100.0/24", "--reason", "shared_infra", "--note", "n")
    )[0] == 0
    assert (await cli(env, "allow", "add", "198.51.100.77", "--reason", "remediated"))[0] == 0
    assert (
        await cli(env, "allow", "add", "Example.ORG", "--reason", "owner_request", "--expires", "5")
    )[0] == 0
    assert (await cli(env, "allow", "add", "nonsense value", "--reason", "policy"))[0] == 1
    allow = {r.value: r for r in await rows(env, "SELECT * FROM feed_allow")}
    assert (
        allow["198.51.100.0/24"].expires_day is None and allow["198.51.100.0/24"].source == "admin"
    )
    assert allow["198.51.100.77"].expires_day == TODAY + timedelta(days=90)
    assert allow["example.org"].expires_day == TODAY + timedelta(days=5)
    code, lines = await cli(env, "allow", "list")
    assert code == 0 and len(lines) == 3
    assert (await cli(env, "allow", "remove", "198.51.100.77"))[0] == 0
    assert (await cli(env, "allow", "remove", "198.51.100.77"))[0] == 1
    audit = await rows(env, "SELECT action, detail::text AS d FROM hub_audit ORDER BY id")
    assert [a.action for a in audit if a.action.startswith("allow")] == ["allow.add"] * 3 + [
        "allow.remove"
    ] * 2
    assert not any("198.51.100" in a.d for a in audit)


@pytest.mark.integration
async def test_feeds_commands(d_env: Env) -> None:
    env = d_env
    code, lines = await cli(env, "feeds", "status")
    assert code == 0 and lines[0] == "paused: False"
    assert (await cli(env, "feeds", "pause"))[0] == 0
    assert (await cli(env, "feeds", "status"))[1][0] == "paused: True"
    assert (await cli(env, "feeds", "resume"))[0] == 0
    assert (await cli(env, "feeds", "release", "7"))[0] == 1  # nothing held
    assert (await cli(env, "feeds", "discard", "7"))[0] == 1
    assert (await cli(env, "feeds", "diff", "7"))[0] == 1
    assert (await cli(env, "ranges", "status"))[0] == 0
    audit = await rows(env, "SELECT action FROM hub_audit ORDER BY id")
    assert [a.action for a in audit] == ["feeds.pause", "feeds.resume"]


# --- keys, files and privacy --------------------------------------------------------------------


async def test_gen_feed_key_writes_a_private_minisign_key(tmp_path: Path) -> None:
    out: list[str] = []
    path = tmp_path / "feed.key"
    assert await admin.run(["gen-feed-key", "--out", str(path)], out=out.append) == 0
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    secret = minisign.parse_secret_key(path.read_text(encoding="ascii"))
    assert out[0] == f"feed_public_key={secret.public.encoded}"
    printed = "\n".join(out)
    assert secret.seed.hex() not in printed
    assert path.read_text().splitlines()[1] not in printed
    # Refuses to overwrite; --force replaces it.
    assert await admin.run(["gen-feed-key", "--out", str(path)], out=out.append) == 1
    assert await admin.run(["gen-feed-key", "--out", str(path), "--force"], out=out.append) == 0
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert minisign.parse_secret_key(path.read_text(encoding="ascii")).seed != secret.seed


def test_delist_page_is_static_and_self_contained() -> None:
    page = (HERE / "static" / "delist.html").read_text()
    import re

    assert not re.search(r"(src|href|action)\s*=\s*[\"']?(https?:)?//", page)
    assert "<link" not in page and "@import" not in page and "url(" not in page
    assert page.count("<script") == 1 and "<script src" not in page
    assert " on" not in re.sub(r"[^<]*", "", page)  # no inline handlers: tags below carry none
    assert not re.search(r"<[^>]+\son\w+\s*=", page)
    assert not re.search(r"<[^>]+\sstyle\s*=", page)


def test_readme_template_covers_the_required_topics() -> None:
    text_ = (HERE / "static" / "README.txt.tmpl").read_text()
    for needle in (
        "CC0 1.0",
        "minisign -V",
        "@FEEDS_DOMAIN@",
        "delist.html",
        "72 hours",
        "@FEED_PUBLIC_KEY@",
    ):
        assert needle in text_
    assert all(len(line) <= 100 for line in text_.splitlines())
    import re

    assert not re.search(r"\b(?!192\.0\.2|198\.51\.100|203\.0\.113)\d{1,3}(\.\d{1,3}){3}\b", text_)


def test_delist_routes_never_touch_the_client_address() -> None:
    for name in ("delist.py", "lookup.py"):
        src = (HERE / "hub" / "routes" / name).read_text()
        assert "request.client" not in src and "x-forwarded" not in src.lower()
        assert "logging" not in src and "log." not in src

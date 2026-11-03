"""abuse.ch submissions: bodies, client, selection, review and auto modes, caps, CLI."""

from __future__ import annotations

import json
import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import text

from hub import abusech, admin
from hub.config import ConfigError, Settings
from hub.never import Never

from .conftest import Env
from .seed import TODAY, add_nodes, observe, shipped_ranges

D1, D2 = TODAY - timedelta(days=2), TODAY - timedelta(days=1)
KEY = "test-auth-key-not-a-secret"  # placeholder
URL_PAGE = "http://198.51.100.20/index.html"
URL_BIN = "http://198.51.100.21/bins/arm7"
URL_FAMILY = "http://198.51.100.22/payload"
C2 = "203.0.113.50:23"


# ---------------------------------------------------------------- pure unit tests


def test_settings_default_off_and_key_required() -> None:
    s = Settings.from_env({})
    assert s.abusech_mode == "off" and s.abusech_daily_cap == 50 and not s.abusech_active
    assert not Settings.from_env({"HUB_ABUSECH_MODE": "review"}).abusech_active  # no key
    assert Settings.from_env(
        {"HUB_ABUSECH_MODE": "review", "HUB_ABUSECH_AUTH_KEY": KEY}
    ).abusech_active
    assert KEY not in repr(Settings.from_env({"HUB_ABUSECH_AUTH_KEY": KEY}))
    with pytest.raises(ConfigError):
        Settings.from_env({"HUB_ABUSECH_MODE": "yes"})


def test_bodies_hold_only_the_public_indicator() -> None:
    tags = abusech.tags_for(["mirai"], ["elf-arm"])
    assert tags == ["mirai", "elf", "arm"]
    uh = json.loads(abusech.urlhaus_body(URL_BIN, tags))
    assert uh == {
        "anonymous": "1",
        "submission": [{"url": URL_BIN, "threat": "malware_download", "tags": tags}],
    }
    tf = json.loads(abusech.threatfox_body(C2, "elf.mirai", tags))
    assert tf["iocs"] == [C2] and tf["anonymous"] == 1 and tf["malware"] == "elf.mirai"
    assert set(tf) == {
        "query", "threat_type", "ioc_type", "malware", "confidence_level",
        "anonymous", "tags", "iocs",
    }  # fmt: skip


def test_bad_tags_and_inputs_are_refused() -> None:
    with pytest.raises(ValueError):
        abusech.urlhaus_body(URL_BIN, ["Not Valid"])
    with pytest.raises(ValueError):
        abusech.urlhaus_body("x" * 2000, [])
    with pytest.raises(ValueError):
        abusech.threatfox_body(C2, "bad name!", [])
    assert len(abusech.tags_for(["a"] * 3 + ["b", "c", "d", "e", "f"], ["elf-arm"])) <= 5


def test_classify_answer_is_constant() -> None:
    c = abusech.classify_answer
    assert c(200, {"query_status": "ok"}) == abusech.INSERTED
    assert c(200, {"query_status": "url_already_known"}) == abusech.ALREADY_KNOWN
    assert c(200, {"query_status": "unauthorized"}) == abusech.AUTH_FAILED
    assert c(401, None) == abusech.AUTH_FAILED
    assert c(429, None) == abusech.RATE_LIMITED
    assert c(500, None) == abusech.HTTP_ERROR
    assert c(200, {"query_status": "illegal_ioc"}) == abusech.INVALID
    assert c(200, {"something": "else"}) == abusech.UNKNOWN_OUTCOME
    assert c(200, {"query_status": "ok"}) in abusech.CODES


def test_refusals() -> None:
    assert abusech.url_refusal("http://198.51.100.9/x") == "private"
    assert abusech.url_refusal("http://198.51.100.9/x", allow_documentation=True) is None
    assert abusech.url_refusal("ftp://malware.example.org/x") == "scheme"
    assert abusech.url_refusal("http://malware.example.org/x") is None
    assert abusech.url_refusal("http://localhost/x") == "host"
    assert abusech.c2_refusal("[fd00::1]:23") == "private"
    assert abusech.c2_refusal("203.0.113.5:0", allow_documentation=True) == "port"


async def _client(handler: Any) -> abusech.AbusechClient:
    return abusech.AbusechClient(
        httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    )


async def test_client_sends_key_header_only_and_caps_the_answer() -> None:
    seen: list[httpx.Request] = []

    def ok(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"query_status": "ok"})

    client = await _client(ok)
    body = abusech.urlhaus_body(URL_BIN, ["elf"])
    assert await client.submit("urlhaus", body, KEY) == abusech.INSERTED
    assert seen[0].headers["Auth-Key"] == KEY and KEY.encode() not in seen[0].content
    assert str(seen[0].url) == abusech.URLHAUS_API
    await client.aclose()

    big = await _client(lambda r: httpx.Response(200, content=b"x" * (abusech.MAX_BODY + 1)))
    assert await big.submit("urlhaus", body, KEY) == abusech.UNKNOWN_OUTCOME
    await big.aclose()

    # a redirect is never followed
    hits: list[str] = []

    def redirect(request: httpx.Request) -> httpx.Response:
        hits.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://elsewhere.example.org/"})

    red = await _client(redirect)
    assert await red.submit("threatfox", body, KEY) == abusech.HTTP_ERROR
    assert hits == [abusech.THREATFOX_API]
    await red.aclose()

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route")

    dead = await _client(down)
    assert await dead.submit("urlhaus", body, KEY) == abusech.HTTP_ERROR
    await dead.aclose()


# ---------------------------------------------------------------- integration


def active(env: Env, **over: Any) -> Settings:
    return replace(env.settings, abusech_mode="review", abusech_auth_key=KEY, **over)


async def _seed(env: Env) -> None:
    nodes = await add_nodes(
        env.worker, 10, enrolled=[TODAY - timedelta(days=20 + 7 * i) for i in range(10)]
    )
    await shipped_ranges(env.worker)
    async with env.worker() as s:
        for i, (url, fam) in enumerate([(URL_PAGE, []), (URL_BIN, []), (URL_FAMILY, ["mirai"])]):
            h = f"{i + 1:02x}" * 32
            await s.execute(
                text(
                    "INSERT INTO targets (id, kind, value, value_b, state, families) "
                    "VALUES (:id, 'url', :v, :h, 'confirmed', :f)"
                ),
                {"id": f"t_url{i}", "v": url, "h": h, "f": fam},
            )
        await s.execute(
            text(
                "INSERT INTO targets (id, kind, value, state, families) VALUES "
                "('t_c2a', 'c2_ip', :v, 'confirmed', ARRAY['mirai']), "
                "('t_c2b', 'c2_ip', '203.0.113.51:23', 'confirmed', ARRAY['generic'])"
            ),
            {"v": C2},
        )
        await s.commit()
    # An ordinary page, a binary, and a url with a family but no file type.
    await observe(env.worker, nodes, "url", "01" * 32, [D1], fetched=True, file_type="other")
    await observe(env.worker, nodes, "url", "02" * 32, [D1], fetched=True, file_type="elf-arm")
    await observe(env.worker, nodes, "url", "03" * 32, [D1], fetched=True, families=["mirai"])


async def _rows(env: Env) -> dict[str, Any]:
    async with env.worker() as s:
        rows = (
            await s.execute(
                text(
                    "SELECT indicator, kind, state, approved_by, tags, malware FROM "
                    "abusech_submissions ORDER BY id"
                )
            )
        ).all()
    return {r.indicator: r for r in rows}


@pytest.mark.integration
async def test_only_executables_or_families_and_malpedia_c2_are_queued(env: Env) -> None:
    await _seed(env)
    s = active(env)
    async with env.worker() as ses:
        res = await abusech.queue_submissions(ses, s, TODAY, never=Never())
        again = await abusech.queue_submissions(ses, s, TODAY, never=Never())
    rows = await _rows(env)
    assert set(rows) == {URL_BIN, URL_FAMILY, C2}  # not the ordinary page, not the generic c2
    assert res.queued == 3 and again.queued == 0  # submitted once
    assert rows[URL_BIN].tags == ["elf", "arm"] and rows[URL_BIN].state == "queued"
    assert rows[C2].malware == "elf.mirai" and rows[C2].kind == "threatfox"


@pytest.mark.integration
async def test_one_fetching_node_is_not_enough(env: Env) -> None:
    await _seed(env)
    async with env.worker() as ses:
        await ses.execute(
            text(
                "DELETE FROM observations WHERE value = :h AND node_id <> "
                "(SELECT node_id FROM observations WHERE value = :h LIMIT 1)"
            ),
            {"h": "02" * 32},
        )
        await ses.commit()
        await abusech.queue_submissions(ses, active(env), TODAY, never=Never())
    assert URL_BIN not in await _rows(env)


@pytest.mark.integration
async def test_off_or_no_key_queues_nothing(env: Env) -> None:
    await _seed(env)
    async with env.worker() as ses:
        for s in (
            env.settings,
            replace(env.settings, abusech_mode="review"),
            replace(env.settings, abusech_auth_key=KEY),
        ):
            assert (await abusech.queue_submissions(ses, s, TODAY, never=Never())).queued == 0
    assert await _rows(env) == {}


@pytest.mark.integration
async def test_never_list_blocks_queueing_and_sending(env: Env) -> None:
    await _seed(env)
    s = active(env)
    blocked = Never.from_rows([("198.51.100.0/24", "ip")])
    async with env.worker() as ses:
        res = await abusech.queue_submissions(ses, s, TODAY, never=blocked)
    assert URL_BIN not in await _rows(env) and res.skipped["never_list"] == 2
    async with env.worker() as ses:
        await abusech.queue_submissions(ses, s, TODAY, never=Never())
        await ses.execute(
            text(
                "UPDATE abusech_submissions SET state='approved', approved_by='op', approved_manually=true"
            )
        )
        await ses.commit()

        async def boom(kind: str, body: bytes, key: str) -> str:
            raise AssertionError("nothing may be sent")

        out = await abusech.send_due(
            ses,
            s,
            datetime(2026, 11, 1, 12, tzinfo=UTC),
            boom,
            never=Never.from_rows([("198.51.100.0/24", "ip"), ("203.0.113.0/24", "ip")]),
        )
    assert out.rejected == 3 and out.sent == 0


@pytest.mark.integration
async def test_review_mode_never_sends_unapproved_and_sent_has_no_node_data(env: Env) -> None:
    await _seed(env)
    s = active(env)
    sent: list[tuple[str, bytes, str]] = []

    async def submit(kind: str, body: bytes, key: str) -> str:
        sent.append((kind, body, key))
        return abusech.INSERTED

    now = datetime(2026, 11, 1, 12, tzinfo=UTC)
    async with env.worker() as ses:
        await abusech.queue_submissions(ses, s, TODAY, never=Never())
        assert await abusech.auto_approve(ses, s, TODAY + timedelta(days=5)) == 0  # review
        out = await abusech.send_due(ses, s, now, submit, never=Never())
        assert out.sent == 0 and sent == []
        await ses.execute(
            text(
                "UPDATE abusech_submissions SET state='approved', approved_by='op', approved_manually=true "
                "WHERE indicator = :i"
            ),
            {"i": URL_BIN},
        )
        await ses.commit()
        out = await abusech.send_due(ses, s, now, submit, never=Never())
    assert out.sent == 1 and len(sent) == 1
    kind, body, key = sent[0]
    assert kind == "urlhaus" and key == KEY and KEY.encode() not in body
    # no node data: no uuid, no pseudonym, no counts, only the indicator and tags
    payload = json.loads(body)
    assert payload["submission"][0]["url"] == URL_BIN
    assert not re.search(rb"[0-9a-f]{8}-[0-9a-f]{4}", body)
    for word in (b"node", b"pseudonym", b"count", b"fingerprint", b"selfhostr", b"suckerpot"):
        assert word not in body.lower()
    row = (await _rows(env))[URL_BIN]
    assert row.state == "sent"
    async with env.worker() as ses:
        code = (
            await ses.execute(
                text("SELECT result_code, sent_at FROM abusech_submissions WHERE indicator = :i"),
                {"i": URL_BIN},
            )
        ).one()
    assert code.result_code == "inserted" and code.sent_at is not None


@pytest.mark.integration
async def test_auto_mode_approves_urlhaus_after_hold_but_never_threatfox(env: Env) -> None:
    await _seed(env)
    s = active(env, report_hold_hours=0)
    s = replace(s, abusech_mode="auto")
    async with env.worker() as ses:
        await abusech.queue_submissions(ses, s, TODAY, never=Never())
        assert await abusech.auto_approve(ses, replace(s, auto_min_cohorts=11), TODAY) == 0
        assert await abusech.auto_approve(ses, s, TODAY) == 2
    rows = await _rows(env)
    assert rows[URL_BIN].state == "approved" and rows[URL_BIN].approved_by == "auto"
    assert rows[C2].state == "queued"
    # even if a threatfox row is forced to approved by 'auto', the sender refuses it
    async with env.worker() as ses:
        await ses.execute(
            text(
                "UPDATE abusech_submissions SET state='approved', "
                "approved_by='op', approved_manually=false WHERE kind='threatfox'"
            )
        )
        await ses.commit()
        calls: list[str] = []

        async def submit(kind: str, body: bytes, key: str) -> str:
            calls.append(kind)
            return abusech.ALREADY_KNOWN

        out = await abusech.send_due(
            ses, s, datetime(2026, 11, 1, 12, tzinfo=UTC), submit, never=Never()
        )
    assert "threatfox" not in calls and out.failed == 1 and out.sent == 2


@pytest.mark.integration
async def test_daily_cap_and_transient_errors(env: Env) -> None:
    await _seed(env)
    s = active(env, abusech_daily_cap=1)
    now = datetime(2026, 11, 1, 12, tzinfo=UTC)
    async with env.worker() as ses:
        await abusech.queue_submissions(ses, s, TODAY, never=Never())
        await ses.execute(
            text(
                "UPDATE abusech_submissions SET state='approved', approved_by='op', approved_manually=true"
            )
        )
        await ses.commit()
        replies = iter([abusech.INSERTED, abusech.INSERTED, abusech.INSERTED])

        async def submit(kind: str, body: bytes, key: str) -> str:
            return next(replies)

        out = await abusech.send_due(ses, s, now, submit, never=Never())
        assert out.sent == 1 and out.deferred["daily_cap"] == 2

        # next day: a transient error keeps the rest approved and stops the cycle
        async def limited(kind: str, body: bytes, key: str) -> str:
            return abusech.RATE_LIMITED

        later = now + timedelta(days=1)
        out = await abusech.send_due(ses, s, later, limited, never=Never())
    assert out.sent == 0 and out.deferred["rate_limited"] == 2
    states = sorted(r.state for r in (await _rows(env)).values())
    assert states == ["approved", "approved", "sent"]


@pytest.mark.integration
async def test_cli_list_approve_reject_and_reports_marker(env: Env) -> None:
    await _seed(env)
    async with env.worker() as ses:
        await abusech.queue_submissions(ses, active(env), TODAY, never=Never())
        await ses.execute(
            text(
                "INSERT INTO reports (recipient, kind, target_ids, state, body_text, "
                "created_day) VALUES ('a@example.net', 'malware_host', ARRAY['t_url1'], "
                "'queued', 'Subject: s\n\nbody', :d)"
            ),
            {"d": TODAY},
        )
        await ses.commit()
    lines: list[str] = []

    async def cli(*argv: str) -> int:
        return await admin.run(list(argv), sessionmaker=env.worker, out=lines.append, actor="op")

    assert await cli("abusech", "list", "--state", "queued") == 0
    assert sum(URL_BIN in line for line in lines) == 1 and len(lines) == 3
    lines.clear()
    assert await cli("reports", "list") == 0 and "abuse.ch: 1" in lines[0]
    assert await cli("abusech", "approve", "1") == 0
    assert await cli("abusech", "approve", "1") == 1  # no longer queued
    assert await cli("abusech", "reject", "2") == 0
    assert await cli("abusech", "reject", "2") == 1
    assert await cli("abusech", "approve", "99") == 1
    states = [r.state for r in (await _rows(env)).values()]
    assert sorted(states) == ["approved", "queued", "rejected"]
    async with env.worker() as ses:
        n = (
            await ses.execute(text("SELECT count(*) FROM hub_audit WHERE action LIKE 'abusech.%'"))
        ).scalar_one()
    assert n == 2


# ---------------------------------------------------------------- security review fixes


def test_numeric_and_local_hosts_are_refused() -> None:
    for url in (
        "http://127.1/x",
        "http://0x7f.1/x",
        "http://2130706433/x",
        "http://0177.0.0.1/x",
        "http://intranet/x",
        "http://printer.local/x",
        "http://db.internal/x",
        "http://nas.lan/x",
        "http://app.localhost/x",
        "http://router.home.arpa/x",
    ):
        assert abusech.url_refusal(url) is not None, url
    assert abusech.url_refusal("http://bad.cafe/x") is None  # hex-looking letters are fine


@pytest.mark.integration
async def test_html_fetched_twice_and_a_third_claim_of_elf_queue_nothing(env: Env) -> None:
    nodes = await add_nodes(
        env.worker, 10, enrolled=[TODAY - timedelta(days=20 + 7 * i) for i in range(10)]
    )
    h = "0a" * 32
    async with env.worker() as ses:
        await ses.execute(
            text(
                "INSERT INTO targets (id, kind, value, value_b, state, families) VALUES "
                "('t_mix', 'url', 'http://198.51.100.30/a', :h, 'confirmed', ARRAY['mirai'])"
            ),
            {"h": h},
        )
        await ses.commit()
    await observe(env.worker, nodes[:2], "url", h, [D1], fetched=True, file_type="other")
    await observe(env.worker, nodes[2:3], "url", h, [D1], fetched=True, file_type="elf-arm")
    await shipped_ranges(env.worker)
    async with env.worker() as ses:
        await abusech.queue_submissions(ses, active(env), TODAY, never=Never())
    assert await _rows(env) == {}
    # a second node that really fetched an executable makes two
    await observe(env.worker, nodes[3:4], "url", h, [D1], fetched=True, file_type="elf-arm")
    async with env.worker() as ses:
        await abusech.queue_submissions(ses, active(env), TODAY, never=Never())
    assert set(await _rows(env)) == {"http://198.51.100.30/a"}


@pytest.mark.integration
async def test_tags_come_from_qualifying_rows_not_the_target(env: Env) -> None:
    await _seed(env)
    async with env.worker() as ses:
        await ses.execute(text("UPDATE targets SET families = ARRAY['xmrig'] WHERE id = 't_url1'"))
        await ses.commit()
        await abusech.queue_submissions(ses, active(env), TODAY, never=Never())
    assert "xmrig" not in (await _rows(env))[URL_BIN].tags


async def _approve_all(env: Env) -> None:
    async with env.worker() as ses:
        await ses.execute(
            text(
                "UPDATE abusech_submissions SET state='approved', approved_by='op', "
                "approved_manually=true"
            )
        )
        await ses.commit()


async def _send(env: Env, s: Settings) -> abusech.SendResult:
    sent: list[str] = []

    async def submit(kind: str, body: bytes, key: str) -> str:
        sent.append(kind)
        return abusech.INSERTED

    async with env.worker() as ses:
        return await abusech.send_due(
            ses, s, datetime(2026, 11, 1, 12, tzinfo=UTC), submit, never=Never()
        )


@pytest.mark.integration
async def test_a_target_that_is_no_longer_live_is_rejected_before_sending(env: Env) -> None:
    await _seed(env)
    s = active(env)
    async with env.worker() as ses:
        await abusech.queue_submissions(ses, s, TODAY, never=Never())
    await _approve_all(env)
    async with env.worker() as ses:
        await ses.execute(text("UPDATE targets SET state = 'disputed' WHERE id = 't_url1'"))
        await ses.execute(text("DELETE FROM targets WHERE id = 't_c2a'"))
        await ses.commit()
    out = await _send(env, s)
    rows = await _rows(env)
    assert out.sent == 1 and out.rejected == 2
    assert rows[URL_BIN].state == "rejected" and rows[C2].state == "rejected"
    assert rows[URL_FAMILY].state == "sent"


@pytest.mark.integration
async def test_auto_approve_skips_targets_that_are_not_live(env: Env) -> None:
    await _seed(env)
    s = replace(active(env, report_hold_hours=0), abusech_mode="auto")
    async with env.worker() as ses:
        await abusech.queue_submissions(ses, s, TODAY, never=Never())
        await ses.execute(text("UPDATE targets SET state = 'disputed' WHERE id = 't_url1'"))
        await ses.commit()
        assert await abusech.auto_approve(ses, s, TODAY) == 1
    assert (await _rows(env))[URL_BIN].state == "queued"


@pytest.mark.integration
async def test_allow_list_row_stops_a_queued_submission(env: Env) -> None:
    await _seed(env)
    s = active(env)
    async with env.worker() as ses:
        await abusech.queue_submissions(ses, s, TODAY, never=Never())
    await _approve_all(env)
    async with env.worker() as ses:
        await ses.execute(
            text(
                "INSERT INTO feed_allow (value, kind, reason, added_day, source) "
                "VALUES ('198.51.100.21', 'ip', 'policy', :d, 'admin')"
            ),
            {"d": TODAY},
        )
        await ses.commit()
    out = await _send(env, s)
    rows = await _rows(env)
    assert rows[URL_BIN].state == "rejected" and out.sent == 2


@pytest.mark.integration
async def test_dispute_and_delist_accept_withdraw_matching_submissions(env: Env) -> None:
    await _seed(env)
    async with env.worker() as ses:
        await abusech.queue_submissions(ses, active(env), TODAY, never=Never())
    lines: list[str] = []

    async def cli(*argv: str) -> int:
        return await admin.run(list(argv), sessionmaker=env.worker, out=lines.append, actor="op")

    assert await cli("target", "dispute", "t_url1", "--note", "wrong") == 0
    rows = await _rows(env)
    assert rows[URL_BIN].state == "rejected" and rows[URL_FAMILY].state == "queued"
    async with env.worker() as ses:
        await ses.execute(
            text(
                "INSERT INTO delist_requests (id, token_hash, value, category, state, "
                "created_day) VALUES ('r1', 'x', '198.51.100.22', 'other', 'received', :d)"
            ),
            {"d": TODAY},
        )
        await ses.commit()
    assert await cli("delist", "accept", "r1", "--as", "remediated", "--note", "fixed") == 0
    rows = await _rows(env)
    assert rows[URL_FAMILY].state == "rejected" and rows[C2].state == "queued"


@pytest.mark.integration
async def test_threatfox_waits_when_the_ranges_are_stale(env: Env) -> None:
    await _seed(env)
    s = active(env)
    async with env.worker() as ses:
        await ses.execute(text("DELETE FROM feed_auto_ranges"))
        await ses.commit()
        res = await abusech.queue_submissions(ses, s, TODAY, never=Never())
    assert C2 not in await _rows(env) and res.skipped["ranges_stale"] == 1
    await shipped_ranges(env.worker)
    async with env.worker() as ses:
        await abusech.queue_submissions(ses, s, TODAY, never=Never())
    await _approve_all(env)
    async with env.worker() as ses:
        await ses.execute(text("DELETE FROM feed_auto_ranges"))
        await ses.commit()
    out = await _send(env, s)
    assert out.deferred["ranges_stale"] == 1 and out.sent == 2
    assert (await _rows(env))[C2].state == "approved"


@pytest.mark.integration
async def test_threatfox_in_a_cdn_range_is_never_queued(env: Env) -> None:
    await _seed(env)
    async with env.worker() as ses:
        await ses.execute(
            text(
                "INSERT INTO feed_auto_ranges (source, prefix, fetched_day) "
                "VALUES ('cdn:test', '203.0.113.0/24', :d)"
            ),
            {"d": TODAY},
        )
        await ses.commit()
        await abusech.queue_submissions(ses, active(env), TODAY, never=Never())
    assert C2 not in await _rows(env)


@pytest.mark.integration
async def test_threatfox_guard_reads_the_flag_not_the_actor_name(env: Env) -> None:
    await _seed(env)
    s = active(env)
    async with env.worker() as ses:
        await abusech.queue_submissions(ses, s, TODAY, never=Never())
        await ses.execute(
            text(
                "UPDATE abusech_submissions SET state='approved', approved_by='alice', "
                "approved_manually=false WHERE kind='threatfox'"
            )
        )
        await ses.commit()
    out = await _send(env, s)
    assert out.failed == 1
    assert (await _rows(env))[C2].state == "failed"


@pytest.mark.integration
async def test_an_inbound_only_delisting_does_not_block_submissions(env: Env) -> None:
    await _seed(env)
    s = active(env)
    async with env.worker() as ses:
        await ses.execute(
            text(
                "INSERT INTO feed_allow (value, kind, reason, added_day, source, list) "
                "VALUES ('198.51.100.21', 'ip', 'false_positive', :d, 'delist', 'inbound')"
            ),
            {"d": TODAY},
        )
        await ses.commit()
        await abusech.queue_submissions(ses, s, TODAY, never=Never())
    assert URL_BIN in await _rows(env)
    async with env.worker() as ses:
        await ses.execute(text("UPDATE feed_allow SET list = 'outbound'"))
        await ses.execute(text("DELETE FROM abusech_submissions"))
        await ses.commit()
        await abusech.queue_submissions(ses, s, TODAY, never=Never())
    assert URL_BIN not in await _rows(env)

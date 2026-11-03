"""abuse.ch path B (basis ``verified``): two eligible reporters plus a verifier attestation."""

from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from suckerpot_netproto import blind

from hub import abusech
from hub.config import Settings
from hub.never import Never

from .conftest import Env
from .seed import TODAY, add_nodes, observe, shipped_ranges

D1 = TODAY - timedelta(days=2)
KEY = "test-auth-key-not-a-secret"  # placeholder
URL = "http://198.51.100.40/bins/arm7"
HASH = blind.blind("url", URL)
NOW = datetime(2026, 11, 1, 12, tzinfo=UTC)
# Distinct enrolment weeks: ten cohorts.
WEEKS = [TODAY - timedelta(days=20 + 7 * i) for i in range(10)]


def active(env: Env, **over: Any) -> Settings:
    return replace(env.settings, abusech_mode="review", abusech_auth_key=KEY, **over)


async def seed(
    env: Env,
    *,
    reporters: int = 2,
    enrolled: list[date] | None = None,
    role: bool = True,
    like: bool = True,
    task_state: str = "attested",
    target_state: str = "candidate",
    url: str = URL,
) -> list[uuid.UUID]:
    """Ten eligible nodes (the last one is the verifier), a candidate target, an attested task."""
    nodes = await add_nodes(env.worker, 10, enrolled=enrolled or WEEKS)
    await shipped_ranges(env.worker)
    verifier = nodes[-1]
    reporting = nodes[:reporters]
    h = blind.blind("url", url)
    async with env.worker() as s:
        await s.execute(
            text("INSERT INTO targets (id, kind, value_b, state) VALUES ('t_b1', 'url', :h, :st)"),
            {"h": h, "st": target_state},
        )
        await s.execute(
            text(
                "INSERT INTO verify_tasks (id, url_b, url, site, state, reporters, "
                "reporter_cohorts, last_report_day, created_day, revealed_day, ended_day) "
                "VALUES ('v_000000000001', :h, :u, '198.51.100.40', :st, 2, 2, :d, :d, :d, :d)"
            ),
            {"h": h, "u": url, "st": task_state, "d": D1},
        )
        await s.execute(
            text(
                "INSERT INTO verify_attestations (task_id, node_id, day, outcome, file_type, "
                "family, malware_like) VALUES ('v_000000000001', :n, :d, 'fetched', "
                "'elf-arm', 'mirai', :m)"
            ),
            {"n": verifier, "d": TODAY, "m": like},
        )
        if role:
            await s.execute(
                text(
                    "INSERT INTO node_roles (node_id, role, granted_day) VALUES (:n, 'verifier', :d)"
                ),
                {"n": verifier, "d": D1},
            )
        await s.commit()
    if reporters:
        await observe(env.worker, reporting, "url", h, [D1])
    return nodes


async def rows(env: Env) -> list[Any]:
    async with env.worker() as s:
        return list(
            (
                await s.execute(
                    text(
                        "SELECT id, indicator, state, basis, verify_task_id, tags, target_id, "
                        "approved_by, result_code FROM abusech_submissions ORDER BY id"
                    )
                )
            ).all()
        )


async def queue(env: Env, s: Settings, never: Never | None = None) -> abusech.QueueResult:
    async with env.worker() as ses:
        return await abusech.queue_submissions(ses, s, TODAY, never=never or Never())


async def approve_all(env: Env) -> None:
    async with env.worker() as s:
        await s.execute(
            text(
                "UPDATE abusech_submissions SET state='approved', approved_by='op', "
                "approved_manually=true"
            )
        )
        await s.commit()


async def send(env: Env, s: Settings) -> tuple[abusech.SendResult, list[bytes]]:
    sent: list[bytes] = []

    async def submit(kind: str, body: bytes, key: str) -> str:
        sent.append(body)
        return abusech.INSERTED

    async with env.worker() as ses:
        return await abusech.send_due(ses, s, NOW, submit, never=Never()), sent


@pytest.mark.integration
async def test_two_reporters_and_a_malware_like_attestation_queue_a_verified_row(env: Env) -> None:
    await seed(env)
    res = await queue(env, active(env))
    (row,) = await rows(env)
    assert res.queued == 1
    assert (row.indicator, row.state, row.basis) == (URL, "queued", "verified")
    assert row.verify_task_id == "v_000000000001" and row.target_id == "t_b1"
    assert row.tags == ["mirai", "elf", "arm"]
    assert (await queue(env, active(env))).queued == 0  # once only


@pytest.mark.integration
async def test_the_attestation_never_counts_as_a_reporter(env: Env) -> None:
    await seed(env, reporters=1)  # one reporter plus the verifier's attestation
    await queue(env, active(env))
    assert await rows(env) == []
    # but a verifier whose own sensor reported the link is one of the two reporters
    async with env.worker() as s:
        await s.execute(text("DELETE FROM observations"))
        await s.commit()
    async with env.worker() as s:
        verifier = (await s.execute(text("SELECT node_id FROM node_roles"))).scalar_one()
        first = (
            await s.execute(text("SELECT id FROM nodes WHERE id <> :v LIMIT 1"), {"v": verifier})
        ).scalar_one()
    await observe(env.worker, [first, verifier], "url", HASH, [D1])
    await queue(env, active(env))
    assert [r.basis for r in await rows(env)] == ["verified"]


@pytest.mark.integration
async def test_unqualified_tasks_queue_nothing(env: Env) -> None:
    await seed(env, role=False)
    await queue(env, active(env))
    assert await rows(env) == []  # the attester is not a verifier (any more)


@pytest.mark.integration
@pytest.mark.parametrize(
    ("kw"),
    [
        {"like": False},  # a page, not malware-like
        {"task_state": "leased"},
        {"task_state": "refused"},
        {"target_state": "disputed"},
        {"target_state": "taken_down"},
    ],
)
async def test_other_cases_queue_nothing(env: Env, kw: dict[str, Any]) -> None:
    await seed(env, **kw)
    await queue(env, active(env))
    assert await rows(env) == []


@pytest.mark.integration
async def test_an_old_attestation_does_not_qualify(env: Env) -> None:
    await seed(env)
    async with env.worker() as s:
        await s.execute(
            text("UPDATE verify_attestations SET day = :d"), {"d": TODAY - timedelta(days=4)}
        )
        await s.commit()
    await queue(env, active(env))
    assert await rows(env) == []


@pytest.mark.integration
async def test_every_path_a_guard_applies(env: Env) -> None:
    await seed(env)
    s = active(env)
    res = await queue(env, s, Never.from_rows([("198.51.100.0/24", "ip")]))
    assert await rows(env) == [] and res.skipped["never_list"] == 1
    res = await queue(env, replace(s, allow_documentation=False))
    assert await rows(env) == [] and res.skipped.keys() <= {"excluded", "not_public"}
    async with env.worker() as ses:
        await ses.execute(
            text(
                "INSERT INTO feed_allow (value, kind, reason, added_day, source) VALUES ('198.51.100.40', 'ip', 'policy', CURRENT_DATE, 'admin')"
            )
        )
        await ses.commit()
    res = await queue(env, s)
    assert await rows(env) == [] and res.skipped["excluded"] == 1


@pytest.mark.integration
async def test_off_or_no_key_queues_nothing(env: Env) -> None:
    await seed(env)
    for s in (env.settings, replace(env.settings, abusech_mode="review")):
        assert (await queue(env, s)).queued == 0
    assert await rows(env) == []


@pytest.mark.integration
async def test_a_consensus_row_for_the_same_link_wins_and_is_not_duplicated(env: Env) -> None:
    await seed(env)
    async with env.worker() as s:
        await s.execute(
            text(
                "INSERT INTO abusech_submissions (kind, target_id, indicator, tags, state, "
                "created_day) VALUES ('urlhaus', 't_b1', :u, '{}', 'queued', :d)"
            ),
            {"u": URL, "d": TODAY},
        )
        await s.commit()
    await queue(env, active(env))
    (row,) = await rows(env)
    assert row.basis == "consensus"


@pytest.mark.integration
async def test_review_mode_never_auto_approves_verified_rows(env: Env) -> None:
    await seed(env)
    s = active(env, report_hold_hours=0)
    await queue(env, s)
    async with env.worker() as ses:
        assert await abusech.auto_approve(ses, s, TODAY) == 0
    assert [r.state for r in await rows(env)] == ["queued"]


@pytest.mark.integration
async def test_auto_needs_verify_auto_two_cohorts_and_network_cohorts(env: Env) -> None:
    await seed(env)
    base = replace(active(env, report_hold_hours=0), abusech_mode="auto")
    await queue(env, base)
    async with env.worker() as ses:
        # HUB_VERIFY_MODE is not auto: stays queued
        assert await abusech.auto_approve(ses, replace(base, verify_mode="review"), TODAY) == 0
        # the network is too small
        auto = replace(base, verify_mode="auto")
        assert await abusech.auto_approve(ses, replace(auto, auto_min_cohorts=11), TODAY) == 0
        assert await abusech.auto_approve(ses, auto, TODAY) == 1
    (row,) = await rows(env)
    assert (row.state, row.approved_by) == ("approved", "auto")


@pytest.mark.integration
async def test_auto_keeps_same_cohort_reporters_for_review(env: Env) -> None:
    # nodes 0 and 1 enrolled in the same week: one cohort, so no automatic approval
    weeks = [TODAY - timedelta(days=20), TODAY - timedelta(days=19), *WEEKS[2:]]
    await seed(env, enrolled=weeks)
    s = replace(active(env, report_hold_hours=0), abusech_mode="auto", verify_mode="auto")
    await queue(env, s)
    assert [r.state for r in await rows(env)] == ["queued"]  # queued: two reporters suffice
    async with env.worker() as ses:
        assert await abusech.auto_approve(ses, s, TODAY) == 0
    assert [r.state for r in await rows(env)] == ["queued"]


@pytest.mark.integration
async def test_auto_does_not_approve_after_the_role_is_gone(env: Env) -> None:
    await seed(env)
    s = replace(active(env, report_hold_hours=0), abusech_mode="auto", verify_mode="auto")
    await queue(env, s)
    async with env.worker() as ses:
        await ses.execute(text("DELETE FROM node_roles"))
        await ses.commit()
        assert await abusech.auto_approve(ses, s, TODAY) == 0


@pytest.mark.integration
async def test_a_verified_row_is_sent_without_a_live_target_state(env: Env) -> None:
    await seed(env)  # the target is only a candidate
    s = active(env)
    await queue(env, s)
    await approve_all(env)
    out, sent = await send(env, s)
    assert out.sent == 1 and len(sent) == 1 and URL.encode() in sent[0]
    assert (await rows(env))[0].state == "sent"


@pytest.mark.integration
@pytest.mark.parametrize(
    "breaker",
    [
        "UPDATE verify_tasks SET state = 'refused'",
        "DELETE FROM node_roles",
        "UPDATE targets SET state = 'disputed'",
        "UPDATE targets SET state = 'expired'",
    ],
)
async def test_sending_rechecks_the_task_the_role_and_the_target(env: Env, breaker: str) -> None:
    await seed(env)
    s = active(env)
    await queue(env, s)
    await approve_all(env)
    async with env.worker() as ses:
        await ses.execute(text(breaker))
        await ses.commit()
    out, sent = await send(env, s)
    assert out.sent == 0 and out.rejected == 1 and sent == []
    row = (await rows(env))[0]
    assert (row.state, row.result_code) == ("rejected", "target_not_live")


@pytest.mark.integration
async def test_withdrawals_cover_both_paths(env: Env) -> None:
    await seed(env)
    s = active(env)
    async with env.worker() as ses:
        await abusech.queue_submissions(ses, s, TODAY, never=Never())
        assert await abusech.withdraw_target(ses, "t_b1") == 1
        await ses.commit()
    assert (await rows(env))[0].result_code == "withdrawn"
    # a delisting decision for the host
    async with env.worker() as ses:
        await ses.execute(text("DELETE FROM abusech_submissions"))
        await abusech.queue_submissions(ses, s, TODAY, never=Never())
        assert await abusech.withdraw_value(ses, "198.51.100.0/24") == 1
        await ses.commit()
    # a refused task, and a revoked verifier
    async with env.worker() as ses:
        await ses.execute(text("DELETE FROM abusech_submissions"))
        await abusech.queue_submissions(ses, s, TODAY, never=Never())
        assert await abusech.withdraw_task(ses, "v_000000000001") == 1
        await ses.execute(text("DELETE FROM abusech_submissions"))
        await abusech.queue_submissions(ses, s, TODAY, never=Never())
        assert await abusech.withdraw_unattested(ses) == 0  # the role is still there
        await ses.execute(text("DELETE FROM node_roles"))
        assert await abusech.withdraw_unattested(ses) == 1
        await ses.execute(text("DELETE FROM abusech_submissions"))
        await abusech.queue_submissions(ses, s, TODAY, never=Never())  # no role: nothing queued
        assert await abusech.withdraw_verified(ses) == 0

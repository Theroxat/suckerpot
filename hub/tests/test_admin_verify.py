"""Operator CLI for verification: roles, task review, abuse.ch cancel. Every change is audited."""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text

from hub import admin
from hub.config import Settings
from hub.db import utcnow

from .conftest import Env
from .seed import TODAY, add_nodes

D1 = TODAY - timedelta(days=1)
SECRET_URL = "http://files.example.org/bins/arm7"


class Cli:
    def __init__(self, env: Env, settings: Settings | None = None) -> None:
        self.env = env
        self.lines: list[str] = []
        self.settings = settings or env.settings

    async def __call__(self, *argv: str) -> int:
        self.lines.clear()
        return await admin.run(
            list(argv),
            sessionmaker=self.env.worker,
            out=self.lines.append,
            actor="op",
            settings=self.settings,
        )

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


async def fingerprint(env: Env, node: uuid.UUID) -> str:
    async with env.worker() as s:
        return str(
            (
                await s.execute(
                    text(
                        "SELECT substr(encode(sha256(pubkey), 'hex'), 1, 8) FROM nodes WHERE id = :n"
                    ),
                    {"n": node},
                )
            ).scalar_one()
        )


async def audit(env: Env, like: str) -> list[Any]:
    async with env.worker() as s:
        return list(
            (
                await s.execute(
                    text("SELECT action, detail::text AS d FROM hub_audit WHERE action LIKE :a"),
                    {"a": like},
                )
            ).all()
        )


async def add_task(env: Env, tid: str, state: str, url: str | None = SECRET_URL, **kw: Any) -> None:
    async with env.worker() as s:
        await s.execute(
            text(
                "INSERT INTO verify_tasks (id, url_b, url, site, state, reporters, "
                "reporter_cohorts, last_report_day, created_day, revealed_day, lease_node, "
                "lease_until) VALUES (:i, :b, :u, 'files.example.org', :st, 2, 2, :d, :d, :d, "
                ":ln, :lu)"
            ),
            {
                "i": tid,
                "b": tid.ljust(64, "0"),
                "u": url,
                "st": state,
                "d": TODAY,
                "ln": kw.get("lease_node"),
                "lu": kw.get("lease_until"),
            },
        )
        await s.commit()


async def task(env: Env, tid: str) -> Any:
    async with env.worker() as s:
        return (
            (await s.execute(text("SELECT * FROM verify_tasks WHERE id = :i"), {"i": tid}))
            .mappings()
            .one()
        )


@pytest.mark.integration
async def test_role_grant_roles_and_revoke_are_audited(env: Env) -> None:
    (node,) = await add_nodes(env.worker, 1)
    fp = await fingerprint(env, node)
    cli = Cli(env)
    assert await cli("node", "role", "grant", fp, "verifier") == 0
    assert await cli("node", "role", "grant", fp, "verifier") == 0  # idempotent
    assert "already holds" in cli.text
    assert await cli("node", "roles") == 0
    assert cli.lines[0].startswith(f"{fp}\tverifier\t")
    assert await cli("node", "role", "revoke", fp, "verifier") == 0
    assert await cli("node", "role", "revoke", fp, "verifier") == 1  # nothing left
    assert await cli("node", "role", "grant", "deadbeef", "verifier") == 1
    assert await cli("node", "roles") == 0 and cli.lines == []
    actions = [a.action for a in await audit(env, "node.role.%")]
    assert actions == ["node.role.grant", "node.role.grant", "node.role.revoke", "node.role.revoke"]
    for a in await audit(env, "node.role.%"):
        assert fp not in a.d and str(node) not in a.d  # counts only


@pytest.mark.integration
async def test_unknown_roles_are_refused_by_the_parser(env: Env) -> None:
    with pytest.raises(SystemExit):
        await Cli(env)("node", "role", "grant", "deadbeef", "admin")


@pytest.mark.integration
async def test_revoke_returns_open_leases_and_withdraws_unvouched_submissions(env: Env) -> None:
    (node,) = await add_nodes(env.worker, 1)
    fp = await fingerprint(env, node)
    cli = Cli(env)
    await cli("node", "role", "grant", fp, "verifier")
    await add_task(
        env, "v_leased000001", "leased", lease_node=node, lease_until=D1 + timedelta(days=3)
    )
    await add_task(env, "v_att00000001", "attested")
    async with env.worker() as s:
        await s.execute(
            text(
                "INSERT INTO verify_attestations (task_id, node_id, day, outcome, malware_like) "
                "VALUES ('v_att00000001', :n, :d, 'fetched', true)"
            ),
            {"n": node, "d": TODAY},
        )
        await s.execute(
            text(
                "INSERT INTO targets (id, kind, value_b, state) VALUES ('t_x', 'url', :b, 'candidate')"
            ),
            {"b": "v_att00000001".ljust(64, "0")},
        )
        await s.execute(
            text(
                "INSERT INTO abusech_submissions (kind, target_id, indicator, tags, state, "
                "created_day, basis, verify_task_id) VALUES ('urlhaus', 't_x', :u, '{}', 'queued', "
                ":d, 'verified', 'v_att00000001')"
            ),
            {"u": SECRET_URL, "d": TODAY},
        )
        await s.commit()
    assert await cli("node", "role", "revoke", fp, "verifier") == 0
    assert "1 lease(s) released, 1 submission(s) withdrawn" in cli.text
    row = await task(env, "v_leased000001")
    assert (row["state"], row["lease_node"], row["release_at"]) == ("queued", None, None)
    async with env.worker() as s:
        sub = (await s.execute(text("SELECT state, result_code FROM abusech_submissions"))).one()
    assert (sub.state, sub.result_code) == ("rejected", "withdrawn")


@pytest.mark.integration
async def test_verify_status_list_and_show_hide_the_link_outside_review_states(env: Env) -> None:
    for tid, state in (
        ("v_wait0000001", "waiting_reveal"),
        ("v_review00001", "pending_review"),
        ("v_queued00001", "queued"),
        ("v_attest00001", "attested"),
    ):
        await add_task(env, tid, state)
    cli = Cli(env, Settings(verify_mode="review"))
    assert await cli("verify", "status") == 0
    assert "mode: review" in cli.text and "pending_review: 1" in cli.text
    assert "of 200" in cli.text
    assert await cli("verify", "list", "--state", "pending_review") == 0
    assert len(cli.lines) == 1 and cli.lines[0].startswith("v_review00001\tpending_review\t")
    assert SECRET_URL not in cli.text  # lists never show the link
    for tid, shown in (("v_review00001", True), ("v_queued00001", True), ("v_attest00001", False),
                       ("v_wait0000001", False)):  # fmt: skip
        assert await cli("verify", "show", tid) == 0
        assert (f"url: {SECRET_URL}" in cli.text) is shown, tid
    assert await cli("verify", "show", "v_nothing00001") == 1
    assert await audit(env, "verify.%") == []  # reading changes nothing


@pytest.mark.integration
async def test_verify_approve_queues_for_immediate_lease(env: Env) -> None:
    await add_task(env, "v_review00001", "pending_review")
    await add_task(env, "v_queued00001", "queued")
    cli = Cli(env)
    assert await cli("verify", "approve", "v_queued00001") == 1  # not in review
    assert await cli("verify", "approve", "v_nothing00001") == 1
    assert await cli("verify", "approve", "v_review00001") == 0
    row = await task(env, "v_review00001")
    assert (row["state"], row["release_at"]) == ("queued", None)
    assert await cli("verify", "approve", "v_review00001") == 1
    assert [a.action for a in await audit(env, "verify.%")] == ["verify.approve"]


@pytest.mark.integration
async def test_verify_refuse_ends_the_task_and_withdraws_submissions(env: Env) -> None:
    await add_task(env, "v_attest00001", "attested")
    await add_task(env, "v_leased00001", "leased")
    async with env.worker() as s:
        await s.execute(
            text(
                "INSERT INTO targets (id, kind, value_b, state) VALUES ('t_x', 'url', :b, 'candidate')"
            ),
            {"b": "v_attest00001".ljust(64, "0")},
        )
        await s.execute(
            text(
                "INSERT INTO abusech_submissions (kind, target_id, indicator, tags, state, "
                "created_day, basis, verify_task_id) VALUES ('urlhaus', 't_x', :u, '{}', "
                "'approved', :d, 'verified', 'v_attest00001')"
            ),
            {"u": SECRET_URL, "d": TODAY},
        )
        await s.commit()
    cli = Cli(env)
    assert await cli("verify", "refuse", "v_leased00001", "--note", "x") == 1  # leased: let it end
    assert await cli("verify", "refuse", "v_attest00001", "--note", "benign") == 0
    assert "1 submission(s) withdrawn" in cli.text
    row = await task(env, "v_attest00001")
    assert (row["state"], row["refusal"], row["ended_day"]) == (
        "refused",
        "operator",
        utcnow().date(),
    )
    async with env.worker() as s:
        sub = (await s.execute(text("SELECT state, result_code FROM abusech_submissions"))).one()
        assert (sub.state, sub.result_code) == ("rejected", "withdrawn")
    assert await cli("verify", "reject", "v_attest00001", "--note", "again") == 1
    (entry,) = await audit(env, "verify.refuse")
    assert "benign" in entry.d and SECRET_URL not in entry.d


@pytest.mark.integration
async def test_verify_refuse_abuse_disputes_the_candidate(env: Env) -> None:
    nodes = await add_nodes(env.worker, 2)
    await add_task(env, "v_review00001", "pending_review")
    async with env.worker() as s:
        await s.execute(
            text(
                "INSERT INTO targets (id, kind, value_b, state) VALUES ('t_x', 'url', :b, 'candidate')"
            ),
            {"b": "v_review00001".ljust(64, "0")},
        )
        for n in nodes:
            await s.execute(
                text("INSERT INTO target_contributors (target_id, node_id) VALUES ('t_x', :n)"),
                {"n": n},
            )
        await s.commit()
    cli = Cli(env)
    assert await cli("verify", "refuse", "v_review00001", "--note", "abuse", "--abuse") == 0
    assert "2 contributors lowered" in cli.text
    async with env.worker() as s:
        state = (await s.execute(text("SELECT state FROM targets WHERE id = 't_x'"))).scalar_one()
        reps = (await s.execute(text("SELECT reputation FROM nodes"))).scalars().all()
    assert state == "disputed" and all(r < 0.8 for r in reps)
    assert (await task(env, "v_review00001"))["state"] == "refused"


@pytest.mark.integration
async def test_abusech_cancel_one_or_all_verified_and_list_shows_basis(env: Env) -> None:
    async with env.worker() as s:
        await s.execute(
            text(
                "INSERT INTO targets (id, kind, value_b, state) VALUES ('t_x', 'url', :b, 'candidate')"
            ),
            {"b": "ab" * 32},
        )
        for i, (basis, state) in enumerate(
            [
                ("verified", "queued"),
                ("verified", "approved"),
                ("consensus", "queued"),
                ("verified", "sent"),
            ]
        ):
            await s.execute(
                text(
                    "INSERT INTO abusech_submissions (kind, target_id, indicator, tags, state, "
                    "created_day, basis) VALUES ('urlhaus', 't_x', :u, '{}', :st, :d, :b)"
                ),
                {"u": f"http://files.example.org/{i}", "st": state, "d": TODAY, "b": basis},
            )
        await s.commit()
    cli = Cli(env)
    assert await cli("abusech", "list") == 0
    assert sum("\tverified\t" in line for line in cli.lines) == 3
    assert await cli("abusech", "cancel") == 2  # needs an id or --all-verified
    assert await cli("abusech", "cancel", "1", "--all-verified") == 2
    assert await cli("abusech", "cancel", "3") == 0  # a consensus row by id
    assert await cli("abusech", "cancel", "3") == 1  # already rejected
    assert await cli("abusech", "cancel", "--all-verified") == 0
    assert "cancelled 2 submission(s)" in cli.text
    async with env.worker() as s:
        states = (
            await s.execute(text("SELECT id, state FROM abusech_submissions ORDER BY id"))
        ).all()
    assert [r.state for r in states] == ["rejected", "rejected", "rejected", "sent"]  # sent stays
    assert len(await audit(env, "abusech.cancel")) == 3  # the usage errors write nothing


async def test_alt_signing_key_is_never_overwritten_and_show_all_labels_both(tmp_path: Any) -> None:
    lines: list[str] = []
    primary, alt = tmp_path / "primary", tmp_path / "alt"
    assert await admin.run(["gen-signing-key", "--out", str(primary)], out=lines.append) == 0
    assert await admin.run(["gen-signing-key", "--alt", "--out", str(alt)], out=lines.append) == 0
    assert lines[0].startswith("hub_key=") and lines[1].startswith("hub_key_alt=")
    assert oct(alt.stat().st_mode & 0o777) == "0o400"
    before = alt.read_text()
    code = await admin.run(
        ["gen-signing-key", "--alt", "--force", "--out", str(alt)], out=lines.append
    )
    assert code == 1 and alt.read_text() == before
    lines.clear()
    argv = ["show-public-key", "--all", "--key-file", str(primary), "--alt-key-file", str(alt)]
    assert await admin.run(argv, out=lines.append) == 0
    assert [x.split("=")[0] for x in lines] == ["hub_key", "hub_key_alt"]
    assert lines[1].split("=")[1] != lines[0].split("=")[1]
    lines.clear()
    assert (
        await admin.run(["show-public-key", "--all", "--key-file", str(primary)], out=lines.append)
        == 0
    )
    assert lines[1] == "hub_key_alt=none"
    assert await admin.run(["gen-signing-key", "--alt"], out=lines.append) == 2

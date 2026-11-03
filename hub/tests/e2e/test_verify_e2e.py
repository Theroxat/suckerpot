"""Verification end to end (design M32): two nodes report a link, an operator reviews the task, a
verifier fetches it, and the verified submission reaches the abuse.ch sender only after approval.

Real API routes, real worker cycles and the real admin CLI against a throwaway PostgreSQL. The
abuse.ch call itself is a local stub: nothing leaves the test.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text
from suckerpot_netproto import blind

from hub import admin
from hub.worker import WorkerContext, run_cycle

from ..conftest import Env
from ..helpers import batch, source

pytestmark = pytest.mark.integration
URL = "http://files.example.org/bins/arm7"
URL_B = blind.blind_url(URL)
KEY = "test-auth-key-not-a-secret"  # placeholder
IP = "198.51.100.24"


async def cli(env: Env, *argv: str) -> tuple[int, str]:
    lines: list[str] = []
    code = await admin.run(
        list(argv), sessionmaker=env.worker, out=lines.append, actor="op", settings=env.settings
    )
    return code, "\n".join(lines)


async def age(env: Env, nodes: list[Any]) -> None:
    async with env.worker() as s:
        for i, n in enumerate(nodes):
            await s.execute(
                text(
                    "UPDATE nodes SET enrolled_day = :d, reputation = 0.9 WHERE id = CAST(:i AS uuid)"
                ),
                {"d": env.clock().date() - timedelta(days=20 + 7 * i), "i": n.node_id},
            )
            for d in range(3, 9):
                await s.execute(
                    text(
                        "INSERT INTO batches (node_id, day, batch_id, items) "
                        "VALUES (CAST(:i AS uuid), :d, :b, 1)"
                    ),
                    {
                        "i": n.node_id,
                        "d": env.clock().date() - timedelta(days=d),
                        "b": bytes([i, d]) * 8,
                    },
                )
        await s.commit()


async def test_verified_path_from_report_to_abusech(env_factory: Any) -> None:
    env: Env = await env_factory(
        verify_mode="review", abusech_mode="review", abusech_auth_key=KEY, report_hold_hours=0
    )
    nodes = await env.enrolled(10)
    await age(env, nodes)
    reporters, verifier = nodes[:2], nodes[9]
    for n in reporters:  # two nodes saw the link; nobody fetched it
        r = await n.call(
            "POST",
            "/v1/observations",
            batch(
                "2026-10-31",
                sources=[source(IP, services=["ssh"], activity=["command"], tags=[], attempts=0)],
                payloads=[
                    {
                        "url_b": URL_B,
                        "host_b": blind.blind_domain("files.example.org"),
                        "fetched": False,
                    }
                ],
            ),
        )
        assert r.status == 200, r.json

    sent: list[bytes] = []

    async def submit(kind: str, body: bytes, key: str) -> str:
        sent.append(body)
        return "inserted"

    ctx = WorkerContext(
        settings=env.settings, sessionmaker=env.worker, clock=env.clock, abusech_submit=submit
    )

    async def cycle() -> None:
        report = await run_cycle(ctx)
        assert report.failed == [], report.steps

    # The operator grants the role by fingerprint, as in production.
    async with env.worker() as s:
        fp = (
            await s.execute(
                text(
                    "SELECT substr(encode(sha256(pubkey), 'hex'), 1, 8) FROM nodes WHERE id = CAST(:i AS uuid)"
                ),
                {"i": verifier.node_id},
            )
        ).scalar_one()
    assert (await cli(env, "node", "role", "grant", fp, "verifier"))[0] == 0

    await cycle()
    assert (await cli(env, "verify", "list", "--state", "waiting_reveal"))[1].count("\n") == 0
    task_id = (await cli(env, "verify", "list", "--state", "waiting_reveal"))[1].split("\t")[0]
    assert task_id.startswith("v_")

    body = {"protocol": "spn/1", "items": [{"kind": "url", "value": URL, "value_b": URL_B}]}
    assert (await reporters[0].call("POST", "/v1/reveals", body)).json["accepted"] == 1
    await cycle()
    _, shown = await cli(env, "verify", "show", task_id)
    assert "state: pending_review" in shown and f"url: {URL}" in shown
    assert (await verifier.call("GET", "/v1/verify/tasks")).json == {"tasks": []}  # review first

    assert (await cli(env, "verify", "approve", task_id))[0] == 0
    (leased,) = (await verifier.call("GET", "/v1/verify/tasks")).json["tasks"]
    assert leased["id"] == task_id
    done = {
        "protocol": "spn/1",
        "items": [
            {
                "id": task_id,
                "outcome": "fetched",
                "sha256": "ab" * 32,
                "size": 2048,
                "file_type": "elf-arm",
                "family": "mirai",
            }
        ],
    }
    assert (await verifier.call("POST", "/v1/verify/results", done)).json["accepted"] == 1

    # Path B: queued for review, never sent before an operator approves it.
    await cycle()
    code, listing = await cli(env, "abusech", "list", "--state", "queued")
    assert code == 0 and "\tverified\t" in listing and URL in listing
    assert sent == []
    sid = listing.split("\t")[0]
    assert (await cli(env, "abusech", "approve", sid))[0] == 0
    await cycle()
    assert len(sent) == 1
    payload = json.loads(sent[0])
    assert payload["submission"][0]["url"] == URL
    assert payload["submission"][0]["tags"] == ["mirai", "elf", "arm"]
    assert not any(w in sent[0].lower() for w in (b"node", b"verifier", b"pseudonym", b"v_"))
    assert (await cli(env, "abusech", "list", "--state", "sent"))[1].count("\tverified\t") == 1

    # Every operator step wrote an audit row, with no link and no node in it.
    async with env.worker() as s:
        rows = (await s.execute(text("SELECT action, detail::text AS d FROM hub_audit"))).all()
    actions = {r.action for r in rows}
    assert {"node.role.grant", "verify.approve", "abusech.approve"} <= actions
    assert all(URL not in r.d and fp not in r.d for r in rows)

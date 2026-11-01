from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from .conftest import Env
from .helpers import batch, source

pytestmark = pytest.mark.integration


def patch(**kw: object) -> dict[str, object]:
    return {"protocol": "spn/1", **kw}


async def test_get_node_has_coarse_standing_only(env: Env) -> None:
    (node,) = await env.enrolled(pseudonym="owl one")
    reply = await node.call("GET", "/v1/node")
    assert set(reply.json) == {
        "node_id", "fingerprint", "pseudonym", "country", "show_country",
        "enrolled_day", "eligible_from_day", "standing", "active_days_14",
    }  # fmt: skip
    assert reply.json["standing"] == "new" and reply.json["active_days_14"] == 0
    env.clock.advance(days=14)
    assert (await node.call("GET", "/v1/node")).json["standing"] == "good"


async def test_standing_low_when_reputation_drops(env: Env) -> None:
    (node,) = await env.enrolled()
    env.clock.advance(days=14)
    async with env.worker() as s:
        await s.execute(text("UPDATE nodes SET reputation = 0.25"))
        await s.commit()
    assert (await node.call("GET", "/v1/node")).json["standing"] == "low"


async def test_active_days_counts_batches(env: Env) -> None:
    (node,) = await env.enrolled()
    for day in ("2026-10-31", "2026-10-30"):
        r = await node.call("POST", "/v1/observations", batch(day, sources=[source("192.0.2.4")]))
        assert r.status == 200
    assert (await node.call("GET", "/v1/node")).json["active_days_14"] == 2


async def test_patch_pseudonym_country_and_weekly_limit(env: Env) -> None:
    (node,) = await env.enrolled(pseudonym="first one")
    ok = await node.call(
        "PATCH", "/v1/node", patch(pseudonym="second one", country="DE", show_country=True)
    )
    assert ok.status == 200
    assert (ok.json["pseudonym"], ok.json["country"], ok.json["show_country"]) == (
        "second one",
        "DE",
        True,
    )
    again = await node.call("PATCH", "/v1/node", patch(pseudonym="third one"))
    assert (again.status, again.error) == (429, "rate_limited")
    # other fields are not limited, and the same name in another case is no change
    assert (await node.call("PATCH", "/v1/node", patch(country="FR"))).status == 200
    assert (await node.call("PATCH", "/v1/node", patch(pseudonym="SECOND ONE"))).status == 200
    env.clock.advance(days=7)
    assert (await node.call("PATCH", "/v1/node", patch(pseudonym="third one"))).status == 200


async def test_patch_validation_and_clearing(env: Env) -> None:
    a, b = await env.enrolled(2)
    await a.call("PATCH", "/v1/node", patch(pseudonym="taken name"))
    assert (
        await b.call("PATCH", "/v1/node", patch(pseudonym="Taken Name"))
    ).error == "pseudonym_taken"
    assert (
        await b.call("PATCH", "/v1/node", patch(pseudonym="admin"))
    ).error == "pseudonym_invalid"
    assert (
        await b.call("PATCH", "/v1/node", {"pseudonym": "x y z"})
    ).error == "invalid_payload"  # no protocol
    assert (await b.call("PATCH", "/v1/node", patch(unknown=1))).error == "invalid_payload"
    cleared = await a.call(
        "PATCH", "/v1/node", patch(pseudonym=None, country="CH", show_country=True)
    )
    assert cleared.json["pseudonym"] is None
    # clearing the country hides it
    off = await a.call("PATCH", "/v1/node", patch(country=None))
    assert off.json["country"] is None and off.json["show_country"] is False


async def test_delete_leaves_no_row_with_the_node_id(env: Env) -> None:
    keep, gone = await env.enrolled(2, pseudonym=None)
    day = "2026-10-31"
    for n in (keep, gone):
        r = await n.call(
            "POST",
            "/v1/observations",
            batch(
                day,
                sources=[source("192.0.2.4")],
                payloads=[{"url_b": "ab" * 32, "host_ip": "192.0.2.1", "fetched": False}],
                c2=[{"ip": "192.0.2.9", "port": 23}],
                files=[{"sha256": "cd" * 32}],
            ),
        )
        assert r.status == 200, r.json
    async with env.worker() as s:
        await s.execute(
            text(
                "INSERT INTO targets (id, kind, value, state) VALUES ('t_000000000001','ip','192.0.2.4','confirmed')"
            )
        )
        await s.execute(
            text("INSERT INTO target_contributors VALUES ('t_000000000001', :n)"),
            {"n": uuid.UUID(gone.node_id or "")},
        )
        await s.execute(
            text("INSERT INTO takedown_votes VALUES ('t_000000000001', :n, '2026-10-31', 'down')"),
            {"n": uuid.UUID(gone.node_id or "")},
        )
        await s.execute(
            text("INSERT INTO node_stats_weekly VALUES (:n, '2026-10-26', 3, 2)"),
            {"n": uuid.UUID(gone.node_id or "")},
        )
        await s.commit()

    reply = await gone.call("DELETE", "/v1/node")
    assert (reply.status, reply.json, reply.signature_ok) == (200, {"deleted": True}, True)

    async with env.worker() as s:
        cols = (
            (
                await s.execute(
                    text(
                        "SELECT table_name FROM information_schema.columns "
                        "WHERE table_schema='public' AND column_name='node_id'"
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(cols) >= 6
        for table in cols:
            n = (
                await s.execute(
                    text(f"SELECT count(*) FROM {table} WHERE node_id = :n"),
                    {"n": uuid.UUID(gone.node_id or "")},
                )
            ).scalar_one()
            assert n == 0, table
        assert (
            await s.execute(
                text("SELECT count(*) FROM nodes WHERE id = :n"),
                {"n": uuid.UUID(gone.node_id or "")},
            )
        ).scalar_one() == 0
        assert (
            await s.execute(text("SELECT count(*) FROM observations"))
        ).scalar_one() > 0  # the other node stays
    assert (await gone.call("GET", "/v1/node")).error == "unknown_node"
    assert (await keep.call("GET", "/v1/node")).status == 200

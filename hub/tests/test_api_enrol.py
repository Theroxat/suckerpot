from __future__ import annotations

from datetime import date, timedelta
from typing import Any

import pytest
from sqlalchemy import func, select, text
from suckerpot_netproto import pow, sign

from hub.models import Node

from .conftest import Env
from .helpers import NodeClient

pytestmark = pytest.mark.integration


async def test_info_is_unsigned_and_answer_is_signed(env: Env) -> None:
    reply = await env.client.unsigned("GET", "/v1/info")
    assert reply.status == 200 and reply.signature_ok
    assert reply.json["protocols"] == ["spn/1"]
    assert reply.json["hub_key"] == env.hub_key
    assert reply.json["pow"] == {"algorithm": "sha256-leading-zero-bits", "difficulty": 6}
    assert reply.json["today"] == "2026-11-01"
    assert reply.json["thresholds"] == {"min_nodes": 5, "min_age_days": 14}


async def test_no_signature_header_without_nonce(env: Env) -> None:
    resp = await env.http.get("/v1/info")
    assert resp.status_code == 200 and "x-spn-hub-signature" not in resp.headers
    assert resp.headers["cache-control"] == "no-store"
    assert "server" not in resp.headers


async def test_enrol_happy_path(env: Env) -> None:
    node = env.node()
    reply = await node.enrol(pseudonym="Night Owl", country="CH", show_country=True)
    assert reply.status == 200 and reply.signature_ok
    assert reply.json["fingerprint"] == node.fingerprint
    assert reply.json["enrolled_day"] == "2026-11-01"
    assert reply.json["eligible_from_day"] == "2026-11-15"
    me = await node.call("GET", "/v1/node")
    assert me.status == 200
    assert me.json["pseudonym"] == "Night Owl" and me.json["country"] == "CH"
    assert me.json["show_country"] is True and me.json["standing"] == "new"
    async with env.worker() as s:
        row = (await s.execute(select(Node))).scalar_one()
        assert row.last_active_day == date(2026, 11, 1)
        assert row.reputation == pytest.approx(0.6)


async def test_show_country_requires_a_country(env: Env) -> None:
    node = env.node()
    reply = await node.enrol(show_country=True)
    assert reply.status == 200
    assert (await node.call("GET", "/v1/node")).json["show_country"] is False


async def _challenge(node: NodeClient) -> dict[str, Any]:
    ch = await node.unsigned(
        "POST", "/v1/enrol/challenge", {"protocol": "spn/1", "node_key": node.key}
    )
    assert ch.status == 200
    out: dict[str, Any] = ch.json
    return out


def _enrol_body(
    node: NodeClient, ch: dict[str, Any], nonce: bytes | None = None, **kw: Any
) -> dict[str, Any]:
    if nonce is None:
        solved = pow.solve_pow(sign.b64u_decode(ch["challenge"]), node.public, ch["difficulty"])
        assert solved is not None
        nonce = solved
    return {
        "protocol": "spn/1",
        "challenge": ch["challenge"],
        "pow_nonce": sign.b64u_encode(nonce),
        "show_country": False,
        **kw,
    }


async def test_enrol_bad_pow(env: Env) -> None:
    node = env.node()
    ch = await _challenge(node)
    challenge = sign.b64u_decode(ch["challenge"])
    bad = next(
        n.to_bytes(8, "big")
        for n in range(10000)
        if not pow.verify_pow(challenge, node.public, n.to_bytes(8, "big"), ch["difficulty"])
    )
    reply = await node.call("POST", "/v1/enrol", _enrol_body(node, ch, bad))
    assert (reply.status, reply.error) == (400, "pow_invalid")


async def test_enrol_pow_bound_to_the_key(env: Env) -> None:
    a, b = env.node(), env.node()
    ch = await _challenge(a)
    # b cannot use a's challenge, even with a valid proof for its own key
    solved = pow.solve_pow(sign.b64u_decode(ch["challenge"]), b.public, ch["difficulty"])
    assert solved is not None
    reply = await b.call("POST", "/v1/enrol", _enrol_body(b, ch, solved))
    assert reply.error == "challenge_expired"


async def test_challenge_expires_and_is_single_use(env: Env) -> None:
    node = env.node()
    ch = await _challenge(node)
    env.clock.advance(minutes=11)
    reply = await node.call("POST", "/v1/enrol", _enrol_body(node, ch))
    assert reply.error == "challenge_expired"
    ch = await _challenge(node)
    assert (await node.call("POST", "/v1/enrol", _enrol_body(node, ch))).status == 200
    again = await node.call("POST", "/v1/enrol", _enrol_body(node, ch))
    assert again.error == "challenge_expired"


async def test_new_challenge_replaces_the_old_one(env: Env) -> None:
    node = env.node()
    first = await _challenge(node)
    await _challenge(node)
    reply = await node.call("POST", "/v1/enrol", _enrol_body(node, first))
    assert reply.error == "challenge_expired"


async def test_enrol_signed_by_another_key(env: Env) -> None:
    a, b = env.node(), env.node()
    ch = await _challenge(a)
    reply = await a.call("POST", "/v1/enrol", _enrol_body(a, ch), forge_with=b.private)
    assert reply.error == "bad_signature"


async def test_enrol_twice_is_refused(env: Env) -> None:
    node = env.node()
    assert (await node.enrol()).status == 200
    ch = await _challenge(node)
    reply = await node.call("POST", "/v1/enrol", _enrol_body(node, ch))
    assert (reply.status, reply.error) == (400, "invalid_payload")


@pytest.mark.parametrize(
    "name",
    [
        "ab",
        "x" * 30,
        "root@example.org",
        "see http://x.y",
        "year 2026 owl",
        "-bad-",
        "Admin",
        "hub",
        "my.suckerpot",
        "a  b",
        "owl!",
        "Selfhostr",
    ],
)
async def test_pseudonym_invalid(env: Env, name: str) -> None:
    node = env.node()
    ch = await _challenge(node)
    reply = await node.call("POST", "/v1/enrol", _enrol_body(node, ch, pseudonym=name))
    assert reply.error == "pseudonym_invalid", name
    assert reply.status == 400


async def test_pseudonym_taken_ignores_case_and_separators(env: Env) -> None:
    assert (await env.node().enrol(pseudonym="Night Owl")).status == 200
    for variant in ("night owl", "NIGHT-OWL", "night_owl"):
        reply = await env.node().enrol(pseudonym=variant)
        assert (reply.status, reply.error) == (409, "pseudonym_taken"), variant


async def test_hard_cap_closes_enrolment(env_factory: Any) -> None:
    env: Env = await env_factory(enrol_hard_cap=2)
    await env.enrolled(2)
    ch = await env.node().unsigned(
        "POST", "/v1/enrol/challenge", {"protocol": "spn/1", "node_key": env.node().key}
    )
    assert (ch.status, ch.error) == (503, "enrolment_closed")
    env.clock.advance(days=1)  # a new day reopens
    ch = await env.node().unsigned(
        "POST", "/v1/enrol/challenge", {"protocol": "spn/1", "node_key": env.node().key}
    )
    assert ch.status == 200


async def test_a_flooding_prefix_pays_more_proof_of_work(env_factory: Any) -> None:
    env: Env = await env_factory(enrol_soft_cap=1, enrol_step=2, challenges_per_prefix=50)
    seen = [(await _challenge(env.node()))["difficulty"] for _ in range(6)]
    # base 6; above the soft cap (1): +1, then +1 more for every 2 further challenges
    assert seen == [6, 6, 7, 7, 8, 8]


async def test_difficulty_does_not_rise_with_the_days_global_enrolments(env_factory: Any) -> None:
    env: Env = await env_factory(enrol_soft_cap=1, enrol_hard_cap=100, challenges_per_prefix=50)
    await env.enrolled(4)  # four enrolments today, from one prefix
    env.clock.advance(minutes=11)  # that prefix's window is over
    assert (await env.client.unsigned("GET", "/v1/info")).json["pow"]["difficulty"] == 6
    assert (await _challenge(env.node()))["difficulty"] == 6


async def test_unsigned_rate_limit_and_daily_key_rotation(env_factory: Any) -> None:
    env: Env = await env_factory(unsigned_per_min=3)
    codes = [(await env.client.unsigned("GET", "/v1/info")).status for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    last = await env.client.unsigned("GET", "/v1/info")
    assert last.json == {"error": "rate_limited"} and int(last.headers["retry-after"]) >= 1
    assert last.signature_ok
    env.clock.advance(minutes=2)
    assert (await env.client.unsigned("GET", "/v1/info")).status == 200


async def test_challenge_table_is_bounded(env_factory: Any) -> None:
    env: Env = await env_factory(max_pending_challenges=2)
    for _ in range(2):
        await _challenge(env.node())
    reply = await env.node().unsigned(
        "POST", "/v1/enrol/challenge", {"protocol": "spn/1", "node_key": env.node().key}
    )
    assert reply.error == "rate_limited"


async def test_enrol_counts_per_day(env: Env) -> None:
    await env.enrolled(2)
    async with env.worker() as s:
        assert (await s.execute(select(func.count()).select_from(Node))).scalar_one() == 2
        # no timestamp column on nodes: dates only (H4)
        cols = (
            (
                await s.execute(
                    text(
                        "SELECT data_type FROM information_schema.columns WHERE table_name='nodes'"
                    )
                )
            )
            .scalars()
            .all()
        )
        assert "timestamp with time zone" not in cols and "timestamp without time zone" not in cols
    assert env.clock().date() + timedelta(days=0) == date(2026, 11, 1)


async def test_challenges_are_capped_per_prefix(env_factory: Any) -> None:
    env: Env = await env_factory(challenges_per_prefix=2)
    results = []
    for _ in range(3):
        node = env.node()
        r = await node.unsigned(
            "POST", "/v1/enrol/challenge", {"protocol": "spn/1", "node_key": node.key}
        )
        results.append(r.status)
    assert results == [200, 200, 429]

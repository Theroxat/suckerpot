"""The seven checks of section 5.2, in order, and their error codes."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import func, select
from suckerpot_netproto import sign

from hub.models import Nonce

from .conftest import Env
from .helpers import NodeClient

pytestmark = pytest.mark.integration


async def _member(env: Env) -> NodeClient:
    (node,) = await env.enrolled()
    return node


async def test_valid_request_and_signed_answer(env: Env) -> None:
    node = await _member(env)
    reply = await node.call("GET", "/v1/node")
    assert reply.status == 200 and reply.signature_ok


async def test_answer_signature_is_bound_to_the_request_nonce(env: Env) -> None:
    node = await _member(env)
    first = await node.call("GET", "/v1/node")
    assert first.signature_ok
    resp_sig = first.headers[sign.H_HUB_SIGNATURE]
    # the same signature does not verify against any other nonce
    assert not sign.verify_response(env.hub_key, resp_sig, sign.new_nonce(), 200, first.raw)


@pytest.mark.parametrize("drop", [sign.H_KEY, sign.H_TIMESTAMP, sign.H_NONCE, sign.H_SIGNATURE])
async def test_missing_header(env: Env, drop: str) -> None:
    node = await _member(env)
    reply = await node.call("GET", "/v1/node", drop=(drop,))
    assert (reply.status, reply.error) == (400, "invalid_payload")


async def test_stale_timestamp_both_directions(env: Env) -> None:
    node = await _member(env)
    now = int(env.clock().timestamp())
    for ts in (now - 301, now + 301):
        reply = await node.call("GET", "/v1/node", timestamp=ts)
        assert (reply.status, reply.error) == (401, "stale_timestamp")
    assert (await node.call("GET", "/v1/node", timestamp=now - 299)).status == 200


async def test_unknown_node(env: Env) -> None:
    stranger = env.node()
    reply = await stranger.call("GET", "/v1/node")
    assert (reply.status, reply.error) == (401, "unknown_node")


async def test_bad_signature_covers_method_path_query_and_body(env: Env) -> None:
    node = await _member(env)
    cases: list[dict[str, Any]] = [
        {"sign_path": "/v1/other"},
        {"sign_path": "/v1/node?x=1"},
        {"sign_body": b"tampered"},
        {"forge_with": sign.generate_private_key()},
    ]
    for kw in cases:
        reply = await node.call("GET", "/v1/node", **kw)
        assert reply.error == "bad_signature", kw


async def test_query_string_is_signed(env: Env) -> None:
    node = await _member(env)
    ok = await node.call("GET", "/v1/targets?since=c_0&limit=5")
    assert ok.status == 200
    forged = await node.call(
        "GET", "/v1/targets?since=c_0&limit=5", sign_path="/v1/targets?since=c_0&limit=6"
    )
    assert forged.error == "bad_signature"


async def test_replayed_nonce(env: Env) -> None:
    node = await _member(env)
    nonce = sign.new_nonce()
    assert (await node.call("GET", "/v1/node", nonce=nonce)).status == 200
    replay = await node.call("GET", "/v1/node", nonce=nonce)
    assert (replay.status, replay.error) == (401, "replayed_nonce")
    # a nonce is per key: another node may use the same value
    other = await _member(env)
    assert (await other.call("GET", "/v1/node", nonce=nonce)).status == 200


async def test_check_order(env: Env) -> None:
    stranger = env.node()
    now = int(env.clock().timestamp())
    # size before everything
    big = await stranger.call("POST", "/v1/reveals", raw=b" " * (64 * 1024 + 1), drop=(sign.H_KEY,))
    assert (big.status, big.error) == (413, "too_large")
    # headers before timestamp
    assert (
        await stranger.call("GET", "/v1/node", drop=(sign.H_NONCE,), timestamp=now - 999)
    ).error == "invalid_payload"
    # timestamp before the key lookup
    assert (await stranger.call("GET", "/v1/node", timestamp=now - 999)).error == "stale_timestamp"
    # key lookup before the signature
    assert (await stranger.call("GET", "/v1/node", sign_path="/v1/x")).error == "unknown_node"
    node = await _member(env)
    # signature before nonce: a bad signature with a fresh nonce does not burn the nonce
    n = sign.new_nonce()
    assert (await node.call("GET", "/v1/node", nonce=n, sign_path="/v1/x")).error == "bad_signature"
    assert (await node.call("GET", "/v1/node", nonce=n)).status == 200


async def test_nonce_is_burnt_even_when_the_request_fails_later(env: Env) -> None:
    node = await _member(env)
    n = sign.new_nonce()
    bad = await node.call("POST", "/v1/reveals", {"protocol": "spn/9", "items": []}, nonce=n)
    assert bad.error == "unsupported_protocol"
    assert (
        await node.call("POST", "/v1/reveals", {"protocol": "spn/1", "items": []}, nonce=n)
    ).error == ("replayed_nonce")


async def test_signed_endpoint_size_caps(env: Env) -> None:
    node = await _member(env)
    huge = await node.call("POST", "/v1/reveals", raw=b" " * (64 * 1024 + 1))
    assert huge.error == "too_large"
    obs = await node.call("POST", "/v1/observations", raw=b" " * (1024 * 1024 + 1))
    assert obs.error == "too_large"


async def test_per_node_rate_limit(env_factory: Any) -> None:
    env: Env = await env_factory(signed_per_hour=3)
    (node,) = await env.enrolled()
    codes = [(await node.call("GET", "/v1/node")).status for _ in range(4)]
    assert codes == [200, 200, 200, 429]
    reply = await node.call("GET", "/v1/node")
    assert reply.error == "rate_limited" and int(reply.headers["retry-after"]) >= 1
    env.clock.advance(hours=1, seconds=1)
    assert (await node.call("GET", "/v1/node")).status == 200


async def test_repeated_auth_failures_block_the_address(env_factory: Any) -> None:
    env: Env = await env_factory(auth_failures_per_min=3)
    (node,) = await env.enrolled()
    stranger = env.node()
    for _ in range(3):
        assert (await stranger.call("GET", "/v1/node")).error == "unknown_node"
    blocked = await node.call("GET", "/v1/node")  # even a valid node behind that address waits
    assert (blocked.status, blocked.error) == (429, "rate_limited")
    env.clock.advance(minutes=2)
    assert (await node.call("GET", "/v1/node")).status == 200


async def test_nonces_are_stored_with_ttl(env: Env) -> None:
    node = await _member(env)
    await node.call("GET", "/v1/node")
    async with env.worker() as s:
        assert (await s.execute(select(func.count()).select_from(Nonce))).scalar_one() == 1
        expires = (await s.execute(select(Nonce.expires_at))).scalar_one()
    assert (expires - env.clock()).total_seconds() == pytest.approx(600, abs=1)


async def test_unknown_route_and_method_are_signed_errors(env: Env) -> None:
    node = await _member(env)
    nonce = sign.new_nonce()
    resp = await env.http.get("/v1/nothing", headers={sign.H_NONCE: nonce})
    assert resp.status_code == 404 and resp.json() == {"error": "invalid_payload"}
    assert sign.verify_response(
        env.hub_key, resp.headers[sign.H_HUB_SIGNATURE], nonce, 404, resp.content
    )
    resp = await env.http.get("/openapi.json")
    assert resp.status_code == 404
    assert node.node_id

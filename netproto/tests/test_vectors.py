"""Golden vectors: the values in vectors.json are the contract for every implementation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from suckerpot_netproto import blind, pow, sign

V = json.loads((Path(__file__).parent / "vectors.json").read_text())
NODE_SEED = bytes.fromhex(V["node"]["private_seed_hex"])
HUB_SEED = bytes.fromhex(V["hub"]["private_seed_hex"])


def test_keys() -> None:
    pub = sign.public_key_of(NODE_SEED)
    assert pub.hex() == V["node"]["public_hex"]
    assert sign.node_key(pub) == V["node"]["node_key"]
    assert sign.fingerprint(pub) == V["node"]["fingerprint"]
    assert sign.parse_node_key(V["node"]["node_key"]) == pub
    assert sign.node_key(sign.public_key_of(HUB_SEED)) == V["hub"]["hub_key"]


@pytest.mark.parametrize("case", V["requests"], ids=lambda c: c["target"])
def test_request_vectors(case: dict[str, Any]) -> None:
    body = case["body"].encode()
    canonical = sign.canonical_request(
        case["method"], case["target"], V["timestamp"], V["nonce"], body
    )
    assert canonical == case["canonical"]
    headers = sign.sign_request(
        NODE_SEED, case["method"], case["target"], body, timestamp=V["timestamp"], nonce=V["nonce"]
    )
    assert headers.signature == case["signature"]  # Ed25519 is deterministic
    pub = sign.public_key_of(NODE_SEED)
    assert sign.verify_request(
        pub,
        case["signature"],
        case["method"],
        case["target"],
        str(V["timestamp"]),
        V["nonce"],
        body,
    )


@pytest.mark.parametrize("case", V["responses"], ids=lambda c: c["name"])
def test_response_vectors(case: dict[str, Any]) -> None:
    body = case["body"].encode()
    binding = sign.RequestBinding(
        case["method"], case["target"], V["nonce"], case["node"], case["digest"]
    )
    assert sign.canonical_response(binding, case["status"], body) == case["canonical"]
    assert sign.sign_response(HUB_SEED, binding, case["status"], body) == case["signature"]
    assert sign.verify_response(
        V["hub"]["hub_key"], case["signature"], binding, case["status"], body
    )


@pytest.mark.parametrize("case", V["blind_urls"], ids=lambda c: c["input"])
def test_url_vectors(case: dict[str, Any]) -> None:
    assert blind.canonical_url(case["input"]) == case["canonical"]
    assert blind.blind_url(case["input"]) == case["value_b"]


@pytest.mark.parametrize("case", V["blind_domains"], ids=lambda c: c["input"])
def test_domain_vectors(case: dict[str, Any]) -> None:
    assert blind.canonical_domain(case["input"]) == case["canonical"]
    assert blind.blind_domain(case["input"]) == case["value_b"]


def test_pow_vector() -> None:
    p = V["pow"]
    challenge, pub, nonce = (
        bytes.fromhex(p["challenge_hex"]),
        bytes.fromhex(p["pubkey_hex"]),
        bytes.fromhex(p["pow_nonce_hex"]),
    )
    assert pow.pow_digest(challenge, pub, nonce).hex() == p["digest_hex"]
    assert pow.verify_pow(challenge, pub, nonce, p["difficulty"])

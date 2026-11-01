"""Regenerate ``vectors.json`` (``python tests/gen_vectors.py``).

The file is the contract: other implementations must reproduce every value. Regenerate it only
when the spec changes, and review the diff. Keys are fixed test keys, never used anywhere else.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from suckerpot_netproto import blind, pow, sign

NODE_SEED = bytes(range(32))
HUB_SEED = bytes(range(32, 64))
TIMESTAMP = 1790000000
NONCE = sign.b64u_encode(bytes(range(16)))

URLS = [
    "http://198.51.100.9/bins/mirai.arm",
    "HTTP://Example.ORG:80/a/B?x=1&y=%2F#frag",
    "https://example.org:443/",
    "https://example.org:8443/x",
    "http://bücher.example.org/p",
    "http://[2001:db8::1]:80/x.sh",
    "ftp://example.org:21/f",
    "http://example.org",
]
DOMAINS = ["Example.ORG.", "bücher.example.org", "cnc.example.org"]


def build() -> dict[str, object]:
    pub = sign.public_key_of(NODE_SEED)
    hub_pub = sign.public_key_of(HUB_SEED)
    requests = []
    for method, target, body in (
        ("GET", "/v1/info", b""),
        ("GET", "/v1/targets?since=c_12&limit=1000", b""),
        ("POST", "/v1/reveals", b'{"protocol":"spn/1","items":[],"pad":""}'),
    ):
        headers = sign.sign_request(
            NODE_SEED, method, target, body, timestamp=TIMESTAMP, nonce=NONCE
        )
        requests.append(
            {
                "method": method,
                "target": target,
                "body": body.decode(),
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "canonical": sign.canonical_request(method, target, TIMESTAMP, NONCE, body),
                "signature": headers.signature,
            }
        )
    responses = []
    for status, body in ((200, b'{"deleted":true}'), (429, b'{"error":"rate_limited"}')):
        responses.append(
            {
                "status": status,
                "body": body.decode(),
                "canonical": sign.canonical_response(NONCE, status, body),
                "signature": sign.sign_response(HUB_SEED, NONCE, status, body),
            }
        )
    challenge = hashlib.sha256(b"spn/1 test challenge").digest()
    nonce = pow.solve_pow(challenge, pub, 12)
    assert nonce is not None
    return {
        "node": {
            "private_seed_hex": NODE_SEED.hex(),
            "public_hex": pub.hex(),
            "node_key": sign.node_key(pub),
            "fingerprint": sign.fingerprint(pub),
        },
        "hub": {
            "private_seed_hex": HUB_SEED.hex(),
            "public_hex": hub_pub.hex(),
            "hub_key": sign.node_key(hub_pub),
        },
        "timestamp": TIMESTAMP,
        "nonce": NONCE,
        "requests": requests,
        "responses": responses,
        "blind_urls": [
            {"input": u, "canonical": blind.canonical_url(u), "value_b": blind.blind_url(u)}
            for u in URLS
        ],
        "blind_domains": [
            {"input": d, "canonical": blind.canonical_domain(d), "value_b": blind.blind_domain(d)}
            for d in DOMAINS
        ],
        "pow": {
            "challenge_hex": challenge.hex(),
            "pubkey_hex": pub.hex(),
            "difficulty": 12,
            "pow_nonce_hex": nonce.hex(),
            "digest_hex": pow.pow_digest(challenge, pub, nonce).hex(),
        },
    }


if __name__ == "__main__":
    out = Path(__file__).with_name("vectors.json")
    out.write_text(json.dumps(build(), indent=2, ensure_ascii=True) + "\n")
    print(f"wrote {out}")

from __future__ import annotations

import json

import pytest

from suckerpot_netproto import ProtoError, sign


def test_roundtrip_and_tamper() -> None:
    priv = sign.generate_private_key()
    pub = sign.public_key_of(priv)
    body = b'{"protocol":"spn/1"}'
    h = sign.sign_request(priv, "post", "/v1/enrol", body, timestamp=1_790_000_000)
    args = (pub, h.signature, "POST", "/v1/enrol", h.timestamp, h.nonce, body)
    assert sign.verify_request(*args)
    # every signed component matters
    assert not sign.verify_request(pub, h.signature, "GET", "/v1/enrol", h.timestamp, h.nonce, body)
    assert not sign.verify_request(pub, h.signature, "POST", "/v1/node", h.timestamp, h.nonce, body)
    assert not sign.verify_request(pub, h.signature, "POST", "/v1/enrol", "1", h.nonce, body)
    assert not sign.verify_request(
        pub, h.signature, "POST", "/v1/enrol", h.timestamp, sign.new_nonce(), body
    )
    assert not sign.verify_request(
        pub, h.signature, "POST", "/v1/enrol", h.timestamp, h.nonce, body + b" "
    )
    other = sign.public_key_of(sign.generate_private_key())
    assert not sign.verify_request(
        other, h.signature, "POST", "/v1/enrol", h.timestamp, h.nonce, body
    )


def test_verify_never_raises_on_garbage() -> None:
    pub = sign.public_key_of(sign.generate_private_key())
    for bad in ("", "!!!", "A" * 86, "A" * 5):
        assert not sign.verify_request(pub, bad, "GET", "/v1/info", "1", "n", b"")


def test_response_bound_to_request_nonce() -> None:
    hub = sign.generate_private_key()
    key = sign.node_key(sign.public_key_of(hub))
    nonce = sign.new_nonce()
    sig = sign.sign_response(hub, nonce, 200, b"{}")
    assert sign.verify_response(key, sig, nonce, 200, b"{}")
    assert not sign.verify_response(key, sig, sign.new_nonce(), 200, b"{}")  # replayed answer
    assert not sign.verify_response(key, sig, nonce, 201, b"{}")
    assert not sign.verify_response(key, sig, nonce, 200, b"{ }")
    assert not sign.verify_response(key, None, nonce, 200, b"{}")
    assert not sign.verify_response("bad", sig, nonce, 200, b"{}")
    wrong = sign.node_key(sign.public_key_of(sign.generate_private_key()))
    assert not sign.verify_response(wrong, sig, nonce, 200, b"{}")
    with pytest.raises(ProtoError) as err:
        sign.require_response(wrong, sig, nonce, 200, b"{}")
    assert err.value.code == "hub_signature"


def test_b64u_strict() -> None:
    assert sign.b64u_decode(sign.b64u_encode(b"\x00\xff" * 8)) == b"\x00\xff" * 8
    for bad in ("AA==", "A", "AB", "a+b/", " AAAA"):
        with pytest.raises(ValueError):
            sign.b64u_decode(bad)


def test_header_parsing() -> None:
    priv = sign.generate_private_key()
    h = sign.sign_request(priv, "GET", "/v1/node", b"", timestamp=1_790_000_000)
    parsed = sign.parse_request_headers(h.key, h.timestamp, h.nonce, h.signature)
    assert parsed.timestamp == 1_790_000_000
    assert parsed.public == sign.public_key_of(priv)
    for args in (
        (None, h.timestamp, h.nonce, h.signature),
        (h.key, "12x", h.nonce, h.signature),
        (h.key, h.timestamp, "short", h.signature),
        (h.key, h.timestamp, h.nonce, "short"),
        ("short", h.timestamp, h.nonce, h.signature),
    ):
        with pytest.raises(ProtoError) as err:
            sign.parse_request_headers(*args)
        assert err.value.code == "invalid_payload"


def test_timestamp_window() -> None:
    sign.check_timestamp(1000, 1300)
    sign.check_timestamp(1300, 1000)
    for ts in (699, 1301):
        with pytest.raises(ProtoError) as err:
            sign.check_timestamp(ts, 1000)
        assert err.value.code == "stale_timestamp"


def test_padding() -> None:
    for payload in ({"protocol": "spn/1"}, {"a": "x" * 5000}, {"a": "x" * 4000}):
        raw = sign.pad_body(payload)
        assert len(raw) % 4096 == 0 and sign.is_padded(raw)
        parsed = json.loads(raw)
        assert parsed["pad"].strip(" ") == ""
        assert {k: v for k, v in parsed.items() if k != "pad"} == payload
    # an existing pad is replaced, not stacked
    again = sign.pad_body(json.loads(sign.pad_body({"a": 1})))
    assert len(again) == 4096
    # non-ASCII stays ASCII so the byte length equals the character length
    assert len(sign.pad_body({"a": "é" * 10})) % 4096 == 0

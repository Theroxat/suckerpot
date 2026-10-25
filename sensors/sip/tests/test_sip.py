"""Parser and response builder: malformed, oversized and pathological input."""

from __future__ import annotations

import time

import pytest

from sip_sensor import sip
from tests.conftest import minimal_request, sip_request


def test_parse_basic_request() -> None:
    msg = sip.parse(sip_request("REGISTER", "sip:pbx.example.net"))
    assert msg.is_request and msg.method == "REGISTER"
    assert msg.get("call-id") == "abc123@198.51.100.7"
    assert msg.get("user-agent") == "friendly-scanner"
    assert len(msg.get_all("via")) == 1


def test_compact_headers_and_folding() -> None:
    raw = (
        b"OPTIONS sip:x@y SIP/2.0\r\nv: SIP/2.0/UDP 1.2.3.4\r\nf: <sip:a@b>;tag=1\r\n"
        b"t: <sip:c@d>\r\ni: id1\r\nCSeq: 1 OPTIONS\r\nSubject: one\r\n two\r\n\r\n"
    )
    msg = sip.parse(raw)
    assert msg.get("via") and msg.get("from") and msg.get("to") and msg.get("call-id") == "id1"
    assert msg.get("subject") == "one two"


def test_parse_response_and_bad_status() -> None:
    assert not sip.parse(b"SIP/2.0 200 OK\r\nCSeq: 1 OPTIONS\r\n\r\n").is_request
    with pytest.raises(sip.ParseError):
        sip.parse(b"SIP/2.0 2000 OK\r\n\r\n")


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\x00\x01\x02",
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        b"OPTIONS sip:x\r\n\r\n",
        b"OPTIONS sip:x SIP/2.0\r\nnocolonhere\r\n\r\n",
        b"OPTIONS sip:x SIP/2.0\r\nContent-Length: abc\r\n\r\n",
        b"OPTIONS sip:x SIP/2.0\r\nContent-Length: 999999\r\n\r\n",
        b"OPTIONS " + b"A" * 600 + b" SIP/2.0\r\n\r\n",
        b"OPTIONS sip:x SIP/2.0\r\nX: " + b"A" * 1100 + b"\r\n\r\n",
        b"OPTIONS sip:x SIP/2.0\r\n" + b"X: 1\r\n" * 65 + b"\r\n",
        b"A" * 5000,
    ],
)
def test_malformed_input_rejected(raw: bytes) -> None:
    with pytest.raises(sip.ParseError):
        sip.parse(raw)


def test_body_is_bounded_by_content_length() -> None:
    msg = sip.parse(sip_request("MESSAGE", body="x" * 1000))
    assert len(msg.body) == sip.MAX_BODY_PREVIEW


def test_pathological_inputs_are_fast() -> None:
    cases = [
        b"OPTIONS sip:x SIP/2.0\r\n" + b"\r\n " * 1000,
        b"OPTIONS sip:x SIP/2.0\r\n" + b"a:" * 2000,
        b"OPTIONS sip:x SIP/2.0\r\nAuthorization: Digest " + b'a="' * 1300 + b"\r\n\r\n",
        b"OPTIONS sip:x SIP/2.0\r\nVia: " + b"," * 1000 + b"\r\n\r\n",
        b"\r\n" * 2000,
        b"<" * 4000,
    ]
    started = time.perf_counter()
    for _ in range(50):
        for raw in cases:
            try:
                sip.parse(raw)
            except sip.ParseError:
                pass
    assert time.perf_counter() - started < 1.0


def test_digest_parser_bounds_and_quotes() -> None:
    params = sip.parse_digest('Digest username="a,b", realm="r\\"x", nonce=abc, response="ff"')
    assert params["username"] == "a,b" and params["realm"] == 'r"x' and params["nonce"] == "abc"
    big = "Digest " + ", ".join(f"k{i}=v" for i in range(500))
    assert len(sip.parse_digest(big)) <= sip.MAX_DIGEST_PARAMS
    assert sip.parse_digest("Basic abc") == {}
    started = time.perf_counter()
    sip.parse_digest("Digest " + "a" * 4000)
    sip.parse_digest("Digest " + '"' * 4000)
    sip.parse_digest("Digest " + "=" * 4000)
    assert time.perf_counter() - started < 0.2


@pytest.mark.parametrize(
    ("number", "expected"),
    [
        ("+41791234567", True),
        ("0041791234567", True),
        ("00441234567", True),
        ("011442071234", True),
        ("100", False),
        ("0791234567", False),
        ("+12", False),
        ("abc", False),
        ("", False),
    ],
)
def test_international_detection(number: str, expected: bool) -> None:
    assert sip.is_international(number) is expected


def test_uri_helpers() -> None:
    assert sip.uri_of('"Bob" <sip:bob@host;transport=udp>;tag=1') == "sip:bob@host;transport=udp"
    assert sip.user_part("sip:0041791234567@gw.example.net:5060") == "0041791234567"
    assert sip.user_part("sip:pbx.example.net") == ""
    assert sip.user_part("tel:+41791234567") == "+41791234567"


def test_response_never_exceeds_max_size() -> None:
    req = sip.parse(minimal_request())
    full = sip.build_response(req, 200, to_tag="as1", optional=("Allow: " + "x" * 300,))
    assert full is not None
    cap = len(minimal_request())
    out = sip.build_response(
        req, 200, to_tag="as1", optional=("Allow: " + "x" * 300,), max_size=cap
    )
    assert out is not None and len(out) <= cap
    # A required header that cannot fit means silence, not a bigger packet.
    assert (
        sip.build_response(req, 401, to_tag="as1", required=("X: " + "y" * 500,), max_size=cap)
        is None
    )

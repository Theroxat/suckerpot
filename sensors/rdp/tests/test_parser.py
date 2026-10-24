"""Parser unit tests: valid requests, malformed lengths, truncation and pathological input."""

from __future__ import annotations

import os
import struct
import time

import pytest

from rdp_sensor import probe, protocol
from rdp_sensor.protocol import ParseError, build_connection_request, parse_connection_request

NMAP_COOKIE_PROBE = b"\x03\0\0*%\xe0\0\0\0\0\0Cookie: mstshash=nmap\r\n\x01\0\x08\0\x03\0\0\0"
NMAP_BARE_PROBE = b"\x03\0\0\x0b\x06\xe0\0\0\0\0\0"


def test_nmap_cookie_probe() -> None:
    cr = parse_connection_request(NMAP_COOKIE_PROBE)
    assert cr.username == "nmap"
    assert cr.neg_present and cr.requested_protocols == 3
    assert cr.requested_protocol_names == ["SSL", "HYBRID"]
    neg = protocol.negotiate(cr)
    assert neg.response == bytes.fromhex("030000130ed00000123400021f080002000000")
    assert neg.summary == "HYBRID"


def test_bare_probe_gets_legacy_confirm() -> None:
    cr = parse_connection_request(NMAP_BARE_PROBE)
    assert cr.username is None and not cr.neg_present
    neg = protocol.negotiate(cr)
    assert neg.response == bytes.fromhex("0300000b06d00000123400")
    assert neg.outcome == "legacy"


@pytest.mark.parametrize(
    ("protocols", "outcome", "selected"),
    [
        (0, "failure", None),
        (1, "failure", None),
        (4, "failure", None),
        (2, "selected", 2),
        (3, "selected", 2),
        (0x0B, "selected", 8),
        (8, "selected", 8),
    ],
)
def test_negotiation_matrix(protocols: int, outcome: str, selected: int | None) -> None:
    neg = protocol.negotiate(
        parse_connection_request(build_connection_request(protocols=protocols))
    )
    assert neg.outcome == outcome
    assert neg.selected_protocol == selected
    if outcome == "failure":
        assert neg.response == bytes.fromhex("030000130ed000001234000300080005000000")
        assert neg.summary == "HYBRID_REQUIRED_BY_SERVER"


def test_routing_token_and_correlation() -> None:
    pkt = build_connection_request(
        cookie=b"Cookie: msts=3640205228.15629.0000", protocols=3, correlation=b"\x11" * 16
    )
    cr = parse_connection_request(pkt)
    assert cr.routing_token == "3640205228.15629.0000"
    assert cr.username is None
    assert cr.correlation_id == "11" * 16
    assert cr.trailing_bytes == 0


def test_other_cookie_and_unterminated() -> None:
    cr = parse_connection_request(build_connection_request(cookie=b"Cookie: foo=bar"))
    assert cr.other_cookie == "foo=bar"
    body = b"Cookie: mstshash=administrator"
    li = 6 + len(body)
    pkt = struct.pack(">BBHBBHHB", 3, 0, li + 5, li, 0xE0, 0, 0, 0) + body
    cr = parse_connection_request(pkt)
    assert cr.username == "administrator" and cr.cookie_unterminated


def test_non_ascii_username_kept() -> None:
    cr = parse_connection_request(
        build_connection_request(cookie="Cookie: mstshash=Jürgen".encode())
    )
    assert cr.username == "Jürgen"


@pytest.mark.parametrize(
    ("packet", "reason"),
    [
        (b"\x03\x00", "short_tpkt_header"),
        (b"\x04\x00\x00\x0b\x06\xe0\0\0\0\0\0", "bad_tpkt_version"),
        (b"\x03\x01\x00\x0b\x06\xe0\0\0\0\0\0", "bad_tpkt_version"),
        (b"\x03\x00\x00\x05\x00", "tpkt_too_short"),
        (b"\x03\x00\xff\xff" + b"\0" * 20, "tpkt_too_long"),
        (b"\x03\x00\x00\x0b\x07\xe0\0\0\0\0\0", "bad_length_indicator"),
        (b"\x03\x00\x00\x0b\x06\xf0\0\0\0\0\0", "not_connection_request"),
        (b"\x03\x00\x00\x0c\x06\xe0\0\0\0\0\0", "length_mismatch"),
        (b"\x03\x00\x01\x10" + b"\0" * 268, "cr_too_long"),
    ],
)
def test_framing_errors(packet: bytes, reason: str) -> None:
    with pytest.raises(ParseError) as err:
        parse_connection_request(packet)
    assert err.value.reason == reason


def test_bad_neg_length() -> None:
    pkt = bytearray(build_connection_request(protocols=3))
    pkt[13] = 9  # RDP_NEG_REQ.length
    with pytest.raises(ParseError, match="bad_neg_req_length"):
        parse_connection_request(bytes(pkt))


def test_truncated_prefixes_never_crash() -> None:
    full = build_connection_request(
        cookie=b"Cookie: mstshash=admin", protocols=0x0B, correlation=b"x" * 16
    )
    for cut in range(len(full)):
        with pytest.raises(ParseError):
            parse_connection_request(full[:cut])


def test_random_fuzz_only_parse_errors() -> None:
    rng = __import__("random").Random(1234)
    for _ in range(5000):
        n = rng.randint(0, 300)
        data = bytearray(rng.getrandbits(8) for _ in range(n))
        if n >= 6 and rng.random() < 0.7:
            data[0:4] = struct.pack(">BBH", 3, 0, n)
            data[4] = (n - 5) & 0xFF
            data[5] = 0xE0
        try:
            cr = parse_connection_request(bytes(data))
        except ParseError:
            continue
        protocol.negotiate(cr)


def test_huge_cookie_cannot_fit() -> None:
    body = b"Cookie: mstshash=" + b"A" * 60000 + b"\r\n"
    pkt = struct.pack(">BBH", 3, 0, 0xFFFF) + b"\xff\xe0" + body
    t0 = time.perf_counter()
    with pytest.raises(ParseError):
        parse_connection_request(pkt)
    assert time.perf_counter() - t0 < 0.05


def test_max_size_cookie_ok() -> None:
    name = b"A" * (255 - 6 - len(protocol.COOKIE_MSTSHASH) - 2)
    pkt = build_connection_request(cookie=protocol.COOKIE_MSTSHASH + name)
    assert len(pkt) == protocol.MAX_CR_TPKT
    assert parse_connection_request(pkt).username == name.decode()


@pytest.mark.parametrize(
    "blob",
    [
        os.urandom(64 * 1024),
        b"\x03\x00" * 32768,
        b"Cookie: " * 8192,
        b"\x16\x03\x01" + b"\xff" * 65533,
        b"\r\n" * 32768,
        b"NTLMSSP\x00" * 8192,
        b"\x30\x84" * 32768,
    ],
)
def test_pathological_inputs_bounded(blob: bytes) -> None:
    t0 = time.perf_counter()
    with pytest.raises(ParseError):
        parse_connection_request(blob)
    probe.guess_protocol(blob)
    probe.hex_preview(blob)
    probe.ascii_preview(blob)
    probe.parse_client_hello(blob)
    probe.parse_ntlm_negotiate(blob)
    probe.credssp_version(blob)
    probe.tls_record_length(blob)
    assert time.perf_counter() - t0 < 0.25

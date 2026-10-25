"""Wire parsing: strict bounds and robustness against random input."""

from __future__ import annotations

import random

import pytest

from mysql_sensor import wire


def _response(caps: int, user: bytes = b"root", auth: bytes = b"", db: bytes = b"") -> bytes:
    out = caps.to_bytes(4, "little") + (1 << 24).to_bytes(4, "little") + bytes([255]) + b"\x00" * 23
    out += user + b"\x00"
    if caps & wire.CLIENT_PLUGIN_AUTH_LENENC:
        out += wire.lenenc_str(auth)
    else:
        out += bytes([len(auth)]) + auth
    if caps & wire.CLIENT_CONNECT_WITH_DB:
        out += db + b"\x00"
    if caps & wire.CLIENT_PLUGIN_AUTH:
        out += b"mysql_native_password\x00"
    return out


BASE = wire.CLIENT_PROTOCOL_41 | wire.CLIENT_SECURE_CONNECTION | wire.CLIENT_PLUGIN_AUTH


def test_parse_basic_response() -> None:
    r = wire.parse_handshake_response(
        _response(BASE | wire.CLIENT_CONNECT_WITH_DB, auth=b"\x01" * 20, db=b"shop")
    )
    assert (r.username, r.database, r.plugin) == ("root", "shop", "mysql_native_password")
    assert r.auth_response == b"\x01" * 20 and not r.ssl_request


def test_ssl_request_and_pre41() -> None:
    ssl_req = (BASE | wire.CLIENT_SSL).to_bytes(4, "little") + b"\x00" * 28
    assert wire.parse_handshake_response(ssl_req).ssl_request
    with pytest.raises(wire.PacketError):
        wire.parse_handshake_response(b"\x00" * 40)


def test_attrs_parsed_and_bounded() -> None:
    caps = BASE | wire.CLIENT_CONNECT_ATTRS
    pairs = b"".join(
        wire.lenenc_str(f"k{i}".encode()) + wire.lenenc_str(b"v" * 300) for i in range(80)
    )
    raw = _response(caps) + wire.lenenc_int(len(pairs)) + pairs
    attrs = wire.parse_handshake_response(raw).attrs
    assert len(attrs) <= wire.MAX_ATTRS or attrs == {}
    assert all(len(v) <= wire.MAX_ATTR_LEN for v in attrs.values())


def test_truncated_inputs_only_raise_packet_error() -> None:
    good = _response(
        BASE | wire.CLIENT_CONNECT_WITH_DB | wire.CLIENT_CONNECT_ATTRS, auth=b"a" * 20, db=b"d"
    )
    for n in range(len(good)):
        try:
            wire.parse_handshake_response(good[:n])
        except wire.PacketError:
            pass


def test_random_fuzz_never_crashes() -> None:
    rng = random.Random(7)
    for _ in range(3000):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200)))
        if rng.random() < 0.7 and len(blob) >= 4:
            blob = (BASE | rng.randrange(1 << 25)).to_bytes(4, "little") + blob[4:]
        try:
            wire.parse_handshake_response(blob)
        except wire.PacketError:
            pass
        try:
            wire.parse_change_user(b"\x11" + blob, rng.randrange(1 << 25))
        except wire.PacketError:
            pass


def test_lenenc_roundtrip() -> None:
    for n in (0, 250, 251, 65535, 65536, 1 << 24, 1 << 40):
        assert wire.Reader(wire.lenenc_int(n)).lenenc_int() == n
    with pytest.raises(wire.PacketError):
        wire.Reader(b"\xff").lenenc_int()
    with pytest.raises(wire.PacketError):
        wire.Reader(wire.lenenc_int(10_000_000)).lenenc_bytes(4096)


def test_handshake_layout() -> None:
    salt = bytes(range(1, 21))
    pkt = wire.handshake_payload(
        "8.0.43-0ubuntu0.24.04.2", 77, salt, wire.SERVER_CAPS, "caching_sha2_password", 2
    )
    assert pkt[0] == 10 and pkt.endswith(b"caching_sha2_password\x00")
    assert salt[:8] in pkt and salt[8:] + b"\x00" in pkt


def test_ok_packet_formats() -> None:
    plain = wire.ok_payload(info="Rows matched: 1")
    assert plain.endswith(b"Rows matched: 1") and b"\x0fRows" not in plain
    tracked = wire.ok_payload(info="Rows matched: 1", session_track=True)
    assert tracked.endswith(b"\x0fRows matched: 1")  # length-encoded with CLIENT_SESSION_TRACK
    assert wire.ok_payload(session_track=True)[-1:] == b"\x00"  # empty info, no session state


def test_result_set_metadata_flag_and_laziness() -> None:
    cols = [wire.Column("a")]
    rows: list[tuple[str | None, ...]] = [("1",), (None,)]
    plain = wire.result_set_payloads(cols, rows, wire.CLIENT_DEPRECATE_EOF)
    assert not isinstance(plain, list) and next(plain) == b"\x01"  # built on demand
    flagged = list(
        wire.result_set_payloads(
            cols, rows, wire.CLIENT_DEPRECATE_EOF | wire.CLIENT_OPTIONAL_RESULTSET_METADATA
        )
    )
    assert flagged[0] == b"\x01\x01" and flagged[-1][0] == 0xFE
    assert len(flagged) == 1 + 1 + 2 + 1


def test_query_attributes_parse_and_bounds() -> None:
    attrs = b"\x02\x01" + b"\x02" + b"\x01" + b"\xfd\x00\x01a" + b"\x08\x00\x01b"
    attrs += b"\x01x" + (7).to_bytes(8, "little")  # b is NULL (bit 1 of the bitmap)
    got = wire.parse_query_attributes(attrs.replace(b"\x01x" + (7).to_bytes(8, "little"), b"\x01x"))
    assert got.query == b"" and got.names == {"a": "x", "b": None}
    assert wire.parse_query_attributes(b"\x00\x01select 1").query == b"select 1"
    for bad in (b"", b"\x00", b"\x21\x01", b"\x01\x01\x00\x00\x99\x00\x01a", b"\x02\x01\x00"):
        with pytest.raises(wire.PacketError):
            wire.parse_query_attributes(bad)


def test_query_attribute_fuzz_never_crashes() -> None:
    rng = random.Random(11)
    for _ in range(3000):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 80)))
        try:
            wire.parse_query_attributes(blob)
        except wire.PacketError:
            pass

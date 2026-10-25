from __future__ import annotations

import struct
import time

import pytest
from tdsclient import batch, login7, packet, prelogin

from mssql_sensor import tds


def test_password_obfuscation_roundtrip() -> None:
    for pw in ("", "sa", "P@ssw0rd!", "pässwörd", "x" * 200):
        assert tds.decode_password(tds.encode_password(pw)) == pw


def test_known_password_vector() -> None:
    # 'a' = 0x61 0x00 -> nibble swap 0x16 0x00 -> xor 0xA5 -> 0xB3 0xA5
    assert tds.decode_password(bytes([0xB3, 0xA5])) == "a"


def test_parser_assembles_split_packet() -> None:
    wire = packet(tds.T_PRELOGIN, b"\xff")
    p = tds.PacketParser()
    for b in wire[:-1]:
        p.feed(bytes([b]))
        assert p.next_packet(first=True) is None
    p.feed(wire[-1:])
    pk = p.next_packet(first=True)
    assert pk is not None and pk.type == tds.T_PRELOGIN and pk.payload == b"\xff"
    assert p.held == 0


@pytest.mark.parametrize(
    "wire,reason",
    [
        (b"GET / HTTP/1.1\r\n", "bad_type"),
        (b"\x16\x03\x01\x02", "bad_type"),
        (b"\x00", "bad_type"),
        (bytes([0x12, 0x01, 0x00, 0x07, 0, 0, 1, 0]), "bad_length"),
        (bytes([0x12, 0x01, 0xFF, 0xFF, 0, 0, 1, 0]), "bad_length"),
        (bytes([0x12, 0x80, 0x00, 0x10, 0, 0, 1, 0]), "bad_status"),
        (bytes([0x01, 0x01, 0x00, 0x10, 0, 0, 1, 0]), "bad_type"),  # SQL batch first
    ],
)
def test_parser_rejects(wire: bytes, reason: str) -> None:
    p = tds.PacketParser()
    p.feed(wire)
    with pytest.raises(tds.TdsError) as err:
        p.next_packet(first=True)
    assert err.value.reason == reason


def test_parser_never_holds_more_than_one_packet_plus_chunk() -> None:
    p = tds.PacketParser()
    p.feed(bytes([0x12, 0x00, 0x7F, 0xFF, 0, 0, 1, 0]))  # claims 32767 bytes
    assert p.next_packet(first=True) is None
    p.feed(b"A" * 100)
    assert p.held == 108


def test_prelogin_reply_matches_known_shape() -> None:
    reply = tds.build_prelogin_reply((15, 0, 4375, 4), tds.ENC_NOT_SUP)
    pkt = tds.frame(tds.T_REPLY, reply, 4096, 0)[0]
    assert pkt[:8] == bytes([4, 1, 0, 0x2B, 0, 0, 1, 0])
    assert len(pkt) == 0x2B
    parsed = tds.parse_prelogin(reply)
    assert parsed.encryption == tds.ENC_NOT_SUP and parsed.version == (15, 0, 4375, 4)


def test_prelogin_parse_client() -> None:
    pl = tds.parse_prelogin(prelogin(tds.ENC_REQ)[8:])
    assert pl.encryption == tds.ENC_REQ and pl.version == (15, 0, 0x104C, 0)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x00",
        b"\x00\x00\x0b\x00\x06",
        b"\x00\x00\x0b\x00\x06\xff",
        b"\x00\xff\xff\xff\xff\xff",
    ],
)
def test_prelogin_malformed(payload: bytes) -> None:
    with pytest.raises(tds.TdsError):
        tds.parse_prelogin(payload)


def test_login7_decode() -> None:
    body = login7(
        "alice", "S3cret!", hostname="HOST1", app="sqlcmd", library="ODBC", database="appdb"
    )[8:]
    lg = tds.parse_login7(body)
    assert (lg.username, lg.password, lg.hostname) == ("alice", "S3cret!", "HOST1")
    assert (lg.app_name, lg.library, lg.database) == ("sqlcmd", "ODBC", "appdb")
    assert lg.tds_version == 0x74000004 and not lg.sspi


def test_login7_legacy_tds71_layout() -> None:
    body = login7("bob", "pw", version=0x71000001, legacy=True)[8:]
    lg = tds.parse_login7(body)
    assert (lg.username, lg.password) == ("bob", "pw")


def test_login7_truncated_and_lying_lengths() -> None:
    body = login7("alice", "pw")[8:]
    for cut in (0, 10, 85, 94, len(body) - 3):
        with pytest.raises(tds.TdsError):
            tds.parse_login7(body[:cut])
    # a field whose character count runs past the end of the message
    bad = bytearray(body)
    struct.pack_into("<H", bad, 42, 0xFFFF)
    with pytest.raises(tds.TdsError):
        tds.parse_login7(bytes(bad))
    # a total length larger than what was received
    bad = bytearray(body)
    struct.pack_into("<I", bad, 0, len(body) + 100)
    with pytest.raises(tds.TdsError):
        tds.parse_login7(bytes(bad))


def test_login7_oversized_fields_are_capped() -> None:
    body = login7("u" * 3000, "p" * 3000)[8:]
    lg = tds.parse_login7(body)
    assert len(lg.username) == tds.MAX_FIELD_CHARS
    assert len(lg.password) == tds.MAX_PASSWORD_CHARS
    assert "username" in lg.truncated


def test_batch_and_all_headers() -> None:
    assert tds.parse_batch(batch("select 1")[8:]) == "select 1"
    assert tds.parse_batch("select 2".encode("utf-16-le")) == "select 2"  # pre-7.2 client


def test_batch_decode_is_bounded() -> None:
    text = tds.parse_batch(("A" * 500_000).encode("utf-16-le"))
    assert len(text) == tds.MAX_SQL_BYTES // 2


def test_rpc_sp_executesql() -> None:
    name = struct.pack("<HH", 0xFFFF, 10) + struct.pack("<H", 0)
    sql = "select @@version".encode("utf-16-le")
    param = (
        b"\x00\x00"
        + b"\xe7"
        + struct.pack("<H", 8000)
        + bytes(5)
        + struct.pack("<H", len(sql))
        + sql
    )
    headers = struct.pack("<IIHQI", 22, 18, 2, 0, 1)[:22]
    proc, first = tds.parse_rpc(headers + name + param)
    assert proc == "sp_executesql" and first == "select @@version"


def test_rpc_malformed_never_raises_unexpected() -> None:
    for blob in (b"", b"\x01", b"\xff\xff", b"\x05\x00abc", b"\x00" * 30, bytes(range(256))):
        try:
            tds.parse_rpc(blob)
        except tds.TdsError:
            pass


def test_frame_splits_and_marks_eom() -> None:
    pkts = tds.frame(tds.T_REPLY, b"x" * 1200, 512, 55)
    assert len(pkts) == 3 and all(len(p) <= 512 for p in pkts)
    assert [p[1] for p in pkts] == [0, 0, 1]
    assert sum(len(p) - 8 for p in pkts) == 1200


def test_parsers_are_fast_on_hostile_input() -> None:
    blobs = [b"\xff" * 65536, b"\x00" * 65536, bytes(range(256)) * 256]
    start = time.perf_counter()
    for blob in blobs:
        for fn in (tds.parse_prelogin, tds.parse_login7, tds.parse_batch, tds.parse_rpc):
            try:
                fn(blob)
            except tds.TdsError:
                pass
    assert time.perf_counter() - start < 1.0

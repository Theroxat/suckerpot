"""Bounded parsers and the verification chain."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from suckerpot_netproto.feeds import (
    FeedError,
    minisign,
    parse_index,
    parse_list_json,
    parse_txt,
    render_json,
    verify_file_against_index,
    verify_index,
)
from suckerpot_netproto.feeds.models import MAX_INDEX_BYTES

from .test_feeds_common import (
    GEN,
    GOLDEN,
    SECRET,
    SECRET2,
    SERIAL,
    SETS,
    build_signed_index,
    ctx,
    entry,
)

# Built from parts so no private literal sits in the source (public repo hygiene).
PRIVATE_1 = ".".join(("10", "0", "0", "1"))
PRIVATE_2 = ".".join(("10", "0", "0", "2"))
PUB = SECRET.public
NOW = GEN + timedelta(hours=1)


def code(fn: Any, *args: Any, **kw: Any) -> str:
    with pytest.raises(FeedError) as e:
        fn(*args, **kw)
    return e.value.code


# --- txt --------------------------------------------------------------------------------------


def test_parse_txt_golden() -> None:
    parsed = parse_txt("outbound", (GOLDEN / "outbound.txt").read_bytes(), allow_documentation=True)
    assert parsed.values == ["192.0.2.77", "198.51.100.9", "203.0.113.50", "2001:db8::50"]
    assert parsed.invalid == 0
    dom = parse_txt("outbound-domains", (GOLDEN / "outbound-domains.txt").read_bytes())
    assert dom.values == ["cnc.example.org", "dl.example.net"]
    assert parse_txt("outbound", b"").values == []


def test_parse_txt_refuses_prefixes_private_and_wildcards() -> None:
    good = "\n".join(f"1.1.{i // 250}.{i % 250 + 1}" for i in range(250))
    for bad in ("198.51.100.0/24", PRIVATE_1, "*.example.org", "# comment", "", "8.8.8.8 ", "::1"):
        data = (good + "\n" + bad + "\n").encode()
        # one bad line in 251 is 0.4 %: dropped and counted
        parsed = parse_txt("outbound", data)
        assert parsed.invalid == 1 and bad not in parsed.values
        # the same bad line among a handful of lines is over 1 %
        assert code(parse_txt, "outbound", f"1.1.1.1\n{bad}\n".encode()) == "too_many_invalid"


def test_parse_txt_over_one_percent_invalid_is_rejected() -> None:
    lines = [f"1.1.{i // 250}.{i % 250 + 1}" for i in range(100)] + [PRIVATE_1, PRIVATE_2]
    assert code(parse_txt, "outbound", ("\n".join(lines) + "\n").encode()) == "too_many_invalid"
    assert parse_txt("outbound", ("\n".join(lines[:-1]) + "\n").encode()).invalid == 1  # 0.99 %


@pytest.mark.parametrize(
    "data",
    [b"1.1.1.1", b"1.1.1.1\r\n", b"1.1.1.1\x00\n", b"\xff\xfe\n", b"1.1.1.1\n\n\x00"],
)
def test_parse_txt_malformed_files_are_refused(data: bytes) -> None:
    assert code(parse_txt, "outbound", data) == "bad_format"


def test_parse_txt_duplicates_count_as_invalid() -> None:
    assert code(parse_txt, "outbound", b"1.1.1.1\n1.1.1.1\n") == "too_many_invalid"


def test_parse_txt_caps() -> None:
    assert code(parse_txt, "outbound", b"1.1.1.1\n" * 10, max_bytes=20) == "too_large"
    lines = "".join(f"1.1.{i // 250}.{i % 250 + 1}\n" for i in range(30)).encode()
    assert code(parse_txt, "outbound", lines, max_entries=29) == "too_large"
    big = b"1" * (16 * 1024 * 1024 + 1)
    assert code(parse_txt, "outbound", big) == "too_large"
    assert code(parse_txt, "nope", b"") == "bad_format"
    assert code(parse_txt, "outbound", b"1" * 300 + b"\n") == "too_many_invalid"


# --- list json --------------------------------------------------------------------------------


def doc(entries: Any, list_id: str = "outbound", **over: Any) -> bytes:
    obj = json.loads(render_json(ctx(list_id), []))
    obj["entries"] = entries
    obj.update(over)
    return json.dumps(obj).encode()


def test_parse_list_json_golden() -> None:
    parsed = parse_list_json(
        (GOLDEN / "outbound.json").read_bytes(), expected_list="outbound", allow_documentation=True
    )
    assert parsed.invalid == 0 and parsed.feed.serial == SERIAL
    assert [e.value for e in parsed.feed.entries][:2] == ["192.0.2.77", "198.51.100.9"]
    inbound = parse_list_json((GOLDEN / "inbound.json").read_bytes(), allow_documentation=True)
    first = next(e for e in inbound.feed.entries if e.value == "198.51.100.200")
    assert first.services == ["ssh", "telnet"]


def test_unknown_fields_are_ignored_at_every_level() -> None:
    e = {**entry("198.51.100.9", 4), "future_field": {"a": 1}}
    data = doc([e], future_top="x")
    parsed = parse_list_json(data, allow_documentation=True)
    assert [x.value for x in parsed.feed.entries] == ["198.51.100.9"] and parsed.invalid == 0


def test_invalid_entries_are_dropped_counted_and_over_one_percent_rejects() -> None:
    good = [entry(f"1.1.{i // 250}.{i % 250 + 1}", 4) for i in range(199)]
    bad = [
        entry(PRIVATE_1, 4),
        entry("198.51.100.0/24", 4),
        entry("x\ny", "dns"),
        {"value": 1},
        "str",
        entry("1.1.1.1", 4, tier="bogus"),
    ]
    parsed = parse_list_json(doc([*good, bad[0]]))
    assert parsed.invalid == 1 and len(parsed.feed.entries) == 199
    for b in bad:
        assert code(parse_list_json, doc([good[0], b])) == "too_many_invalid"


def test_parse_list_json_header_negatives() -> None:
    ok = [entry("198.51.100.9", 4)]
    cases = [
        doc(ok, schema="other/1"),
        doc(ok, list="inbound"),  # direction mismatch
        doc(ok, list="nope"),
        doc(ok, serial=-1),
        doc(ok, serial=1.5),
        doc(ok, generated_at="2026-11-01"),
        doc(ok, valid_until="2026-10-01T00:00:00Z"),
        doc(ok, licence="MIT"),
        doc("x"),
        b"[]",
        b"not json",
        b'{"a": NaN}',
        b"\xff",
        b"[" * 50_000 + b"]" * 50_000,
        json.dumps({"x": {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": 1}}}}}}}}}).encode(),
    ]
    for data in cases:
        assert code(parse_list_json, data, allow_documentation=True) == "bad_format", data[:60]
    assert (
        code(parse_list_json, doc(ok), expected_list="inbound", allow_documentation=True)
        == "bad_format"
    )


def test_parse_list_json_caps() -> None:
    ok = doc([entry("198.51.100.9", 4)])
    assert code(parse_list_json, ok, max_bytes=50) == "too_large"
    assert code(parse_list_json, doc([entry("1.1.1.1", 4)] * 3), max_entries=2) == "too_large"
    assert code(parse_list_json, b"{" + b" " * (16 * 1024 * 1024)) == "too_large"


def test_dns_and_address_kinds_must_fit_the_list() -> None:
    d = doc([entry("198.51.100.9", 4)], "outbound-domains")
    assert code(parse_list_json, d, allow_documentation=True) == "too_many_invalid"
    d2 = doc([entry("cnc.example.org", "dns")], "outbound")
    assert code(parse_list_json, d2) == "too_many_invalid"


# --- index and the whole chain ----------------------------------------------------------------


def test_golden_index_parses_and_verifies() -> None:
    raw = (GOLDEN / "index.json").read_bytes()
    sig = (GOLDEN / "index.json.minisig").read_text()
    index = verify_index(raw, sig, PUB, now=NOW, last_serial=SERIAL)
    assert index.serial == SERIAL and index.key_id == PUB.key_id_hex
    assert {lst.id for lst in index.lists} == {"outbound", "inbound", "outbound-domains"}
    assert index.find_file("outbound.nft") is not None and index.find_file("zzz") is None
    assert index.find_file("stats.json") is not None


def test_whole_chain_for_every_file() -> None:
    raw, sig, files, sigs = build_signed_index()
    index = verify_index(raw, sig, PUB, now=NOW)
    for name, data in files.items():
        verify_file_against_index(index, name, data, sigs[name], PUB)


def test_index_negatives() -> None:
    raw, sig, _files, _sigs = build_signed_index()
    # bad signature: tampered index
    tampered = raw.replace(b'"serial":4812', b'"serial":4813', 1)
    assert code(verify_index, tampered, sig, PUB, now=NOW) == "bad_signature"
    # wrong key (key rotation not announced)
    assert code(verify_index, raw, sig, SECRET2.public, now=NOW) == "wrong_key"
    # rollback
    assert code(verify_index, raw, sig, PUB, now=NOW, last_serial=SERIAL + 1) == "rollback"
    # expired
    assert code(verify_index, raw, sig, PUB, now=GEN + timedelta(days=3)) == "expired"
    # the index signed as another file
    other = minisign.sign_feed_file(raw, "outbound.txt", SERIAL, SECRET, timestamp=1)
    assert code(verify_index, raw, other, PUB, now=NOW) == "wrong_file"
    # signed serial differs from the index serial
    other = minisign.sign_feed_file(raw, "index.json", SERIAL - 1, SECRET, timestamp=1)
    assert code(verify_index, raw, other, PUB, now=NOW) == "wrong_serial"
    # an index that names another key than the one that signed it
    raw2, _sig2, *_ = build_signed_index(secret=SECRET2)
    forged = minisign.sign_feed_file(raw2, "index.json", SERIAL, SECRET, timestamp=1)
    assert code(verify_index, raw2, forged, PUB, now=NOW) == "wrong_key"
    # oversize
    assert code(verify_index, b" " * (MAX_INDEX_BYTES + 1), sig, PUB, now=NOW) == "too_large"
    # garbage that is validly signed is still refused
    junk = b'{"schema":"selfhostr-feeds/1"}'
    junk_sig = minisign.sign_feed_file(junk, "index.json", 1, SECRET, timestamp=1)
    assert code(verify_index, junk, junk_sig, PUB, now=NOW) == "bad_format"


def test_file_negatives() -> None:
    raw, sig, files, sigs = build_signed_index()
    index = verify_index(raw, sig, PUB, now=NOW)
    name = "outbound.txt"
    data = files[name]
    # sha256 / size mismatch
    assert (
        code(verify_file_against_index, index, name, data + b"1.1.1.1\n", sigs[name], PUB)
        == "hash_mismatch"
    )
    same_size = data.replace(b"1", b"2", 1)
    assert (
        code(verify_file_against_index, index, name, same_size, sigs[name], PUB) == "hash_mismatch"
    )
    # a valid signature for another file name (swap attack)
    swapped = minisign.sign_feed_file(data, "outbound.v4.txt", SERIAL, SECRET, timestamp=1)
    assert code(verify_file_against_index, index, name, data, swapped, PUB) == "wrong_file"
    # a valid signature of the right file but an old serial
    old = minisign.sign_feed_file(data, name, SERIAL - 1, SECRET, timestamp=1)
    assert code(verify_file_against_index, index, name, data, old, PUB) == "wrong_serial"
    # not listed in the index
    assert code(verify_file_against_index, index, "evil.txt", data, sigs[name], PUB) == "bad_format"
    # signature by another key
    foreign = minisign.sign_feed_file(data, name, SERIAL, SECRET2, timestamp=1)
    assert code(verify_file_against_index, index, name, data, foreign, PUB) == "wrong_key"


def test_index_schema_negatives() -> None:
    raw = json.loads((GOLDEN / "index.json").read_bytes())

    def with_(**kw: Any) -> bytes:
        return json.dumps({**raw, **kw}).encode()

    lst = raw["lists"][0]
    bad_lists = [
        [{**lst, "files": [{**lst["files"][0], "name": "../etc/passwd"}]}],
        [{**lst, "files": [{**lst["files"][0], "name": "a/b.txt"}]}],
        [{**lst, "files": [{**lst["files"][0], "sha256": "xyz"}]}],
        [{**lst, "files": [{**lst["files"][0], "format": "exe"}]}],
        [{**lst, "files": [lst["files"][0], lst["files"][0]]}],
        [{**lst, "tier": "high"}],
        [{**lst, "v4": 99999}],
        [lst, lst],
    ]
    for lists in bad_lists:
        assert code(parse_index, with_(lists=lists)) == "bad_format"
    assert code(parse_index, with_(key_id="abc")) == "bad_format"
    assert code(parse_index, with_(valid_until="2020-01-01T00:00:00Z")) == "bad_format"
    # unknown fields are ignored
    assert parse_index(with_(future={"x": 1})).serial == SERIAL


def test_expiry_boundary() -> None:
    raw, sig, *_ = build_signed_index()
    until = datetime(2026, 11, 4, 13, 0, 0, tzinfo=UTC)
    assert verify_index(raw, sig, PUB, now=until - timedelta(seconds=1)).serial == SERIAL
    assert code(verify_index, raw, sig, PUB, now=until) == "expired"


def test_sets_fixture_is_documentation_only() -> None:
    text = json.dumps(SETS)
    assert "example.org" in text or "example.net" in text

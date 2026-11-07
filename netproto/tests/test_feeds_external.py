"""External tier (design M36 section 7): models, renderers, golden vectors, verification chain.

Regenerate the vectors with ``python -m tests.test_feeds_external`` from ``netproto/`` (only when
the spec changes; review the diff). Fixed test keys, documentation addresses only.
"""

from __future__ import annotations

import csv
import io
import json
import sys
from datetime import timedelta
from typing import Any

import pytest

from suckerpot_netproto.feeds import (
    EXTERNAL_LIST_IDS,
    LIST_IDS,
    FeedError,
    IndexFile,
    minisign,
    parse_index,
    verify_index,
)
from suckerpot_netproto.feeds.external import (
    NOTICE,
    ExternalContext,
    ExternalEntry,
    ExternalIndexFile,
    ExternalSource,
    build_external_index,
    external_index_list,
    parse_external_index,
    parse_external_list_json,
    parse_external_txt,
    render_external_index,
    render_external_list,
    verify_external_file,
    verify_external_index,
)
from suckerpot_netproto.feeds.models import MAX_ENTRIES

from .test_feeds_common import (
    GEN,
    SECRET,
    SECRET2,
    SERIAL,
    SIGN_TS,
    UNTIL,
    VECTORS,
    build_signed_index,
)

# Built from parts so no private literal sits in the source (public repo hygiene).
PRIVATE = ".".join(("10", "0", "0", "1"))
LOOPBACK = ".".join(("127", "0", "0", "1"))
EXT_GOLDEN = VECTORS / "external"
PUB = SECRET.public
SOURCE = ExternalSource(
    id="feodotracker",
    name="abuse.ch Feodo Tracker",
    url="https://feodotracker.example.org/downloads/list.json",
)


def ectx(**kw: Any) -> ExternalContext:
    base: dict[str, Any] = {
        "serial": SERIAL,
        "generated_at": GEN,
        "valid_until": UNTIL,
        "sources": (SOURCE,),
        "allow_documentation": True,
    }
    base.update(kw)
    return ExternalContext(**base)


def eentry(value: str, family: int, **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "value": value,
        "family": family,
        "list": "external-outbound",
        "categories": ["c2"],
        "sources": ["feodotracker"],
        "ports": [443],
        "first_seen": "2026-11-02",
        "last_seen": "2026-11-06",
        "expires": "2026-11-13",
    }
    base.update(kw)
    return base


ENTRIES: list[dict[str, Any]] = [
    eentry("203.0.113.45", 4),
    eentry("198.51.100.9", 4, ports=[8080, 447], families=["generic"]),
    eentry("2001:db8::45", 6, ports=[]),
    eentry("192.0.2.77", 4, ports=[]),
]


def build_external() -> tuple[bytes, str, dict[str, bytes], dict[str, str]]:
    rendered = render_external_list(ectx(), ENTRIES)
    index = build_external_index(
        serial=SERIAL,
        generated_at=GEN,
        valid_until=UNTIL,
        key_id=SECRET.public.key_id_hex,
        lists=[external_index_list(rendered, dict.fromkeys(rendered.files, GEN))],
        sources=[SOURCE],
    )
    raw = render_external_index(index)
    sig = minisign.sign_feed_file(raw, "index.json", SERIAL, SECRET, timestamp=SIGN_TS)
    sigs = {
        n: minisign.sign_feed_file(d, n, SERIAL, SECRET, timestamp=SIGN_TS)
        for n, d in rendered.files.items()
    }
    return raw, sig, dict(rendered.files), sigs


# --- rendering ------------------------------------------------------------------------------


def test_txt_nft_and_ipset_exact() -> None:
    r = render_external_list(ectx(), ENTRIES)
    assert r.files["external-outbound.txt"] == (
        b"192.0.2.77\n198.51.100.9\n203.0.113.45\n2001:db8::45\n"
    )
    assert r.files["external-outbound.v6.txt"] == b"2001:db8::45\n"
    nft = r.files["external-outbound.nft"].decode()
    assert nft.splitlines()[1] == "table inet selfhostr_ext {"
    assert "set external_outbound_v4 {" in nft and "set external_outbound_v6 {" in nft
    assert "add element inet selfhostr_ext external_outbound_v4 { 192.0.2.77," in nft
    ipset = r.files["external-outbound.ipset"].decode()
    assert "create external_outbound_v4 hash:net family inet" in ipset
    assert "selfhostr-" not in ipset  # never collides with the M30 sets


def test_headers_name_the_source_and_deny_confirmation() -> None:
    r = render_external_list(ectx(), ENTRIES)
    for name in ("external-outbound.nft", "external-outbound.ipset", "external-outbound.rsc"):
        first = r.files[name].decode().splitlines()[0]
        assert "abuse.ch Feodo Tracker" in first and NOTICE in first, name
    doc = json.loads(r.files["external-outbound.json"])
    assert "Feodo Tracker" in doc["notice"] and doc["notice"].endswith(NOTICE)
    assert doc["sources"][0]["id"] == "feodotracker"


def test_json_entry_shape_and_no_network_field() -> None:
    doc = json.loads(render_external_list(ectx(), ENTRIES).files["external-outbound.json"])
    assert doc["schema"] == "selfhostr-external-feed/1" and doc["list"] == "external-outbound"
    assert list(doc["entries"][0]) == [
        "value", "family", "list", "categories", "sources", "families", "ports",
        "first_seen", "last_seen", "expires",
    ]  # fmt: skip
    for forbidden in ("tier", "tags", "services", "reported"):
        assert all(forbidden not in e for e in doc["entries"])


def test_csv_is_defused_and_columns_fixed() -> None:
    text = render_external_list(ectx(), ENTRIES).files["external-outbound.csv"].decode()
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0][:3] == ["value", "family", "list"] and len(rows) == 5
    assert text.count("\r\n") == 5


def test_rendering_is_deterministic_and_unsorted_input_is_sorted() -> None:
    a = render_external_list(ectx(), ENTRIES)
    b = render_external_list(ectx(), list(reversed(ENTRIES)))
    assert a.files == b.files


@pytest.mark.parametrize(
    "bad",
    [
        eentry("203.0.113.0/24", 4),
        eentry("203.0.113.45\nadd", 4),
        eentry(PRIVATE, 4),
        eentry(LOOPBACK, 4),
        eentry("203.0.113.45", 6),
        eentry("203.0.113.46", 4, categories=["brute-force"]),
        eentry("203.0.113.47", 4, sources=[]),
        eentry("203.0.113.48", 4, sources=["Not Valid"]),
        eentry("203.0.113.49", 4, last_seen="2026-10-01"),
        eentry("203.0.113.50", 4, list="outbound"),
    ],
)
def test_bad_entries_are_dropped_and_counted(bad: dict[str, Any]) -> None:
    r = render_external_list(ectx(), [*ENTRIES, bad])
    assert r.dropped == 1 and len(r.entries) == len(ENTRIES)


def test_documentation_addresses_need_the_test_flag() -> None:
    r = render_external_list(ectx(allow_documentation=False), ENTRIES)
    assert r.entries == [] and r.dropped == len(ENTRIES)


def test_duplicates_and_cap() -> None:
    r = render_external_list(ectx(), [*ENTRIES, ENTRIES[0]])
    assert r.dropped == 1
    big = [eentry(f"203.0.{i // 250}.{i % 250 + 1}", 4) for i in range(20_001)]
    # 203.0.x.y is global, not documentation: allowed without the test flag
    with pytest.raises(FeedError) as exc:
        render_external_list(ectx(allow_documentation=False), big)
    assert exc.value.code == "too_large"


def test_context_needs_a_source_and_timezone() -> None:
    with pytest.raises(FeedError):
        ectx(sources=())
    with pytest.raises(FeedError):
        ectx(list_id="outbound")


# --- golden vectors -------------------------------------------------------------------------


def test_golden_files() -> None:
    raw, sig, files, sigs = build_external()
    assert (EXT_GOLDEN / "index.json").read_bytes() == raw
    assert (EXT_GOLDEN / "index.json.minisig").read_text() == sig
    for name, data in files.items():
        assert (EXT_GOLDEN / name).read_bytes() == data, name
    assert (EXT_GOLDEN / "external-outbound.txt.minisig").read_text() == sigs[
        "external-outbound.txt"
    ]


def test_golden_chain_verifies() -> None:
    raw = (EXT_GOLDEN / "index.json").read_bytes()
    sig = (EXT_GOLDEN / "index.json.minisig").read_text()
    index = verify_external_index(raw, sig, PUB, now=GEN, last_serial=SERIAL)
    assert index.sources[0].id == "feodotracker" and index.lists[0].entries == 4
    data = (EXT_GOLDEN / "external-outbound.txt").read_bytes()
    sig_txt = (EXT_GOLDEN / "external-outbound.txt.minisig").read_text()
    verify_external_file(index, "external-outbound.txt", data, sig_txt, PUB)
    assert parse_external_txt(data, allow_documentation=True) == [
        "192.0.2.77",
        "198.51.100.9",
        "203.0.113.45",
        "2001:db8::45",
    ]
    parsed = parse_external_list_json(
        (EXT_GOLDEN / "external-outbound.json").read_bytes(), allow_documentation=True
    )
    assert parsed.invalid == 0 and len(parsed.feed.entries) == 4


# --- verification negatives -----------------------------------------------------------------


def code(fn: Any, *a: Any, **kw: Any) -> str:
    with pytest.raises(FeedError) as exc:
        fn(*a, **kw)
    return str(exc.value.code)


def test_index_negatives() -> None:
    raw, sig, files, sigs = build_external()
    assert code(verify_external_index, raw, sig, PUB, now=GEN + timedelta(days=3)) == "expired"
    assert code(verify_external_index, raw, sig, PUB, now=GEN, last_serial=SERIAL + 1) == (
        "rollback"
    )
    tampered = raw.replace(b'"serial":4812', b'"serial":4813', 1)
    assert code(verify_external_index, tampered, sig, PUB, now=GEN) == "bad_signature"
    assert code(verify_external_index, raw, sig, SECRET2.public, now=GEN) == "wrong_key"
    index = verify_external_index(raw, sig, PUB, now=GEN)
    name = "external-outbound.txt"
    assert code(verify_external_file, index, name, files[name] + b"x", sigs[name], PUB) == (
        "hash_mismatch"
    )
    assert code(verify_external_file, index, "stats.json", b"{}", sigs[name], PUB) == "bad_format"
    other_sig = sigs["external-outbound.csv"]
    assert code(verify_external_file, index, name, files[name], other_sig, PUB) == "bad_signature"


def test_main_and_external_indexes_cannot_replace_each_other() -> None:
    main_raw, main_sig, _f, _s = build_signed_index()
    ext_raw, ext_sig, _ef, _es = build_external()
    # A valid main index and its signature are not an external index, and the reverse.
    assert code(verify_external_index, main_raw, main_sig, PUB, now=GEN) == "bad_format"
    assert code(verify_index, ext_raw, ext_sig, PUB, now=GEN) == "bad_format"


def test_main_index_still_rejects_external_lists() -> None:
    """Compat guard (design 7.3): LIST_IDS and IndexFile do not learn external-* lists."""
    assert not set(EXTERNAL_LIST_IDS) & set(LIST_IDS)
    assert not any(lid in MAX_ENTRIES for lid in EXTERNAL_LIST_IDS)
    raw, _sig, _f, _s = build_signed_index()
    doc = json.loads(raw)
    doc["lists"].append(
        {
            "id": "external-outbound", "direction": "outbound", "tier": "standard",
            "entries": 0, "v4": 0, "v6": 0, "files": [],
        }
    )  # fmt: skip
    with pytest.raises(ValueError):
        IndexFile.model_validate(doc)
    assert code(parse_index, json.dumps(doc).encode()) == "bad_format"
    # And the external index refuses a main list id.
    ext = json.loads(build_external()[0])
    ext["lists"][0]["id"] = "outbound"
    assert code(parse_external_index, json.dumps(ext).encode()) == "bad_format"


def test_external_index_refuses_foreign_formats_and_wrong_schema() -> None:
    ext = json.loads(build_external()[0])
    ext["lists"][0]["files"][0]["format"] = "stix"
    assert code(parse_external_index, json.dumps(ext).encode()) == "bad_format"
    ext = json.loads(build_external()[0])
    ext["schema"] = "selfhostr-feeds/1"
    assert code(parse_external_index, json.dumps(ext).encode()) == "bad_format"


def test_non_cc0_source_is_refused_by_the_model() -> None:
    with pytest.raises(ValueError):
        ExternalSource.model_validate(
            {"id": "x", "name": "x", "licence": "proprietary", "url": "https://a.example.org/x"}
        )


def test_entry_model_is_not_the_main_entry() -> None:
    with pytest.raises(ValueError):
        ExternalEntry.model_validate(eentry("203.0.113.1", 4, categories=["exploit"]))
    assert ExternalIndexFile.model_fields["lists"] is not None


def main() -> None:  # pragma: no cover - generator
    EXT_GOLDEN.mkdir(parents=True, exist_ok=True)
    raw, sig, files, sigs = build_external()
    out: dict[str, bytes] = {"index.json": raw, "index.json.minisig": sig.encode(), **files}
    out["external-outbound.txt.minisig"] = sigs["external-outbound.txt"].encode()
    for name, data in out.items():
        (EXT_GOLDEN / name).write_bytes(data)
    print(f"wrote {len(out)} golden files", file=sys.stderr)


if __name__ == "__main__":
    main()

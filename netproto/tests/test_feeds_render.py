"""Renderers: exact outputs, golden files, injection and size negatives."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

import pytest

from suckerpot_netproto.feeds import (
    FeedError,
    clean_entries,
    render_csv,
    render_ipset,
    render_json,
    render_list,
    render_nft,
    render_rsc,
    render_stix,
    render_txt,
    render_txt_family,
)
from suckerpot_netproto.feeds.models import MAX_ENTRIES

from .test_feeds_common import GOLDEN, SETS, ctx, entry, render_all

OUT = ctx("outbound")


def cleaned(list_id: str = "outbound") -> list[Any]:
    return clean_entries(ctx(list_id), SETS[list_id])[0]


def test_txt_exact_sorted_ipv4_then_ipv6() -> None:
    assert render_txt(OUT, cleaned()) == "192.0.2.77\n198.51.100.9\n203.0.113.50\n2001:db8::50\n"
    assert render_txt_family(OUT, cleaned(), 4) == "192.0.2.77\n198.51.100.9\n203.0.113.50\n"
    assert render_txt_family(OUT, cleaned(), 6) == "2001:db8::50\n"


def test_txt_numeric_not_lexicographic_order() -> None:
    entries = clean_entries(
        OUT, [entry("203.0.113.9", 4), entry("203.0.113.100", 4), entry("203.0.113.20", 4)]
    )[0]
    assert render_txt(OUT, entries) == "203.0.113.9\n203.0.113.20\n203.0.113.100\n"


def test_nft_exact() -> None:
    assert render_nft(OUT, cleaned()) == (
        "# selfhostr outbound serial 4812 generated 2026-11-01T13:00:00Z licence CC0-1.0\n"
        "table inet selfhostr {\n"
        "  set outbound_v4 { type ipv4_addr; flags interval; auto-merge; }\n"
        "  set outbound_v6 { type ipv6_addr; flags interval; auto-merge; }\n"
        "}\n"
        "flush set inet selfhostr outbound_v4\n"
        "flush set inet selfhostr outbound_v6\n"
        "add element inet selfhostr outbound_v4 { 192.0.2.77, 198.51.100.9, 203.0.113.50 }\n"
        "add element inet selfhostr outbound_v6 { 2001:db8::50 }\n"
    )


def test_nft_empty_v6_set_has_no_add_element_line() -> None:
    entries = clean_entries(OUT, [entry("198.51.100.9", 4)])[0]
    text = render_nft(OUT, entries)
    assert "add element inet selfhostr outbound_v4 { 198.51.100.9 }\n" in text
    assert "add element inet selfhostr outbound_v6" not in text
    assert "{ }" not in text and "{  }" not in text
    assert "flush set inet selfhostr outbound_v6\n" in text


def test_nft_set_name_dash_becomes_underscore() -> None:
    inbound = ctx("inbound-high")
    text = render_nft(inbound, [])
    assert "set inbound_high_v4" in text and "inbound-high" in text.splitlines()[0]
    assert "add element" not in text


def test_ipset_exact_and_maxelem_fixed_per_list() -> None:
    entries = clean_entries(OUT, [entry("198.51.100.9", 4)])[0]
    assert render_ipset(OUT, entries) == (
        "# selfhostr outbound serial 4812 generated 2026-11-01T13:00:00Z licence CC0-1.0\n"
        "create selfhostr-outbound-v4 hash:net family inet hashsize 4096 maxelem 32768 -exist\n"
        "create selfhostr-outbound-v4-new hash:net family inet hashsize 4096 maxelem 32768 -exist\n"
        "flush selfhostr-outbound-v4-new\n"
        "add selfhostr-outbound-v4-new 198.51.100.9\n"
        "swap selfhostr-outbound-v4-new selfhostr-outbound-v4\n"
        "destroy selfhostr-outbound-v4-new\n"
        "create selfhostr-outbound-v6 hash:net family inet6 hashsize 1024 maxelem 32768 -exist\n"
        "create selfhostr-outbound-v6-new hash:net family inet6 hashsize 1024 maxelem 32768 -exist\n"
        "flush selfhostr-outbound-v6-new\n"
        "swap selfhostr-outbound-v6-new selfhostr-outbound-v6\n"
        "destroy selfhostr-outbound-v6-new\n"
    )
    assert "maxelem 65536" in render_ipset(ctx("inbound"), [])  # 50,000 rounded up


def test_rsc_exact() -> None:
    entries = clean_entries(OUT, [entry("198.51.100.9", 4), entry("2001:db8::50", 6)])[0]
    assert render_rsc(OUT, entries) == (
        "# selfhostr outbound serial 4812\n"
        ":local t 1d6h\n"
        "/ip firewall address-list\n"
        ":do { add list=selfhostr-outbound address=198.51.100.9 timeout=$t comment=selfhostr } "
        "on-error={ set [find list=selfhostr-outbound address=198.51.100.9] timeout=$t }\n"
        "/ipv6 firewall address-list\n"
        ":do { add list=selfhostr-outbound address=2001:db8::50/128 timeout=$t comment=selfhostr }"
        " on-error={ set [find list=selfhostr-outbound address=2001:db8::50/128] timeout=$t }\n"
    )


def test_csv_exact_crlf_and_columns() -> None:
    entries = clean_entries(
        ctx("inbound"), [entry("198.51.100.200", 4, categories=["brute-force"], services=["ssh"],
                               tags=["mirai", "recon"])]
    )[0]  # fmt: skip
    assert render_csv(ctx("inbound"), entries) == (
        "value,family,list,tier,categories,services,tags,families,ports,first_seen,last_seen,"
        "expires,reported\r\n"
        "198.51.100.200,4,inbound,standard,brute-force,ssh,mirai;recon,,,2026-10-26,2026-10-31,"
        "2026-11-14,false\r\n"
    )


def test_csv_cells_defuse_formulas() -> None:
    from suckerpot_netproto.feeds.render import csv_cell

    for evil in ("=1+1", "+cmd", "-2", "@SUM(A1)", "\tx", "\rx"):
        assert csv_cell(evil).startswith("'")
    assert csv_cell("a\nb") == "a b"
    assert csv_cell(["x", "=y"]) == "x;'=y"
    assert csv_cell(True) == "true"
    assert csv_cell("a\x00b\x1bc") == "abc"


def test_csv_roundtrips_through_a_csv_reader() -> None:
    text = render_csv(OUT, cleaned())
    rows = list(csv.reader(io.StringIO(text, newline="")))
    assert len(rows) == 5 and all(len(r) == 13 for r in rows)


def test_json_exact_inbound_and_outbound_shapes() -> None:
    obj = json.loads(render_json(OUT, cleaned()))
    assert list(obj) == [
        "schema", "list", "direction", "serial", "generated_at", "valid_until", "licence",
        "policy", "entries",
    ]  # fmt: skip
    assert next(e for e in obj["entries"] if e["value"] == "198.51.100.9") == {
        "value": "198.51.100.9", "family": 4, "tier": "high", "categories": ["payload-host"],
        "tags": ["mirai"], "families": ["mirai"], "ports": [], "first_seen": "2026-10-26",
        "last_seen": "2026-10-31", "expires": "2026-11-14", "reported": True,
    }  # fmt: skip
    inbound = json.loads(render_json(ctx("inbound"), cleaned("inbound")))
    first = next(e for e in inbound["entries"] if e["value"] == "198.51.100.200")
    assert first["services"] == ["ssh", "telnet"] and "families" not in first
    assert render_json(OUT, cleaned()).endswith("}\n")


def test_stix_outbound_only_and_shape() -> None:
    bundle = json.loads(render_stix(OUT, cleaned()))
    assert bundle["type"] == "bundle" and bundle["id"].startswith("bundle--")
    text = json.dumps(bundle)
    assert "created_by_ref" not in text and '"identity"' not in text
    marking, *indicators = bundle["objects"]
    assert marking["type"] == "marking-definition" and len(indicators) == 4
    for ind in indicators:
        assert ind["object_marking_refs"] == [marking["id"]]
        assert ind["created"] <= ind["modified"]
        assert ind["pattern_type"] == "stix"
    assert indicators[3]["pattern"] == "[ipv6-addr:value = '2001:db8::50']"
    dns = json.loads(render_stix(ctx("outbound-domains"), cleaned("outbound-domains")))
    assert dns["objects"][1]["pattern"] == "[domain-name:value = 'cnc.example.org']"
    with pytest.raises(FeedError):
        render_stix(ctx("inbound"), cleaned("inbound"))


def test_stix_is_deterministic() -> None:
    shuffled = clean_entries(OUT, list(reversed(SETS["outbound"])))[0]
    assert render_stix(OUT, cleaned()) == render_stix(OUT, shuffled)


def test_domains_have_no_firewall_formats() -> None:
    d = ctx("outbound-domains")
    for fn in (render_nft, render_ipset, render_rsc):
        with pytest.raises(FeedError):
            fn(d, [])
    assert render_txt(d, cleaned("outbound-domains")) == "cnc.example.org\ndl.example.net\n"


def test_file_sets_per_list() -> None:
    r = render_all()
    assert set(r["outbound"].files) == {
        "outbound.txt", "outbound.v4.txt", "outbound.v6.txt", "outbound.nft", "outbound.ipset",
        "outbound.rsc", "outbound.csv", "outbound.json", "outbound.stix.json",
    }  # fmt: skip
    assert "inbound.stix.json" not in r["inbound"].files
    assert set(r["outbound-domains"].files) == {
        "outbound-domains.txt", "outbound-domains.csv", "outbound-domains.json",
    }  # fmt: skip


def test_golden_files() -> None:
    for rendered in render_all().values():
        for name, data in rendered.files.items():
            assert (GOLDEN / name).read_bytes() == data, name


def test_rendering_is_deterministic() -> None:
    assert render_all()["outbound"].files == render_all()["outbound"].files


# --- negatives ------------------------------------------------------------------------------

# Built from parts so no private literal sits in the source (public repo hygiene).
ANY_ADDR = ".".join(("0", "0", "0", "0"))
PRIVATE_A = ".".join(("10", "1", "2", "3"))
PRIVATE_B = ".".join(("192", "168", "1", "1"))
BAD_IPS = [
    "198.51.100.0/24", "0.0.0.0/0", "::/0", ANY_ADDR, PRIVATE_A, PRIVATE_B, "127.0.0.1",
    "100.64.0.1", "169.254.1.1", "224.0.0.1", "255.255.255.255", "::1", "fe80::1", "fc00::1",
    "::ffff:198.51.100.9", "64:ff9b::198.51.100.9", "2002:c633:6409::1", "198.51.100.9 ",
    " 198.51.100.9", "198.51.100.9\n", "198.51.100.9\nflush ruleset", "198.51.100.9; drop",
    "198.51.100.9}\nadd rule", "198.51.100.9\"", "198.51.100.9'", "$(reboot)", "`id`",
    "198.51.100.9\x00", "198.051.100.9", "2001:DB8::50", "2001:db8:0:0:0:0:0:50", "fe80::1%eth0",
    "1.2.3", "", "*", "*.example.org", "1.2.3.4-1.2.3.9",
]  # fmt: skip


@pytest.mark.parametrize("bad", BAD_IPS)
def test_bad_address_never_rendered(bad: str) -> None:
    good = entry("198.51.100.9", 4)
    # strict mode (documentation addresses refused) and the permissive test mode
    for allow in (True, False):
        c = ctx("outbound", allow_documentation=allow)
        fam = 6 if ":" in bad else 4
        entries, dropped = clean_entries(c, [entry(bad, fam), good])
        assert [e.value for e in entries] == (["198.51.100.9"] if allow else []), bad
        assert dropped == (1 if allow else 2)


def test_documentation_ranges_refused_without_the_flag() -> None:
    entries, dropped = clean_entries(
        ctx("outbound", allow_documentation=False), [entry("198.51.100.9", 4)]
    )
    assert entries == [] and dropped == 1


def test_real_global_address_accepted_in_strict_mode() -> None:
    strict = ctx("outbound", allow_documentation=False)
    entries, dropped = clean_entries(strict, [entry("1.1.1.2", 4), entry("2606:4700::1111", 6)])
    assert dropped == 0 and len(entries) == 2


BAD_NAMES = [
    "*.example.org", ".example.org", "example.org.", "Example.org", "bücher.example.org",
    "example", "com", "localhost", "printer.local", "host.internal", "198.51.100.9",
    "a b.example.org", "a\nb.example.org", "a;b.example.org", "a'b.example.org",
    "a\"b.example.org", "$(x).example.org", "-a.example.org", "a..example.org", "a/b.example.org",
    "example.org/path", "example.org:80", "x" * 64 + ".example.org", ("a." * 130) + "org",
    "example.org\x00", "",
]  # fmt: skip


@pytest.mark.parametrize("bad", BAD_NAMES)
def test_bad_name_never_rendered(bad: str) -> None:
    entries, dropped = clean_entries(
        ctx("outbound-domains"), [entry(bad, "dns"), entry("cnc.example.org", "dns")]
    )
    assert [e.value for e in entries] == ["cnc.example.org"], bad
    assert dropped == 1


@pytest.mark.parametrize(
    "field, value",
    [
        ("categories", ["c2\nflush ruleset"]),
        ("categories", []),
        ("services", ["ssh\n"]),
        ("tags", ["x;rm -rf"]),
        ("tags", ["mirai\r\nX"]),
        ("families", ["nope"]),
        ("ports", [0]),
        ("ports", [70000]),
        ("ports", [23, 23]),
        ("tier", "gold"),
        ("first_seen", "2026-10-26\n"),
        ("first_seen", "2026-13-40"),
        ("expires", "2026-10-01"),
        ("reported", "yes"),
    ],
)
def test_bad_metadata_drops_the_entry(field: str, value: Any) -> None:
    base = entry("198.51.100.9", 4, services=["ssh"] if field == "services" else [])
    entries, dropped = clean_entries(ctx("inbound"), [{**base, field: value}])
    assert entries == [] and dropped == 1


def test_list_rules_are_enforced() -> None:
    # address in the domains list, name in an address list, standard entry in a high list
    assert clean_entries(ctx("outbound-domains"), [entry("198.51.100.9", 4)])[1] == 1
    assert clean_entries(ctx("outbound"), [entry("cnc.example.org", "dns")])[1] == 1
    assert clean_entries(ctx("outbound-high"), [entry("198.51.100.9", 4)])[1] == 1
    assert clean_entries(ctx("outbound-high"), [entry("198.51.100.9", 4, tier="high")])[1] == 0
    # services only inbound; families and ports only outbound
    assert clean_entries(ctx("outbound"), [entry("198.51.100.9", 4, services=["ssh"])])[1] == 1
    assert clean_entries(ctx("inbound"), [entry("198.51.100.9", 4, ports=[22])])[1] == 1


def test_family_must_match_the_address() -> None:
    assert clean_entries(ctx("outbound"), [entry("198.51.100.9", 6)])[1] == 1
    assert clean_entries(ctx("outbound"), [entry("2001:db8::1", 4)])[1] == 1


def test_duplicates_are_dropped_once() -> None:
    entries, dropped = clean_entries(
        OUT, [entry("198.51.100.9", 4), entry("198.51.100.9", 4, tier="high")]
    )
    assert len(entries) == 1 and dropped == 1


def test_model_construct_bypass_is_caught() -> None:
    from suckerpot_netproto.feeds import FeedEntry

    forged = FeedEntry.model_construct(
        value="198.51.100.9\nflush ruleset", family=4, tier="standard", categories=["c2"],
        services=[], tags=[], families=[], ports=[], first_seen="2026-10-26",
        last_seen="2026-10-26", expires="2026-11-14", reported=False,
    )  # fmt: skip
    entries, dropped = clean_entries(OUT, [forged, entry("203.0.113.50", 4)])
    assert [e.value for e in entries] == ["203.0.113.50"] and dropped == 1
    files = render_list(OUT, [forged]).files
    assert all(b"flush ruleset" not in data for data in files.values())


def test_no_special_character_in_any_rendered_firewall_file() -> None:
    evil = [
        entry("198.51.100.9\n}\nflush ruleset\n{", 4),
        entry("198.51.100.10 timeout=1s; /system reset-configuration", 4),
        entry("203.0.113.50", 4),
    ]
    files = render_list(OUT, evil).files
    for name in ("outbound.nft", "outbound.ipset", "outbound.rsc"):
        text = files[name].decode()
        assert "flush ruleset" not in text and "reset-configuration" not in text, name
        assert "203.0.113.50" in text


def test_oversize_input_is_refused() -> None:
    cap = MAX_ENTRIES["outbound"]
    many = [entry(f"1.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}", 4) for i in range(cap + 1)]
    strict = ctx("outbound", allow_documentation=False)
    with pytest.raises(FeedError) as e:
        clean_entries(strict, many)
    assert e.value.code == "too_large"
    with pytest.raises(FeedError):
        clean_entries(strict, many + many)  # refused before per-entry work


def test_at_the_cap_is_accepted_and_file_size_stays_under_8_mib() -> None:
    cap = MAX_ENTRIES["outbound-domains"]
    names = [entry(f"h{i}.example.org", "dns") for i in range(cap)]
    r = render_list(ctx("outbound-domains"), names)
    assert len(r.entries) == cap
    assert all(len(d) <= 8 * 1024 * 1024 for d in r.files.values())


def test_context_is_validated() -> None:
    from datetime import datetime

    with pytest.raises(FeedError):
        ctx("nope")
    with pytest.raises(FeedError):
        ctx("outbound", serial=-1)
    with pytest.raises(FeedError):
        ctx("outbound", valid_until=ctx("outbound").generated_at)
    with pytest.raises(FeedError):
        ctx("outbound", generated_at=datetime(2026, 11, 1))

"""Indicator helpers without a database: defanging, CSV safety, STIX shape, link allow-list."""

import csv
import io
from datetime import UTC, datetime

import pytest

from api.indicators import (
    IndicatorOut,
    _stix_pattern,
    defang,
    render_csv,
    render_stix,
    safe_reference,
)

T = datetime(2026, 10, 24, 12, 0, tzinfo=UTC)


def item(kind: str, value: str, **kw: object) -> IndicatorOut:
    base = {
        "id": 1,
        "type": kind,
        "value": value,
        "defanged": defang(kind, value),
        "role": "hash" if kind == "hash" else "download_host",
        "host": None,
        "first_seen": T,
        "last_seen": T,
        "sightings": 3,
        "sensors": ["ssh"],
        "sessions": 2,
        "ips": 2,
        "checked": False,
        "known": None,
        "family": None,
        "sources": [],
    }
    return IndicatorOut.model_validate({**base, **kw})


@pytest.mark.parametrize(
    ("kind", "value", "expected"),
    [
        ("url", "http://files.badhost.ru/a.sh", "hxxp://files[.]badhost[.]ru/a.sh"),
        ("url", "https://1.2.3.4:8080/x.y?z=a.b", "hxxps://1[.]2[.]3[.]4:8080/x.y?z=a.b"),
        ("url", "ftp://files.badhost.ru/", "fxp://files[.]badhost[.]ru/"),
        ("url", "ldap://ldap.badhost.ru/a", "ldxp://ldap[.]badhost[.]ru/a"),
        ("domain", "files.badhost.ru", "files[.]badhost[.]ru"),
        ("ip", "8.8.4.4", "8[.]8[.]4[.]4"),
        ("ip", "2001:4860:4860::8888", "2001[:]4860[:]4860[:][:]8888"),
        ("url", "http://[2001:4860::1]:8080/x", "hxxp://[2001[:]4860[:][:]1]:8080/x"),
        ("hash", "ab" * 16, "ab" * 16),
    ],
)
def test_defang(kind: str, value: str, expected: str) -> None:
    out = defang(kind, value)
    assert out == expected
    assert "://" not in out or out.split("://")[0] not in {"http", "https", "ftp"}


def test_defanged_url_has_no_resolvable_host() -> None:
    out = defang("url", "http://evil.ru/a.b.c")
    host = out.split("://", 1)[1].split("/", 1)[0]
    assert host.replace("[.]", "") == "evilru"


def test_csv_neutralises_formulas_and_keeps_columns() -> None:
    rows = list(
        csv.reader(
            io.StringIO(render_csv([item("domain", "=cmd.badhost.ru"), item("ip", "8.8.4.4")]))
        )
    )
    assert rows[0][:3] == ["type", "value", "defanged"]
    assert rows[1][1] == "'=cmd.badhost.ru"
    assert rows[2][1] == "8.8.4.4" and rows[2][2] == "8[.]8[.]4[.]4"
    assert len(rows) == 3 and all(len(r) == len(rows[0]) for r in rows)


def test_stix_bundle_shape_and_patterns() -> None:
    items = [
        item("url", "http://files.badhost.ru/it's.sh", known=True, family="Mirai"),
        item("domain", "files.badhost.ru"),
        item("ip", "8.8.4.4"),
        item("ip", "2001:4860:4860::8888"),
        item("hash", "ab" * 32),
        item("hash", "cd" * 20),
        item("hash", "ef" * 16),
    ]
    bundle = render_stix(items, T)
    assert bundle["type"] == "bundle" and bundle["id"].startswith("bundle--")
    objs = bundle["objects"]
    assert [o["pattern"] for o in objs] == [
        "[url:value = 'http://files.badhost.ru/it\\'s.sh']",
        "[domain-name:value = 'files.badhost.ru']",
        "[ipv4-addr:value = '8.8.4.4']",
        "[ipv6-addr:value = '2001:4860:4860::8888']",
        f"[file:hashes.'SHA-256' = '{'ab' * 32}']",
        f"[file:hashes.'SHA-1' = '{'cd' * 20}']",
        f"[file:hashes.'MD5' = '{'ef' * 16}']",
    ]
    for o in objs:
        assert o["type"] == "indicator" and o["spec_version"] == "2.1"
        assert o["pattern_type"] == "stix" and o["id"].startswith("indicator--")
        assert o["created"].endswith("Z") and o["valid_from"] == o["created"]
    assert objs[0]["indicator_types"] == ["malicious-activity"] and objs[0]["labels"] == ["Mirai"]
    assert objs[1]["indicator_types"] == ["anomalous-activity"]
    # ids are stable, so re-importing an export updates instead of duplicating
    assert render_stix(items, T)["objects"][0]["id"] == objs[0]["id"]
    # the name is defanged, only the pattern carries the raw value
    assert objs[0]["name"].startswith("hxxp://")


def test_stix_pattern_escapes_backslash() -> None:
    assert _stix_pattern(item("url", "http://a.bc/x\\y")) == "[url:value = 'http://a.bc/x\\\\y']"


def test_references_are_limited_to_the_intel_providers() -> None:
    assert safe_reference("https://urlhaus.abuse.ch/url/1/")
    assert safe_reference("https://threatfox.abuse.ch/ioc/1/")
    assert safe_reference("https://www.virustotal.com/gui/file/ab")
    for bad in (None, "http://urlhaus.abuse.ch/x", "https://evil.ru/x", "javascript:alert(1)", ""):
        assert safe_reference(bad) is None
    assert safe_reference("https://urlhaus.abuse.ch.evil.ru/x") is None

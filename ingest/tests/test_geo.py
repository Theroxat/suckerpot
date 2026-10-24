from pathlib import Path

import pytest

from ingest.enrichment import EnrichmentSettings, GeoResolver

from .mmdb_helpers import asn_db, city_db


def test_global_ip_lookup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    city_db(tmp_path / "dbip-city-lite.mmdb")
    asn_db(tmp_path / "dbip-asn-lite.mmdb")
    r = GeoResolver(tmp_path)
    assert r.available
    # The benchmarking range is not routable: pretend it is to exercise the parsing code.
    monkeypatch.setattr("ingest.enrichment.geo.is_routable", lambda _a: True)
    info = r.lookup("198.18.0.5")
    assert (info.country, info.city, info.asn, info.org) == (
        "NL", "Amsterdam", 64496, "Example Hosting",
    )  # fmt: skip
    only_country = r.lookup("198.19.0.7")
    assert only_country.country == "CH" and only_country.city is None
    assert only_country.asn is None
    assert r.lookup("198.20.1.1").country is None  # not in the database


def test_no_databases_degrades_to_none(tmp_path: Path) -> None:
    r = GeoResolver(tmp_path)
    assert not r.available
    assert r.lookup("8.8.8.8").country is None
    assert r.lookup("not-an-ip").country is None


def test_private_and_documentation_addresses_have_no_geo(tmp_path: Path) -> None:
    r = GeoResolver(tmp_path)
    for ip in (
        "10.0.0.1",  # gitleaks:allow (private range must be skipped)
        "192.0.2.5",
        "203.0.113.9",
        "127.0.0.1",
        "::1",
    ):  # gitleaks:allow (private range must be skipped)
        assert r.lookup(ip).country is None


def test_fake_geo_for_demo_is_deterministic(tmp_path: Path) -> None:
    r = GeoResolver(tmp_path, fake_for_private=True)
    assert r.available
    a = r.lookup("203.0.113.9")
    assert a == r.lookup("203.0.113.9")
    assert a.country and len(a.country) == 2 and a.asn and 64496 <= a.asn <= 64511
    countries = {r.lookup(f"198.51.100.{i}").country for i in range(1, 200)}
    assert len(countries) >= 8


def test_corrupt_database_is_ignored(tmp_path: Path) -> None:
    (tmp_path / "GeoLite2-City.mmdb").write_bytes(b"not a database")
    assert not GeoResolver(tmp_path).available


def test_settings_provider_selection() -> None:
    assert EnrichmentSettings.from_env({}).effective_geoip_provider == "dbip"
    keyed = {"MAXMIND_ACCOUNT_ID": "1", "MAXMIND_LICENSE_KEY": "k"}
    assert EnrichmentSettings.from_env(keyed).effective_geoip_provider == "maxmind"
    assert (
        EnrichmentSettings.from_env({**keyed, "GEOIP_PROVIDER": "dbip"}).effective_geoip_provider
        == "dbip"
    )
    assert (
        EnrichmentSettings.from_env({"GEOIP_PROVIDER": "maxmind"}).effective_geoip_provider == "off"
    )
    assert EnrichmentSettings.from_env({"GEOIP_PROVIDER": "off"}).effective_geoip_provider == "off"
    s = EnrichmentSettings.from_env({"ABUSEIPDB_API_KEY": "secret-value"})
    assert "secret-value" not in repr(s)

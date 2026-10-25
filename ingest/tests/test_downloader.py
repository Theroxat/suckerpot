from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from ingest.enrichment import EnrichmentSettings, GeoResolver
from ingest.enrichment import downloader as dl
from ingest.enrichment.downloader import GeoManager

from .mmdb_helpers import asn_db, city_db, gz_bytes, tar_gz_bytes


def settings(tmp_path: Path, **env: str) -> EnrichmentSettings:
    return EnrichmentSettings.from_env({"GEOIP_DIR": str(tmp_path / "geo"), **env})


def manager(
    s: EnrichmentSettings, handler: Callable[[httpx.Request], httpx.Response]
) -> tuple[GeoManager, GeoResolver, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def wrap(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    resolver = GeoResolver(s.geoip_dir)
    mgr = GeoManager(
        s,
        resolver,
        client_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(wrap), follow_redirects=True
        ),
    )
    return mgr, resolver, seen


async def test_dbip_download_falls_back_to_previous_month(tmp_path: Path) -> None:
    city = gz_bytes(city_db(tmp_path / "c.mmdb"))
    asn = gz_bytes(asn_db(tmp_path / "a.mmdb"))
    now = datetime.now(UTC)

    def handler(req: httpx.Request) -> httpx.Response:
        name = req.url.path.rsplit("/", 1)[-1]
        if f"{now.year}-{now.month:02d}" in name:
            return httpx.Response(404)
        return httpx.Response(200, content=city if "city" in name else asn)

    s = settings(tmp_path)
    mgr, resolver, seen = manager(s, handler)
    assert await mgr.refresh_if_needed() is True
    assert (s.geoip_dir / "dbip-city-lite.mmdb").is_file()
    assert (s.geoip_dir / "dbip-asn-lite.mmdb").is_file()
    assert resolver.available and mgr.last_error is None
    assert not [p for p in s.geoip_dir.iterdir() if p.name.startswith(".")]  # no temp leftovers
    assert all(r.method == "GET" and r.url.host == "download.db-ip.com" for r in seen)
    # fresh files: nothing to do on the next check
    seen.clear()
    assert await mgr.refresh_if_needed() is False and not seen
    st = mgr.status()
    assert st["provider"] == "dbip" and st["available"] and set(st["files"]) == {"city", "asn"}


async def test_maxmind_download_with_checksum(tmp_path: Path) -> None:
    import hashlib

    archive = tar_gz_bytes(city_db(tmp_path / "c.mmdb"))
    asn_archive = tar_gz_bytes(asn_db(tmp_path / "a.mmdb"), "GeoLite2-ASN_1/GeoLite2-ASN.mmdb")
    auths: list[str | None] = []

    def handler(req: httpx.Request) -> httpx.Response:
        auths.append(req.headers.get("authorization"))
        body = archive if "GeoLite2-City" in req.url.path else asn_archive
        if req.url.params["suffix"] == "tar.gz.sha256":
            return httpx.Response(200, text=f"{hashlib.sha256(body).hexdigest()}  x.tar.gz\n")
        return httpx.Response(200, content=body)

    s = settings(tmp_path, MAXMIND_ACCOUNT_ID="123", MAXMIND_LICENSE_KEY="lic-key")
    mgr, resolver, _ = manager(s, handler)
    assert await mgr.refresh_if_needed() is True
    assert (s.geoip_dir / "GeoLite2-City.mmdb").is_file()
    assert resolver.available
    assert all(a and a.startswith("Basic ") for a in auths)
    assert "lic-key" not in str(mgr.status())


async def test_checksum_mismatch_is_rejected_and_keeps_old_file(tmp_path: Path) -> None:
    s = settings(tmp_path, MAXMIND_ACCOUNT_ID="1", MAXMIND_LICENSE_KEY="k", GEOIP_REFRESH_DAYS="1")
    s.geoip_dir.mkdir()
    old = s.geoip_dir / "GeoLite2-City.mmdb"
    city_db(old)
    import os

    os.utime(old, (1, 1))  # ancient: stale
    before = old.read_bytes()
    archive = tar_gz_bytes(city_db(tmp_path / "new.mmdb"))

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.params["suffix"].endswith("sha256"):
            return httpx.Response(200, text="0" * 64 + "  x\n")
        return httpx.Response(200, content=archive)

    mgr, _, _ = manager(s, handler)
    await mgr.refresh_if_needed()
    assert old.read_bytes() == before
    assert mgr.last_error and "checksum" in mgr.last_error


async def test_size_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dl, "MAX_DOWNLOAD_BYTES", 100)
    gz = gz_bytes(city_db(tmp_path / "c.mmdb"))
    assert len(gz) > 100
    s = settings(tmp_path)
    mgr, resolver, _ = manager(s, lambda r: httpx.Response(200, content=gz))
    assert await mgr.refresh_if_needed() is False
    assert mgr.last_error and "size cap" in mgr.last_error
    assert not resolver.available
    assert not list(s.geoip_dir.glob("*.mmdb"))


async def test_garbage_is_never_installed(tmp_path: Path) -> None:
    import gzip

    s = settings(tmp_path)
    mgr, resolver, _ = manager(s, lambda r: httpx.Response(200, content=gzip.compress(b"junk")))
    await mgr.refresh_if_needed()
    assert not list(s.geoip_dir.glob("*.mmdb")) and not resolver.available
    assert mgr.last_error and "valid" in mgr.last_error


async def test_network_failure_degrades_gracefully(tmp_path: Path) -> None:
    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route")

    s = settings(tmp_path)
    mgr, resolver, _ = manager(s, boom)
    assert await mgr.refresh_if_needed() is False
    assert mgr.last_error == "ConnectError" or "ConnectError" in (mgr.last_error or "")
    assert resolver.lookup("8.8.8.8").country is None


async def test_off_provider_never_connects(tmp_path: Path) -> None:
    s = settings(tmp_path, GEOIP_PROVIDER="off")
    mgr, _, seen = manager(s, lambda r: httpx.Response(500))
    assert await mgr.refresh_if_needed() is False and not seen


async def test_key_change_does_not_redownload_fresh_files(tmp_path: Path) -> None:
    city = gz_bytes(city_db(tmp_path / "c.mmdb"))
    asn = gz_bytes(asn_db(tmp_path / "a.mmdb"))

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=city if "city" in req.url.path else asn)

    s = settings(tmp_path)
    mgr, _, seen = manager(s, handler)
    assert await mgr.refresh_if_needed() is True
    seen.clear()
    mgr.apply_settings(s, credentials_changed=True)  # healthy, fresh files: nothing forced
    assert await mgr.refresh_if_needed() is False and not seen


async def test_key_change_retries_after_a_failed_download(tmp_path: Path) -> None:
    city = gz_bytes(city_db(tmp_path / "c.mmdb"))
    asn = gz_bytes(asn_db(tmp_path / "a.mmdb"))
    state = {"fail": False}

    def handler(req: httpx.Request) -> httpx.Response:
        if state["fail"]:
            return httpx.Response(401)
        return httpx.Response(200, content=city if "city" in req.url.path else asn)

    s = settings(tmp_path)
    mgr, _, seen = manager(s, handler)
    assert await mgr.refresh_if_needed() is True
    mgr.last_error = "city: HTTP 401"  # the last download failed for auth reasons
    seen.clear()
    mgr.apply_settings(s, credentials_changed=True)
    assert await mgr.refresh_if_needed() is True and seen  # retried although files are fresh
    assert mgr.last_error is None

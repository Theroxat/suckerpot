"""Fetch and refresh the GeoIP databases (ingest is the only service with egress).

Providers: MaxMind GeoLite2 (needs an account id and license key) or DB-IP Lite (key-less,
CC BY 4.0, attribution required). Downloads are size-capped, verified (checksum when the
provider publishes one, and the file must open as an MMDB) and moved into place atomically.
"""

from __future__ import annotations

import asyncio
import contextlib
import gzip
import hashlib
import logging
import os
import shutil
import tarfile
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import maxminddb

from ingest.enrichment.config import EnrichmentSettings
from ingest.enrichment.geo import ASN_FILES, CITY_FILES, GeoResolver

log = logging.getLogger(__name__)

MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024
MAX_DB_BYTES = 768 * 1024 * 1024
TOTAL_TIMEOUT_S = 1800
CHECK_INTERVAL_S = 24 * 3600
MAXMIND_URL = "https://download.maxmind.com/geoip/databases/{edition}/download?suffix={suffix}"
DBIP_URL = "https://download.db-ip.com/free/{edition}-{year}-{month:02d}.mmdb.gz"


class DownloadError(Exception):
    """A download failed (message is safe to log: no credentials)."""


def _plan(settings: EnrichmentSettings) -> list[tuple[str, str, str]]:
    """(kind, remote edition, local file name) per database."""
    if settings.effective_geoip_provider == "maxmind":
        return [
            ("city", "GeoLite2-City", CITY_FILES[0]),
            ("asn", "GeoLite2-ASN", ASN_FILES[0]),
        ]
    return [
        ("city", "dbip-city-lite", CITY_FILES[1]),
        ("asn", "dbip-asn-lite", ASN_FILES[1]),
    ]


async def _fetch(client: httpx.AsyncClient, url: str, dest: Path, **kw: Any) -> str:
    """Stream ``url`` into ``dest`` (size capped). Returns the sha256 of what was written."""
    digest = hashlib.sha256()
    size = 0
    try:
        async with client.stream("GET", url, **kw) as resp:
            if resp.status_code != 200:
                raise DownloadError(f"HTTP {resp.status_code}")
            with dest.open("wb") as fh:
                async for chunk in resp.aiter_bytes(65536):
                    size += len(chunk)
                    if size > MAX_DOWNLOAD_BYTES:
                        raise DownloadError("download exceeds the size cap")
                    digest.update(chunk)
                    fh.write(chunk)
    except httpx.HTTPError as exc:
        raise DownloadError(type(exc).__name__) from None
    return digest.hexdigest()


def _copy_capped(src: Any, dest: Path) -> None:
    written = 0
    with dest.open("wb") as out:
        while chunk := src.read(1 << 20):
            written += len(chunk)
            if written > MAX_DB_BYTES:
                raise DownloadError("database exceeds the size cap")
            out.write(chunk)


def _extract_mmdb(archive: Path, dest: Path, tar: bool) -> None:
    """Unpack the single .mmdb from a tar.gz (MaxMind) or gz (DB-IP) archive."""
    if not tar:
        with gzip.open(archive, "rb") as gz:
            _copy_capped(gz, dest)
        return
    with tarfile.open(archive, "r:gz") as tf:
        for member in tf:
            name = member.name.rsplit("/", 1)[-1]
            if member.isfile() and name.endswith(".mmdb"):
                fh = tf.extractfile(member)
                if fh is None:
                    continue
                with fh:
                    _copy_capped(fh, dest)
                return
    raise DownloadError("no .mmdb file in the archive")


def _verify_and_install(candidate: Path, target: Path) -> None:
    try:
        with maxminddb.open_database(str(candidate)) as reader:
            if reader.metadata().node_count <= 0:
                raise DownloadError("empty database")
    except (OSError, ValueError, maxminddb.InvalidDatabaseError):
        raise DownloadError("downloaded file is not a valid MMDB") from None
    candidate.chmod(0o644)
    os.replace(candidate, target)  # atomic on the same filesystem


class GeoManager:
    """Keeps the databases fresh and tells the resolver to reload after a refresh."""

    def __init__(
        self,
        settings: EnrichmentSettings,
        resolver: GeoResolver,
        *,
        client_factory: Callable[[], httpx.AsyncClient] | None = None,
        on_status: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        self.s = settings
        self.resolver = resolver
        self._client_factory = client_factory or (
            lambda: httpx.AsyncClient(
                timeout=httpx.Timeout(30.0, read=120.0), follow_redirects=True
            )
        )
        self.on_status = on_status
        self.last_error: str | None = None
        self._force = False
        self._wake = asyncio.Event()

    def apply_settings(self, settings: EnrichmentSettings, *, credentials_changed: bool) -> None:
        """Hot-swap the settings and look at the databases right away when a key changed.

        Files that are missing (for example after switching provider) are downloaded, fresh
        files are left alone. Only a previous failed download is retried even though the files
        are fresh, so a key change can never force a full re-download of healthy databases.
        """
        self.s = settings
        if credentials_changed:
            if self.last_error is not None:
                self._force = True
            self._wake.set()

    def status(self) -> dict[str, Any]:
        files: dict[str, Any] = {}
        for kind, _, name in _plan(self.s):
            path = self.s.geoip_dir / name
            if path.is_file():
                st = path.stat()
                files[kind] = {
                    "file": name,
                    "bytes": st.st_size,
                    "updated_at": datetime.fromtimestamp(st.st_mtime, UTC).isoformat(),
                }
        return {
            "provider": self.s.effective_geoip_provider,
            "available": self.resolver.available,
            "files": files,
            "last_error": self.last_error,
            "refresh_days": self.s.geoip_refresh_days,
        }

    def _stale(self, name: str) -> bool:
        path = self.s.geoip_dir / name
        try:
            age = time.time() - path.stat().st_mtime
        except OSError:
            return True
        return age > self.s.geoip_refresh_days * 86400

    async def refresh_if_needed(self) -> bool:
        """Download whatever is missing or older than the refresh period. Never raises."""
        if self.s.effective_geoip_provider == "off":
            return False
        force, self._force = self._force, False
        todo = [p for p in _plan(self.s) if force or self._stale(p[2])]
        if not todo:
            return False
        changed = False
        try:
            self.s.geoip_dir.mkdir(parents=True, exist_ok=True)
            async with asyncio.timeout(TOTAL_TIMEOUT_S), self._client_factory() as client:
                for kind, edition, name in todo:
                    try:
                        await self._download_one(client, edition, self.s.geoip_dir / name)
                        changed = True
                        log.info("GeoIP %s database updated", kind)
                    except DownloadError as exc:
                        self.last_error = f"{kind}: {exc}"
                        log.warning("GeoIP %s download failed: %s", kind, exc)
            if changed:
                self.last_error = None
                self.resolver.reload()
        except (OSError, TimeoutError) as exc:
            self.last_error = type(exc).__name__
            log.warning("GeoIP refresh failed: %s", type(exc).__name__)
        return changed

    async def _download_one(self, client: httpx.AsyncClient, edition: str, target: Path) -> None:
        with tempfile.TemporaryDirectory(dir=target.parent, prefix=".dl-") as tmp:
            tmpdir = Path(tmp)
            archive = tmpdir / "archive"
            if self.s.effective_geoip_provider == "maxmind":
                auth = httpx.BasicAuth(self.s.maxmind_account_id, self.s.maxmind_license_key)
                url = MAXMIND_URL.format(edition=edition, suffix="tar.gz")
                digest = await _fetch(client, url, archive, auth=auth)
                try:
                    sum_url = MAXMIND_URL.format(edition=edition, suffix="tar.gz.sha256")
                    expected = (await client.get(sum_url, auth=auth)).text.split()[0]
                    if expected.lower() != digest:
                        raise DownloadError("checksum mismatch")
                except (httpx.HTTPError, IndexError):
                    log.info("no checksum available for %s", edition)
                tar = True
            else:
                tar = False
                now = datetime.now(UTC)
                year, month = now.year, now.month
                for _ in range(2):  # the current month may not be published yet
                    url = DBIP_URL.format(edition=edition, year=year, month=month)
                    try:
                        await _fetch(client, url, archive)
                        break
                    except DownloadError as exc:
                        if "404" not in str(exc):
                            raise
                        year, month = (year, month - 1) if month > 1 else (year - 1, 12)
                else:
                    raise DownloadError("no recent database published")
            candidate = tmpdir / "candidate.mmdb"
            await asyncio.to_thread(_extract_mmdb, archive, candidate, tar)
            await asyncio.to_thread(_verify_and_install_into, candidate, target)

    async def run(self) -> None:
        """Background loop: refresh at startup and then once a day if due."""
        await asyncio.sleep(3)
        while True:
            self._wake.clear()
            await self.refresh_if_needed()
            if self.on_status is not None:
                try:
                    await self.on_status(self.status())
                except Exception:
                    log.warning("could not publish GeoIP status", exc_info=True)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), CHECK_INTERVAL_S)


def _verify_and_install_into(candidate: Path, target: Path) -> None:
    # The candidate lives in a temp dir on the same volume as the target: rename is atomic.
    staged = target.with_name(f".{target.name}.new")
    shutil.move(str(candidate), staged)
    try:
        _verify_and_install(staged, target)
    finally:
        staged.unlink(missing_ok=True)

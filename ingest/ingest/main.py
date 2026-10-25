"""Entry point: ``python -m ingest``."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from typing import Any

from redis.asyncio import Redis
from suckerpot_db import create_engine, create_session_factory
from suckerpot_db.diskguard import max_db_bytes
from suckerpot_db.secretbox import SecretBox, SecretError, box_from_env

from ingest.config import Settings
from ingest.consumer import Consumer
from ingest.cve import CveWatch
from ingest.cve.relevance import load_relevance
from ingest.diskguard import DiskGuard, publish_system_status
from ingest.enrichment import EnrichmentSettings, GeoResolver
from ingest.enrichment.credentials import CredentialSync
from ingest.enrichment.downloader import GeoManager
from ingest.enrichment.enricher import Enricher
from ingest.enrichment.intel import IntelWorker
from ingest.enrichment.reputation import ReputationWorker
from ingest.enrichment.status import publish_status
from ingest.indicators import IndicatorExtractor, IndicatorSettings
from ingest.tagging import load_rules

log = logging.getLogger(__name__)


def load_secret_box() -> SecretBox | None:
    """The Settings-key encryption box; a bad value disables the feature instead of crashing."""
    try:
        return box_from_env()
    except SecretError as exc:
        log.error("SETTINGS_ENCRYPTION_KEY is unusable (%s): keys set in Settings are ignored", exc)
        return None


async def run() -> None:
    settings = Settings.from_env()
    enrich = EnrichmentSettings.from_env()
    redis = Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        username=settings.redis_user,
        password=settings.redis_password,
        lib_name=None,
        lib_version=None,
        socket_timeout=settings.block_ms / 1000 + 10,
        socket_connect_timeout=5,
    )
    engine = create_engine()
    factory = create_session_factory(engine)

    rules = load_rules(enrich.rules_dir)  # fail fast on a broken rule file
    log.info("loaded %d tagging rules", len(rules.rules))
    resolver = GeoResolver(enrich.geoip_dir, fake_for_private=enrich.geoip_fake_for_private)

    async def disk_status(detail: dict[str, Any]) -> None:
        await publish_system_status(factory, "ingest_disk", detail)

    guard = DiskGuard(factory, max_db_bytes(), on_status=disk_status)
    indicator_settings = IndicatorSettings.from_env()
    enricher = Enricher(
        resolver,
        rules,
        indicators=IndicatorExtractor(indicator_settings) if indicator_settings.enabled else None,
        link_cap=indicator_settings.link_cap,
    )
    consumer = Consumer(settings, redis, factory, enricher, guard)

    async def geo_status(detail: dict[str, Any]) -> None:
        await publish_status(factory, "geoip", detail)

    # Keys set in Settings override .env. Read them once before the workers start.
    appliers: list[Any] = []

    def apply_credentials(settings: EnrichmentSettings, changed: set[str]) -> None:
        for apply in appliers:
            apply(settings, changed)

    sync = CredentialSync(factory, enrich, load_secret_box(), on_change=apply_credentials)
    try:
        await sync.sync_once()
    except Exception as exc:
        log.warning("initial provider credential sync failed (%s)", type(exc).__name__)
    enrich = sync.current

    geo = GeoManager(enrich, resolver, on_status=geo_status)
    reputation = ReputationWorker(factory, enrich)
    appliers.append(
        lambda settings, changed: geo.apply_settings(
            settings, credentials_changed="maxmind" in changed
        )
    )
    appliers.append(reputation.apply_settings)
    cve_watch = CveWatch(factory, enrich, relevance=load_relevance(enrich.rules_dir))
    appliers.append(cve_watch.apply_settings)
    intel = IntelWorker(factory, enrich)
    appliers.append(intel.apply_settings)

    async def rep_status(detail: dict[str, Any]) -> None:
        for name, value in detail.items():
            await publish_status(factory, name, {**value, **sync.status(name)})

    async def cve_status(detail: dict[str, Any]) -> None:
        for name, value in detail.items():
            extra = sync.status(name) if name in ("nvd", "github") else {}
            await publish_status(factory, name, {**value, **extra})

    async def publish_all() -> None:
        await rep_status(await reputation.status())
        await cve_status(await cve_watch.status())
        await rep_status(await intel.status())
        await publish_status(factory, "maxmind", sync.status("maxmind"))

    async def run_test(provider: str) -> None:
        if provider in ("abusech", "virustotal"):
            await intel.run_key_test(provider)
        elif provider == "maxmind":
            await sync.test_maxmind()
        elif provider in ("nvd", "github"):
            await cve_watch.run_key_test(provider)
        else:
            await reputation.run_key_test(provider)

    sync.run_test = run_test
    sync.on_synced = publish_all
    background = [
        asyncio.create_task(geo.run(), name="geoip"),
        asyncio.create_task(reputation.run(rep_status), name="reputation"),
        asyncio.create_task(cve_watch.run(cve_status), name="cve-watch"),
        asyncio.create_task(intel.run(rep_status), name="intel"),
        asyncio.create_task(sync.run(), name="credentials"),
    ]
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, consumer.stop.set)
    try:
        await consumer.run()
    finally:
        for task in background:
            task.cancel()
        for task in background:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await reputation.aclose()
        await cve_watch.aclose()
        await intel.aclose()
        await sync.aclose()
        resolver.close()
        await redis.aclose()
        await engine.dispose()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    asyncio.run(run())

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

from ingest.config import Settings
from ingest.consumer import Consumer
from ingest.diskguard import DiskGuard, publish_system_status
from ingest.enrichment import EnrichmentSettings, GeoResolver
from ingest.enrichment.downloader import GeoManager
from ingest.enrichment.enricher import Enricher
from ingest.enrichment.reputation import ReputationWorker
from ingest.enrichment.status import publish_status
from ingest.tagging import load_rules

log = logging.getLogger(__name__)


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
    consumer = Consumer(settings, redis, factory, Enricher(resolver, rules), guard)

    async def geo_status(detail: dict[str, Any]) -> None:
        await publish_status(factory, "geoip", detail)

    geo = GeoManager(enrich, resolver, on_status=geo_status)
    reputation = ReputationWorker(factory, enrich)

    async def rep_status(detail: dict[str, Any]) -> None:
        for name, value in detail.items():
            await publish_status(factory, name, value)

    background = [
        asyncio.create_task(geo.run(), name="geoip"),
        asyncio.create_task(reputation.run(rep_status), name="reputation"),
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
        resolver.close()
        await redis.aclose()
        await engine.dispose()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    asyncio.run(run())

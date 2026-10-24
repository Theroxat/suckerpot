"""Entry point: ``python -m ingest``."""

from __future__ import annotations

import asyncio
import logging
import signal

from redis.asyncio import Redis
from suckerpot_db import create_engine, create_session_factory

from ingest.config import Settings
from ingest.consumer import Consumer


async def run() -> None:
    settings = Settings.from_env()
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
    consumer = Consumer(settings, redis, create_session_factory(engine))
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, consumer.stop.set)
    try:
        await consumer.run()
    finally:
        await redis.aclose()
        await engine.dispose()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    asyncio.run(run())

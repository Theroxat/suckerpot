"""Entry point: ``python -m hubproxy``."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys

from .config import ConfigError, Settings
from .server import HubProxy

log = logging.getLogger("hubproxy")
REPORT_EVERY = 300.0


async def run(settings: Settings) -> None:
    proxy = HubProxy(settings)
    await proxy.start()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    log.info("started allow=%s max_conns=%d", ",".join(settings.allow), settings.max_conns)
    last: dict[str, int] = {}
    while not stop.is_set():
        try:
            async with asyncio.timeout(REPORT_EVERY):
                await stop.wait()
        except TimeoutError:
            current = dict(proxy.counters)
            if current != last:
                log.info("counters %s", current)  # counter names and totals only
                last = current
    await proxy.stop()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        settings = Settings.from_env(os.environ)
    except ConfigError as exc:
        log.error("invalid configuration: %s", exc)
        return 2
    asyncio.run(run(settings))
    return 0


if __name__ == "__main__":
    sys.exit(main())

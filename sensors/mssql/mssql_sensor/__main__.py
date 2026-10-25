"""Entry point: ``python -m mssql_sensor``."""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import sys
import time

from suckerpot_common import EventPublisher

from mssql_sensor import tls
from mssql_sensor.config import Config
from mssql_sensor.events import EventSink
from mssql_sensor.identity import load_profile
from mssql_sensor.server import MssqlServer, Sensor
from mssql_sensor.watchdog import LoopWatchdog


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        return json.dumps(payload, ensure_ascii=True)


def setup_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.INFO)
    # asyncio logs connection noise for every hostile client.
    logging.getLogger("asyncio").setLevel(logging.CRITICAL)


async def run() -> None:
    cfg = Config.from_env()
    log = logging.getLogger("mssql_sensor")
    profile = load_profile(cfg.data_dir, cfg.version)
    sink = EventSink(
        EventPublisher.from_env(),
        dst_port=cfg.public_port,
        per_ip_rate=cfg.sessions_per_sec_per_ip,
        per_ip_burst=cfg.sessions_per_sec_per_ip * 15,
        global_rate=cfg.global_sessions_per_sec,
        global_burst=cfg.global_sessions_per_sec * 2,
        events_rate=cfg.global_events_per_sec,
        events_burst=cfg.global_events_per_sec * 2,
        priority_rate=cfg.priority_events_per_sec,
        priority_burst=cfg.priority_events_per_sec * 2,
        disconnect_rate=cfg.disconnect_events_per_sec,
        disconnect_burst=cfg.disconnect_events_per_sec * 2,
        queue_size=cfg.event_queue_size,
    )
    sink.start()
    watchdog = LoopWatchdog(limit=10.0)
    watchdog.start()
    tls_ctx = tls.make_context(cfg.data_dir) if cfg.tls else None
    sensor = Sensor(cfg, sink, profile, tls_ctx=tls_ctx)
    server = MssqlServer(cfg, sensor)
    port = await server.start()
    log.info("listening on %s:%d", cfg.host, port)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    async def report() -> None:
        while True:
            await asyncio.sleep(60)
            log.info("stats %s", json.dumps(sensor.stats()))

    reporter = asyncio.create_task(report())
    await stop.wait()
    log.info("shutting down")
    reporter.cancel()
    watchdog.stop()
    await server.stop()
    await sink.close()


def main() -> None:
    setup_logging()
    asyncio.run(run())


if __name__ == "__main__":
    main()

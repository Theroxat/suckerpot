"""Entry point: ``python -m rdp_sensor``."""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import sys
import time

from suckerpot_common import EventPublisher

from rdp_sensor.config import Config
from rdp_sensor.events import EventSink
from rdp_sensor.identity import load_or_create_identity
from rdp_sensor.server import RDPServer, Sensor, make_tls_context
from rdp_sensor.watchdog import LoopWatchdog


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
    # asyncio logs "SSL handshake failed" and similar noise for every hostile client.
    logging.getLogger("asyncio").setLevel(logging.CRITICAL)


async def run() -> None:
    cfg = Config.from_env()
    log = logging.getLogger("rdp_sensor")
    identity = load_or_create_identity(cfg.data_dir, cfg.hostname or None)
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
        per_ip_events_rate=cfg.per_ip_events_per_sec,
        per_ip_events_burst=cfg.per_ip_events_burst,
        per_ip_priority_rate=cfg.per_ip_priority_per_sec,
        per_ip_priority_burst=cfg.per_ip_priority_burst,
        queue_size=cfg.event_queue_size,
    )
    sink.start()
    watchdog = LoopWatchdog(limit=10.0)
    watchdog.start()
    sensor = Sensor(cfg, sink, make_tls_context(identity), identity)
    server = RDPServer(cfg, sensor)
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

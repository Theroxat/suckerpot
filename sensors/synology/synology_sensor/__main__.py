"""Entry point: ``python -m synology_sensor``."""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import sys
import time

from suckerpot_common import EventPublisher

from synology_sensor.api import SynologyApi
from synology_sensor.config import Config
from synology_sensor.events import EventSink
from synology_sensor.profile import load_or_create_profile
from synology_sensor.server import SynologySensor, SynologyServer
from synology_sensor.tls import ensure_certificate, load_public_key_pem, make_context
from synology_sensor.watchdog import LoopWatchdog


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, str] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=True)


def setup_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.INFO)


async def run() -> None:
    cfg = Config.from_env()
    watchdog = LoopWatchdog()
    watchdog.start()
    log = logging.getLogger("synology_sensor")
    profile = load_or_create_profile(cfg.data_dir)
    sink = EventSink(
        EventPublisher.from_env(),
        rate=cfg.events_per_sec,
        burst=cfg.events_burst,
        queue_size=cfg.event_queue_size,
        queue_bytes=cfg.event_queue_bytes,
        global_rate=cfg.global_events_per_sec,
        global_burst=cfg.global_events_per_sec * 2,
        important_ip_rate=cfg.important_per_ip_rate,
        important_ip_burst=cfg.important_per_ip_burst,
    )
    sink.start()
    cert, key = ensure_certificate(cfg.data_dir, profile)
    sensor = SynologySensor(cfg, sink, SynologyApi(cfg, profile, load_public_key_pem(cert)))
    sensor.tls_ctx = make_context(cert, key, sensor.on_sni)
    server = SynologyServer(cfg, sensor)
    http_port, https_port = await server.start()
    log.info("listening on %d (http) and %d (https)", http_port, https_port)

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
    await server.stop()
    await sink.close()
    watchdog.stop()


def main() -> None:
    setup_logging()
    asyncio.run(run())


if __name__ == "__main__":
    main()

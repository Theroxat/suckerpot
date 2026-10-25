"""Entry point: ``python -m adb_sensor``."""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import sys
import time

from suckerpot_common import EventPublisher

from adb_sensor.config import Config
from adb_sensor.events import EventSink
from adb_sensor.secret import load_or_create_secret
from adb_sensor.server import AdbServer, Sensor
from adb_sensor.watchdog import LoopWatchdog


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


async def run() -> None:
    cfg = Config.from_env()
    log = logging.getLogger("adb_sensor")
    seed = load_or_create_secret(cfg.data_dir)
    sink = EventSink(
        EventPublisher.from_env(),
        rate=cfg.events_per_sec,
        burst=cfg.events_burst,
        queue_size=cfg.event_queue_size,
        dst_port=cfg.public_port,
        noisy_rate=cfg.noisy_events_per_sec,
        global_rate=cfg.global_events_per_sec,
        global_burst=cfg.global_events_per_sec * 2,
        summary_interval=cfg.summary_interval,
    )
    sink.start()
    watchdog = LoopWatchdog()
    watchdog.start()
    sensor = Sensor(cfg, sink, seed)
    server = AdbServer(cfg, sensor)
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

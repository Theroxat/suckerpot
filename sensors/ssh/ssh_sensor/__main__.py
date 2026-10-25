"""Entry point: ``python -m ssh_sensor``."""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import sys
import time

from suckerpot_common import EventPublisher

from ssh_sensor.config import Config
from ssh_sensor.events import EventSink
from ssh_sensor.hostkeys import load_or_create_host_keys, load_or_create_secret
from ssh_sensor.server import Sensor, SSHSensorServer
from ssh_sensor.shell.baseimage import derive_profile
from ssh_sensor.watchdog import LoopWatchdog


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
    logging.getLogger("asyncssh").setLevel(logging.WARNING)


async def run() -> None:
    cfg = Config.from_env()
    log = logging.getLogger("ssh_sensor")
    keys = load_or_create_host_keys(cfg.hostkey_dir)
    seed = load_or_create_secret(cfg.hostkey_dir)
    profile = derive_profile(
        seed,
        cfg.hostname,
        cfg.fake_ip,
        os_version=cfg.os_version,
        kernel=cfg.kernel,
        kernel_build=cfg.kernel_build,
    )
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
        ip_bytes_rate=cfg.ip_event_bytes_per_sec,
        ip_bytes_burst=cfg.ip_event_bytes_burst,
        global_bytes_rate=cfg.global_event_bytes_per_sec,
        global_bytes_burst=cfg.global_event_bytes_burst,
        queue_bytes=cfg.event_queue_bytes,
    )
    sink.start()
    watchdog = LoopWatchdog()
    watchdog.start()
    sensor = Sensor(cfg, sink, profile)
    server = SSHSensorServer(cfg, sensor, keys)
    port = await server.start()
    log.info("listening on %s:%d", cfg.host, port)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    async def report() -> None:
        while True:
            await asyncio.sleep(cfg.stats_interval)
            log.info("stats %s", json.dumps({**sensor.stats(), **watchdog.stats()}))

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

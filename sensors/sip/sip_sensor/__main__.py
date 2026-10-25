"""Entry point: ``python -m sip_sensor``."""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import sys
import time

from suckerpot_common import EventPublisher

from sip_sensor.config import Config
from sip_sensor.events import EventSink, Tracker
from sip_sensor.handler import Handler
from sip_sensor.identity import load_profile
from sip_sensor.server import Sensor, SipServer
from sip_sensor.watchdog import LoopWatchdog


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
    logging.getLogger("asyncio").setLevel(logging.CRITICAL)


async def run() -> None:
    cfg = Config.from_env()
    log = logging.getLogger("sip_sensor")
    profile = load_profile(cfg.data_dir, cfg.user_agent, cfg.realm)
    sink = EventSink(
        EventPublisher.from_env(),
        dst_port=cfg.public_port,
        events_rate=cfg.global_events_per_sec,
        priority_rate=cfg.priority_events_per_sec,
        disconnect_rate=cfg.disconnect_events_per_sec,
        queue_size=cfg.event_queue_size,
    )
    sink.start()
    watchdog = LoopWatchdog(limit=10.0)
    watchdog.start()
    tracker = Tracker(
        sink,
        per_ip_rate=cfg.sessions_per_sec_per_ip,
        per_ip_burst=cfg.sessions_burst_per_ip,
        global_rate=cfg.global_sessions_per_sec,
        max_sessions=cfg.max_sessions,
        idle=cfg.session_idle,
        max_age=cfg.session_max,
        quota_priority=cfg.quota_priority,
        quiet_loopback=cfg.quiet_loopback,
    )
    sensor = Sensor(cfg, Handler(cfg, profile, tracker), tracker)
    server = SipServer(cfg, sensor)
    port = await server.start()
    log.info("listening on %s:%d (udp%s)", cfg.host, port, "+tcp" if cfg.tcp else "")

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    async def report() -> None:
        while True:
            await asyncio.sleep(60)
            log.info("stats %s", json.dumps(sensor.stats() | sink.stats()))

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

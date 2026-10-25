"""Event-loop lag watchdog.

A thread (so it keeps running when the loop is blocked) checks a heartbeat that an asyncio
task refreshes every half second. If the heartbeat is older than ``limit`` seconds the process
exits and the container restarts. This is the last line of defence against a command that
blocks the loop despite the per-line time budget.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from collections.abc import Callable

log = logging.getLogger("ssh_sensor.watchdog")


class LoopWatchdog:
    def __init__(
        self,
        limit: float = 10.0,
        interval: float = 1.0,
        on_stall: Callable[[float], None] | None = None,
    ) -> None:
        self.limit = limit
        self.interval = interval
        self._on_stall = on_stall or self._exit
        self._beat = time.monotonic()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._watch, name="loop-watchdog", daemon=True)
        self._task: asyncio.Task[None] | None = None
        self.max_lag = 0.0  # worst heartbeat delay seen (seconds beyond the planned sleep)
        self._warned = 0.0

    @staticmethod
    def _exit(lag: float) -> None:
        log.error("event loop blocked for %.1f s, exiting", lag)
        os._exit(70)

    def _watch(self) -> None:
        while not self._stop.wait(self.interval):
            lag = time.monotonic() - self._beat
            if lag > self.limit:
                self._on_stall(lag)
                return

    async def _heartbeat(self) -> None:
        period = min(0.5, self.interval / 2)
        while True:
            now = time.monotonic()
            lag = max(0.0, now - self._beat - period)
            self._beat = now
            self.max_lag = max(self.max_lag, lag)
            if lag > 1.0 and now - self._warned > 10.0:
                self._warned = now
                log.warning("event loop lag %.2f s", lag)
            await asyncio.sleep(period)

    def stats(self) -> dict[str, int]:
        return {"loop_lag_max_ms": int(self.max_lag * 1000)}

    def start(self) -> None:
        self._beat = time.monotonic()
        self._task = asyncio.create_task(self._heartbeat())
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()

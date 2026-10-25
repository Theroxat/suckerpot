"""Event-loop lag watchdog.

A thread (so it keeps running when the loop is blocked) checks a heartbeat that an asyncio
task refreshes every half second. If the heartbeat is older than ``limit`` seconds the process
exits and the container restarts (compose ``restart: unless-stopped`` does not restart a
container that is merely unhealthy). This is the last line of defence against any code path
that would spin or block the loop.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from collections.abc import Callable

log = logging.getLogger("sip_sensor.watchdog")


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
        while True:
            self._beat = time.monotonic()
            await asyncio.sleep(min(0.5, self.interval / 2))

    def start(self) -> None:
        self._beat = time.monotonic()
        self._task = asyncio.create_task(self._heartbeat())
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()

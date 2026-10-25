"""Event emission: bounded queue, rate limits, background publishing.

Handlers never wait for Redis. ``emit`` builds the event, applies the limits and puts it on a
bounded queue; background workers call the publisher. Anything that cannot be queued, or that
the publisher refuses, is only counted.

Limits (per event class):

* ``connect``: per source IP (connection floods).
* ordinary ``http_request``: per session (one TCP connection).
* important events (``login_attempt``, ``download_attempt``, exploit ``http_request``): a
  separate, larger per-session bucket that ordinary traffic can never drain.
* ``disconnect``: never limited, it carries the counters and the number of suppressed events.
* important events are also limited per source IP, in front of the global cap.
* ONE sensor-wide bucket caps the total rate. Ordinary events may only use it while a reserved
  share of tokens is left for important events; ``disconnect`` may dip slightly below zero, so
  the ceiling stays close to the configured rate even for floods of short connections.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from collections import OrderedDict
from datetime import UTC, datetime
from typing import Any, Protocol

from pydantic import ValidationError
from suckerpot_common import Event, EventType, SensorName, truncate_data

log = logging.getLogger("web_sensor.events")

_MAX_TRACKED = 10_000
_WORKERS = 2


class Publisher(Protocol):
    async def publish(self, event: Event) -> bool: ...

    async def close(self) -> None: ...


class _Buckets:
    """Token buckets keyed by string, bounded in size (oldest keys are evicted)."""

    def __init__(self, rate: float, burst: float, max_keys: int = _MAX_TRACKED) -> None:
        self.rate = rate
        self.burst = burst
        self._max = max_keys
        self._items: OrderedDict[str, tuple[float, float]] = OrderedDict()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        tokens, last = self._items.get(key, (self.burst, now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        allowed = tokens >= 1.0
        if allowed:
            tokens -= 1.0
        self._items[key] = (tokens, now)
        self._items.move_to_end(key)
        while len(self._items) > self._max:
            self._items.popitem(last=False)
        return allowed

    def drop(self, key: str) -> None:
        self._items.pop(key, None)


class _GlobalBucket:
    """One token bucket with a reserved share for important events and a debt for disconnects."""

    def __init__(self, rate: float, burst: float, reserve_fraction: float = 0.25) -> None:
        self.rate = rate
        self.burst = burst
        self.reserve = burst * reserve_fraction
        self.debt = min(20.0, burst * 0.1)
        self.tokens = burst
        self.last = time.monotonic()

    def allow(self, important: bool, final: bool = False) -> bool:
        now = time.monotonic()
        self.tokens = min(self.burst, self.tokens + (now - self.last) * self.rate)
        self.last = now
        if final:
            floor = 1.0 - self.debt
        elif important:
            floor = 1.0
        else:
            floor = 1.0 + self.reserve
        if self.tokens < floor:
            return False
        self.tokens -= 1.0
        return True


class EventSink:
    def __init__(
        self,
        publisher: Publisher,
        *,
        rate: float = 20.0,
        burst: float = 100.0,
        queue_size: int = 5000,
        queue_bytes: int = 4 * 1024 * 1024,
        important_rate: float = 50.0,
        important_burst: float = 400.0,
        global_rate: float = 200.0,
        global_burst: float = 400.0,
        important_ip_rate: float = 20.0,
        important_ip_burst: float = 200.0,
    ) -> None:
        self._publisher = publisher
        # Bounded in count AND in bytes (JSON size of ``data``): a slow or unreachable Redis
        # must not turn the queue into the biggest memory consumer of the process.
        self._queue: asyncio.Queue[tuple[Event, int]] = asyncio.Queue(maxsize=queue_size)
        self._queue_bytes = queue_bytes
        self.queued_bytes = 0
        self._ip = _Buckets(rate, burst)
        self._session = _Buckets(rate, burst)
        self._important = _Buckets(important_rate, important_burst)
        self._important_ip = _Buckets(important_ip_rate, important_ip_burst)
        self._global = _GlobalBucket(global_rate, global_burst)
        self._suppressed: dict[str, int] = {}
        self._tasks: list[asyncio.Task[None]] = []
        self.emitted = 0
        self.published = 0
        self.rate_limited = 0
        self.global_limited = 0
        self.queue_full = 0
        self.publish_failed = 0
        self.invalid = 0

    def start(self) -> None:
        self._tasks = [asyncio.create_task(self._worker()) for _ in range(_WORKERS)]

    def _suppress(self, session_id: str) -> None:
        self.rate_limited += 1
        if session_id in self._suppressed or len(self._suppressed) < _MAX_TRACKED:
            self._suppressed[session_id] = self._suppressed.get(session_id, 0) + 1

    def end_session(self, session_id: str) -> int:
        """Forget a session's buckets; returns how many of its events were suppressed."""
        self._session.drop(session_id)
        self._important.drop(session_id)
        return self._suppressed.pop(session_id, 0)

    def emit(
        self,
        *,
        session_id: str,
        src_ip: str,
        src_port: int,
        dst_port: int,
        type_: EventType,
        data: dict[str, Any],
        important: bool = False,
        ts: datetime | None = None,
        max_string: int = 4096,
    ) -> bool:
        """Queue one event. Returns False if it was dropped. Never raises."""
        if type_ == EventType.disconnect:
            ok = self._global.allow(True, final=True)
        elif important:
            ok = (
                self._important.allow(session_id)
                and self._important_ip.allow(src_ip)
                and self._global.allow(True)
            )
        elif type_ == EventType.connect:
            ok = self._ip.allow(src_ip) and self._global.allow(False)
        else:
            ok = self._session.allow(session_id) and self._global.allow(False)
        if not ok:
            if type_ == EventType.disconnect:
                self.global_limited += 1
            else:
                self._suppress(session_id)
            return False
        try:
            event = Event(
                ts=ts or datetime.now(UTC),
                sensor=SensorName.web,
                session_id=session_id,
                src_ip=src_ip,  # type: ignore[arg-type]
                src_port=src_port,
                dst_port=dst_port,
                type=type_,
                data=truncate_data(data, max_string=max_string),
            )
        except (ValidationError, ValueError, TypeError):
            self.invalid += 1
            log.warning("event rejected by schema validation (type=%s)", type_)
            return False
        size = len(json.dumps(event.data, default=str, separators=(",", ":"))) + 256
        if self.queued_bytes + size > self._queue_bytes:
            self.queue_full += 1
            return False
        try:
            self._queue.put_nowait((event, size))
        except asyncio.QueueFull:
            self.queue_full += 1
            return False
        self.queued_bytes += size
        self.emitted += 1
        return True

    async def _worker(self) -> None:
        while True:
            event, size = await self._queue.get()
            self.queued_bytes -= size
            try:
                if await self._publisher.publish(event):
                    self.published += 1
                else:
                    self.publish_failed += 1
            except Exception:
                self.publish_failed += 1
                log.exception("publisher raised unexpectedly")
            finally:
                self._queue.task_done()

    async def flush(self, wait: float = 5.0) -> None:
        """Wait until the queue is drained (bounded)."""
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._queue.join(), wait)

    async def close(self) -> None:
        await self.flush()
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await self._publisher.close()

    def stats(self) -> dict[str, int]:
        return {
            "emitted": self.emitted,
            "published": self.published,
            "rate_limited": self.rate_limited,
            "global_limited": self.global_limited,
            "queue_full": self.queue_full,
            "publish_failed": self.publish_failed,
            "invalid": self.invalid,
        }

"""Event emission: session admission, bounded queue, background publishing.

An RDP connection produces at most three events (``connect``, one ``login_attempt`` or
``scan``, ``disconnect``), so rate limiting happens once per connection: :meth:`admit`
decides whether a connection is recorded, with a token bucket per source IP and a global one.
Connections that are not recorded behave identically on the wire; they are only counted and
reported periodically as one aggregated ``scan`` event (``kind = "rate_limited"``) per IP.

Handlers never wait for Redis: ``emit`` puts events on a bounded queue drained by background
workers, and anything that does not fit is only counted.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
import uuid
from collections import OrderedDict
from datetime import UTC, datetime
from typing import Any, Protocol

from pydantic import ValidationError
from suckerpot_common import Event, EventType, SensorName, truncate_data

log = logging.getLogger("rdp_sensor.events")

MAX_TRACKED_IPS = 10_000
SUMMARY_MAX_IPS = 100
_WORKERS = 2


class Publisher(Protocol):
    async def publish(self, event: Event) -> bool: ...

    async def close(self) -> None: ...


class Buckets:
    """Token buckets keyed by string, bounded in size (oldest keys are evicted)."""

    def __init__(self, rate: float, burst: float, max_keys: int = MAX_TRACKED_IPS) -> None:
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

    def __len__(self) -> int:
        return len(self._items)


class EventSink:
    def __init__(
        self,
        publisher: Publisher,
        *,
        dst_port: int = 3389,
        per_ip_rate: float = 2.0,
        per_ip_burst: float = 30.0,
        global_rate: float = 50.0,
        global_burst: float = 100.0,
        events_rate: float = 200.0,
        events_burst: float = 400.0,
        disconnect_rate: float = 60.0,
        disconnect_burst: float = 120.0,
        queue_size: int = 5000,
    ) -> None:
        self._publisher = publisher
        self._dst_port = dst_port
        self._queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=queue_size)
        self._per_ip = Buckets(per_ip_rate, per_ip_burst)
        self._global = Buckets(global_rate, global_burst, max_keys=1)
        self._events = Buckets(events_rate, events_burst, max_keys=1)
        # Disconnects carry the session summary, so they have their own (generous) budget.
        self._disconnects = Buckets(disconnect_rate, disconnect_burst, max_keys=1)
        self._suppressed: OrderedDict[str, int] = OrderedDict()
        self._tasks: list[asyncio.Task[None]] = []
        self.emitted = 0
        self.published = 0
        self.sessions_suppressed = 0
        self.events_limited = 0
        self.queue_full = 0
        self.publish_failed = 0
        self.invalid = 0
        self.untracked_suppressed = 0

    def start(self) -> None:
        self._tasks = [asyncio.create_task(self._worker()) for _ in range(_WORKERS)]

    # --- admission -----------------------------------------------------------------------

    def admit(self, src_ip: str) -> bool:
        """Should this new connection be recorded? Never raises."""
        if self._per_ip.allow(src_ip) and self._global.allow("*"):
            return True
        self.note_suppressed(src_ip)
        return False

    def note_suppressed(self, src_ip: str) -> None:
        self.sessions_suppressed += 1
        # No move_to_end: a busy IP must not keep its entry alive at the expense of others;
        # the flush picks the top talkers by count anyway.
        if src_ip in self._suppressed:
            self._suppressed[src_ip] += 1
        elif len(self._suppressed) < MAX_TRACKED_IPS:
            self._suppressed[src_ip] = 1
        else:
            self.untracked_suppressed += 1

    def flush_suppressed(self, window_s: float) -> int:
        """Emit one event per top IP with unrecorded connections, plus one aggregate for the rest.

        Returns the number of events emitted. All counters are reset.
        """
        top = sorted(self._suppressed.items(), key=lambda kv: kv[1], reverse=True)
        rest = top[SUMMARY_MAX_IPS:]
        top = top[:SUMMARY_MAX_IPS]
        rest_ips = len(rest) + (1 if self.untracked_suppressed else 0)
        rest_count = sum(c for _, c in rest) + self.untracked_suppressed
        self._suppressed.clear()
        self.untracked_suppressed = 0
        sent = 0
        for ip, count in top:
            self.emit(
                session_id=uuid.uuid4().hex[:24],
                src_ip=ip,
                src_port=0,
                type_=EventType.scan,
                data={
                    "kind": "rate_limited",
                    "suppressed_connections": count,
                    "window_s": round(window_s, 1),
                },
                force=True,
            )
            sent += 1
        if rest_count:
            self.emit(
                session_id=uuid.uuid4().hex[:24],
                src_ip="0.0.0.0",  # noqa: S104 - aggregate over many sources
                src_port=0,
                type_=EventType.scan,
                data={
                    "kind": "rate_limited_aggregate",
                    "suppressed_connections": rest_count,
                    "source_ips": rest_ips,
                    "window_s": round(window_s, 1),
                },
                force=True,
            )
            sent += 1
        return sent

    # --- emission ------------------------------------------------------------------------

    def emit(
        self,
        *,
        session_id: str,
        src_ip: str,
        src_port: int,
        type_: EventType,
        data: dict[str, Any],
        ts: datetime | None = None,
        force: bool = False,
    ) -> bool:
        """Queue one event. Returns False if it was dropped. Never raises."""
        if not force:
            bucket = self._disconnects if type_ == EventType.disconnect else self._events
            if not bucket.allow("*"):
                self.events_limited += 1
                return False
        try:
            event = Event(
                ts=ts or datetime.now(UTC),
                sensor=SensorName.rdp,
                session_id=session_id,
                src_ip=src_ip,  # type: ignore[arg-type]
                src_port=src_port,
                dst_port=self._dst_port,
                type=type_,
                data=truncate_data(data, max_string=1024),
            )
        except (ValidationError, ValueError, TypeError):
            self.invalid += 1
            log.warning("event rejected by schema validation (type=%s)", type_)
            return False
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self.queue_full += 1
            return False
        self.emitted += 1
        return True

    async def _worker(self) -> None:
        while True:
            event = await self._queue.get()
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
            "sessions_suppressed": self.sessions_suppressed,
            "events_limited": self.events_limited,
            "queue_full": self.queue_full,
            "publish_failed": self.publish_failed,
            "invalid": self.invalid,
            "tracked_ips": len(self._per_ip),
        }

"""Event emission: session admission, bounded queue, background publishing.

A connection is recorded only if :meth:`admit` says so (token bucket per source IP and a global
one). Inside a recorded connection the session applies its own quotas (see ``server.Session``),
and the sink adds global buckets: one for ordinary events, one for priority events (credentials,
downloads, flagged commands) so a flood of noise cannot starve them, and one for disconnects.
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
from collections import OrderedDict, deque
from datetime import UTC, datetime
from typing import Any, Protocol

from pydantic import ValidationError
from suckerpot_common import Event, EventType, SensorName, truncate_data

log = logging.getLogger("redis_sensor.events")

MAX_TRACKED_IPS = 10_000
SUMMARY_MAX_IPS = 100
_WORKERS = 2
URGENT_TYPES = frozenset(
    {
        EventType.connect,
        EventType.disconnect,
        EventType.login_attempt,
        EventType.download_attempt,
    }
)


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

    def allow(self, key: str, cost: float = 1.0) -> bool:
        now = time.monotonic()
        tokens, last = self._items.get(key, (self.burst, now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        allowed = tokens >= min(cost, self.burst)
        if allowed:
            tokens -= min(cost, self.burst)
        self._items[key] = (tokens, now)
        self._items.move_to_end(key)
        while len(self._items) > self._max:
            self._items.popitem(last=False)
        return allowed

    def take(self, key: str, cost: float = 1.0) -> tuple[bool, bool]:
        """Spend for ``key``: returns ``(allowed, heavy)``.

        ``heavy`` is True once the key has used more than half of its burst, i.e. it is a source
        consuming much more than its fair share."""
        allowed = self.allow(key, cost)
        return allowed, self._items[key][0] < self.burst / 2

    def __len__(self) -> int:
        return len(self._items)


class FairBucket:
    """A shared token bucket whose last ``reserve`` tokens only light sources may spend.

    Heavy sources (see :meth:`Buckets.take`) can drain it only down to the reserve, so any
    number of flooding IPs leaves a quiet one the shared budget (lesson 18)."""

    def __init__(self, rate: float, burst: float, reserve_fraction: float = 0.3) -> None:
        self.rate = rate
        self.burst = burst
        self.reserve = burst * reserve_fraction
        self.tokens = burst
        self._last = time.monotonic()

    def allow(self, heavy: bool) -> bool:
        now = time.monotonic()
        self.tokens = min(self.burst, self.tokens + (now - self._last) * self.rate)
        self._last = now
        if self.tokens - 1.0 >= (self.reserve if heavy else 0.0):
            self.tokens -= 1.0
            return True
        return False


class EventSink:
    def __init__(
        self,
        publisher: Publisher,
        *,
        dst_port: int = 6379,
        per_ip_rate: float = 2.0,
        per_ip_burst: float = 30.0,
        global_rate: float = 50.0,
        global_burst: float = 100.0,
        events_rate: float = 200.0,
        events_burst: float = 400.0,
        disconnect_rate: float = 60.0,
        disconnect_burst: float = 120.0,
        priority_rate: float = 300.0,
        priority_burst: float = 600.0,
        queue_size: int = 5000,
        priority_queue_size: int = 1000,
        ip_events_rate: float = 20.0,
        ip_events_burst: float = 200.0,
        ip_priority_rate: float = 10.0,
        ip_priority_burst: float = 100.0,
        ip_bytes_rate: float = 20_000.0,
        ip_bytes_burst: float = 300_000.0,
        ip_disconnect_rate: float = 4.0,
        ip_disconnect_burst: float = 60.0,
        ip_queued_max: int = 250,
        ip_priority_queued_max: int = 100,
    ) -> None:
        self._publisher = publisher
        self._dst_port = dst_port
        # Two bounded queues (priority events are published first) and per-IP limits applied
        # before them: rate, bytes and how many events one IP may have waiting. One noisy
        # source can therefore never crowd out the events of the others.
        self._normal: deque[Event] = deque()
        self._urgent: deque[Event] = deque()
        self._normal_max, self._urgent_max = queue_size, priority_queue_size
        self._ip_queued_max, self._ip_priority_queued_max = ip_queued_max, ip_priority_queued_max
        self._queued: dict[str, int] = {}
        self._wake = asyncio.Event()
        self._pending = 0
        self._ip_events = Buckets(ip_events_rate, ip_events_burst)
        self._ip_priority = Buckets(ip_priority_rate, ip_priority_burst)
        self._ip_bytes = Buckets(ip_bytes_rate, ip_bytes_burst)
        # Session ends have a reserve of their own: a flood must not leave sessions "open" forever.
        # Sized above the per-IP session admission rate, so every recorded session can close.
        self._ip_disconnects = Buckets(ip_disconnect_rate, ip_disconnect_burst)
        self._per_ip = Buckets(per_ip_rate, per_ip_burst)
        self._global = FairBucket(global_rate, global_burst)
        self._events = FairBucket(events_rate, events_burst)
        self._priority = FairBucket(priority_rate, priority_burst)
        # Disconnects carry the session summary, so they have their own (generous) budget.
        self._disconnects = FairBucket(disconnect_rate, disconnect_burst)
        self._suppressed: OrderedDict[str, int] = OrderedDict()
        self._tasks: list[asyncio.Task[None]] = []
        self.emitted = 0
        self.published = 0
        self.sessions_suppressed = 0
        self.events_limited = 0
        self.queue_full = 0
        self.ip_limited = 0
        self.publish_failed = 0
        self.invalid = 0
        self.untracked_suppressed = 0

    def start(self) -> None:
        self._tasks = [asyncio.create_task(self._worker()) for _ in range(_WORKERS)]

    # --- admission -----------------------------------------------------------------------

    def admit(self, src_ip: str) -> bool:
        """Should this new connection be recorded? Never raises."""
        allowed, heavy = self._per_ip.take(src_ip)
        if allowed and self._global.allow(heavy):
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
        priority: bool = False,
    ) -> bool:
        """Queue one event. Returns False if it was dropped. Never raises."""
        urgent = priority or type_ in URGENT_TYPES
        if not force:
            if type_ == EventType.disconnect:
                allowed, heavy = self._ip_disconnects.take(src_ip)
                bucket = self._disconnects
            else:
                cost = 300.0 + sum(len(v) for v in data.values() if isinstance(v, str))
                allowed, heavy = (self._ip_priority if urgent else self._ip_events).take(src_ip)
                ok_bytes, heavy_bytes = self._ip_bytes.take(src_ip, cost)
                allowed, heavy = allowed and ok_bytes, heavy or heavy_bytes
                bucket = self._priority if urgent else self._events
            if not allowed:
                self.ip_limited += 1
                return False
            if not bucket.allow(heavy):
                self.events_limited += 1
                return False
        try:
            event = Event(
                ts=ts or datetime.now(UTC),
                sensor=SensorName.redis,
                session_id=session_id,
                src_ip=src_ip,  # type: ignore[arg-type]
                src_port=src_port,
                dst_port=self._dst_port,
                type=type_,
                data=truncate_data(data, max_string=2048),
            )
        except (ValidationError, ValueError, TypeError):
            self.invalid += 1
            log.warning("event rejected by schema validation (type=%s)", type_)
            return False
        queue = self._urgent if urgent else self._normal
        cap = self._urgent_max if urgent else self._normal_max
        per_ip = self._ip_priority_queued_max if urgent else self._ip_queued_max
        key = ("u:" if urgent else "n:") + src_ip
        if len(queue) >= cap or (
            not force and type_ != EventType.disconnect and self._queued.get(key, 0) >= per_ip
        ):
            self.queue_full += 1
            return False
        queue.append(event)
        self._queued[key] = self._queued.get(key, 0) + 1
        self._pending += 1
        self._wake.set()
        self.emitted += 1
        return True

    def _next(self) -> Event | None:
        for queue, prefix in ((self._urgent, "u:"), (self._normal, "n:")):
            if queue:
                event = queue.popleft()
                key = prefix + str(event.src_ip)
                left = self._queued.get(key, 1) - 1
                if left > 0:
                    self._queued[key] = left
                else:
                    self._queued.pop(key, None)
                return event
        return None

    async def _worker(self) -> None:
        while True:
            event = self._next()
            if event is None:
                self._wake.clear()
                await self._wake.wait()
                continue
            try:
                if await self._publisher.publish(event):
                    self.published += 1
                else:
                    self.publish_failed += 1
            except Exception:
                self.publish_failed += 1
                log.exception("publisher raised unexpectedly")
            finally:
                self._pending -= 1

    async def flush(self, wait: float = 5.0) -> None:
        deadline = asyncio.get_running_loop().time() + wait
        while self._pending > 0 and asyncio.get_running_loop().time() < deadline:  # noqa: ASYNC110
            await asyncio.sleep(0.005)

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
            "ip_limited": self.ip_limited,
            "publish_failed": self.publish_failed,
            "invalid": self.invalid,
            "tracked_ips": len(self._per_ip),
        }

"""Event emission: session admission, fairness, bounded queues, background publishing.

Three levels of protection, each in front of the next:

1. :meth:`admit` decides per connection whether its routine events (``connect``, plain
   commands, ``disconnect``) are recorded, with a token bucket per source IP and a global one.
   Connections that are not recorded behave identically on the wire; they are only counted and
   reported periodically as one aggregated ``scan`` event (``kind = "rate_limited"``) per IP.
2. Important events (credentials, flagged queries, download attempts) have a token bucket PER
   SOURCE IP. What a flooding source cannot get through is not lost silently: it is folded into
   one ``scan`` event per source and window (``kind = "suppressed_logins"``: how many logins,
   and the most frequent user/password pairs). One noisy IP can therefore never use the shared
   budget up and starve the credentials of other IPs.
3. A hard ceiling (``events_rate``, 200/s by default) applies to every event except those
   aggregates, which are bounded by construction (at most ``SUMMARY_MAX_IPS`` + 1 per window
   for each kind). Routine events may use only part of the ceiling, so important events always
   keep a guaranteed share.

Handlers never wait for Redis: ``emit`` puts events on bounded queues drained by background
workers (important events have their own queue and are published first); anything that does
not fit is only counted.
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

log = logging.getLogger("mysql_sensor.events")

MAX_TRACKED_IPS = 10_000
SUMMARY_MAX_IPS = 100
MAX_OVER_IPS = 500  # sources with a pending suppressed-events aggregate
MAX_PAIRS = 32  # distinct user/password pairs tracked per source
TOP_PAIRS = 10  # pairs reported per aggregate
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

    def allow(self, key: str, cost: float = 1.0) -> bool:
        now = time.monotonic()
        tokens, last = self._items.get(key, (self.burst, now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        allowed = tokens >= cost
        if allowed:
            tokens -= cost
        self._items[key] = (tokens, now)
        self._items.move_to_end(key)
        while len(self._items) > self._max:
            self._items.popitem(last=False)
        return allowed

    def __len__(self) -> int:
        return len(self._items)


class Throttle:
    """Reservation-style limiter: ``reserve`` returns how long the caller must wait.

    Keyed like :class:`Buckets`. The wait grows with the backlog, so N parallel users of one
    key are served at ``rate`` in total, whatever N is.
    """

    def __init__(self, rate: float, burst: float, max_keys: int = MAX_TRACKED_IPS) -> None:
        self.rate = max(rate, 1e-9)
        self.burst = burst
        self._max = max_keys
        self._tat: OrderedDict[str, float] = OrderedDict()

    def reserve(self, key: str, cost: float, now: float | None = None) -> float:
        now = time.monotonic() if now is None else now
        tat = max(self._tat.get(key, now), now) + cost / self.rate
        self._tat[key] = tat
        self._tat.move_to_end(key)
        while len(self._tat) > self._max:
            self._tat.popitem(last=False)
        return max(0.0, tat - now - self.burst / self.rate)


class _Over:
    """Important events one source could not get through its own budget."""

    __slots__ = ("logins", "other", "pairs", "untracked")

    def __init__(self) -> None:
        self.logins = 0
        self.other = 0
        self.pairs: dict[tuple[str, str | None], int] = {}
        self.untracked = 0  # logins whose pair was not tracked (table full)


class EventSink:
    def __init__(
        self,
        publisher: Publisher,
        *,
        dst_port: int = 3306,
        per_ip_rate: float = 2.0,
        per_ip_burst: float = 30.0,
        global_rate: float = 50.0,
        global_burst: float = 100.0,
        events_rate: float = 200.0,
        events_burst: float = 400.0,
        routine_rate: float = 100.0,
        routine_burst: float = 200.0,
        important_ip_rate: float = 10.0,
        important_ip_burst: float = 50.0,
        disconnect_rate: float = 40.0,
        disconnect_burst: float = 80.0,
        queue_size: int = 5000,
        important_queue_size: int = 1000,
    ) -> None:
        self._publisher = publisher
        self._dst_port = dst_port
        self._queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=queue_size)
        self._important_queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=important_queue_size)
        self._wake = asyncio.Semaphore(0)  # one permit per queued event, both queues
        self._pending = 0  # queued + being published
        self._idle = asyncio.Event()
        self._idle.set()
        self._per_ip = Buckets(per_ip_rate, per_ip_burst)
        self._global = Buckets(global_rate, global_burst, max_keys=1)
        self._ceiling = Buckets(events_rate, events_burst, max_keys=1)
        self._routine = Buckets(routine_rate, routine_burst, max_keys=1)
        self._important_ip = Buckets(important_ip_rate, important_ip_burst)
        # Disconnects carry the session summary, so they have their own (generous) budget.
        self._disconnects = Buckets(disconnect_rate, disconnect_burst, max_keys=1)
        self._suppressed: OrderedDict[str, int] = OrderedDict()
        self._over: OrderedDict[str, _Over] = OrderedDict()
        self._over_untracked = 0
        self._tasks: list[asyncio.Task[None]] = []
        self.emitted = 0
        self.published = 0
        self.sessions_suppressed = 0
        self.events_limited = 0
        self.important_limited = 0
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

    def _note_over(self, src_ip: str, type_: EventType, data: dict[str, Any]) -> None:
        """Fold an important event that exceeded its source's budget into the aggregate."""
        self.important_limited += 1
        over = self._over.get(src_ip)
        if over is None:
            if len(self._over) >= MAX_OVER_IPS:
                self._over_untracked += 1
                return
            over = self._over[src_ip] = _Over()
        if type_ != EventType.login_attempt:
            over.other += 1
            return
        over.logins += 1
        pw = data.get("password")
        pair = (str(data.get("username", ""))[:64], str(pw)[:64] if pw is not None else None)
        if pair in over.pairs:
            over.pairs[pair] += 1
        elif len(over.pairs) < MAX_PAIRS:
            over.pairs[pair] = 1
        else:
            over.untracked += 1

    def flush_suppressed(self, window_s: float) -> int:
        """Emit the periodic aggregates (unrecorded connections, suppressed important events).

        One event per top IP plus one for the rest of each kind. Returns the number of events
        emitted. All counters are reset.
        """
        sent = self._flush_connections(window_s) + self._flush_over(window_s)
        return sent

    def _flush_connections(self, window_s: float) -> int:
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

    def _flush_over(self, window_s: float) -> int:
        over, untracked = self._over, self._over_untracked
        self._over, self._over_untracked = OrderedDict(), 0
        ranked = sorted(over.items(), key=lambda kv: kv[1].logins + kv[1].other, reverse=True)
        sent = 0
        for ip, agg in ranked[:SUMMARY_MAX_IPS]:
            top = sorted(agg.pairs.items(), key=lambda kv: kv[1], reverse=True)[:TOP_PAIRS]
            self.emit(
                session_id=uuid.uuid4().hex[:24],
                src_ip=ip,
                src_port=0,
                type_=EventType.scan,
                data={
                    "kind": "suppressed_logins" if agg.logins else "suppressed_important",
                    "count": agg.logins,
                    "other_events": agg.other,
                    "top_pairs": [
                        {"username": user, "password": pw, "count": n} for (user, pw), n in top
                    ],
                    "untracked_pairs": agg.untracked,
                    "window_s": round(window_s, 1),
                },
                force=True,
            )
            sent += 1
        rest = ranked[SUMMARY_MAX_IPS:]
        rest_count = sum(a.logins + a.other for _, a in rest) + untracked
        if rest_count:
            self.emit(
                session_id=uuid.uuid4().hex[:24],
                src_ip="0.0.0.0",  # noqa: S104 - aggregate over many sources
                src_port=0,
                type_=EventType.scan,
                data={
                    "kind": "suppressed_logins_aggregate",
                    "count": rest_count,
                    "source_ips": len(rest),
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
        important: bool = False,
        prelude: tuple[EventType, dict[str, Any], datetime] | None = None,
    ) -> bool:
        """Queue one event. Returns False if it was dropped. Never raises.

        ``prelude`` is an event that must precede this one (the deferred ``connect`` of a
        sampled-out session). It is queued only if this event passes its source's budget, so
        a flooding source cannot spend budget it does not have, and it does not count against
        that budget.
        """
        if not force:
            if important:
                if not self._important_ip.allow(src_ip):
                    self._note_over(src_ip, type_, data)
                    return False
            else:
                bucket = self._disconnects if type_ == EventType.disconnect else self._routine
                if not bucket.allow("*"):
                    self.events_limited += 1
                    return False
            if not self._ceiling.allow("*", 2.0 if prelude is not None else 1.0):
                self.events_limited += 1
                return False
        if prelude is not None:
            p_type, p_data, p_ts = prelude
            self._enqueue(session_id, src_ip, src_port, p_type, p_data, p_ts, important=True)
        return self._enqueue(session_id, src_ip, src_port, type_, data, ts, important=important)

    def _enqueue(
        self,
        session_id: str,
        src_ip: str,
        src_port: int,
        type_: EventType,
        data: dict[str, Any],
        ts: datetime | None,
        *,
        important: bool,
    ) -> bool:
        try:
            event = Event(
                ts=ts or datetime.now(UTC),
                sensor=SensorName.mysql,
                session_id=session_id,
                src_ip=src_ip,  # type: ignore[arg-type]
                src_port=src_port,
                dst_port=self._dst_port,
                type=type_,
                data=truncate_data(data, max_string=4096),
            )
        except (ValidationError, ValueError, TypeError):
            self.invalid += 1
            log.warning("event rejected by schema validation (type=%s)", type_)
            return False
        queue = self._important_queue if important else self._queue
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            self.queue_full += 1
            return False
        self._pending += 1
        self._idle.clear()
        self._wake.release()
        self.emitted += 1
        return True

    async def _worker(self) -> None:
        while True:
            await self._wake.acquire()
            queue = self._important_queue if not self._important_queue.empty() else self._queue
            try:
                event = queue.get_nowait()
            except asyncio.QueueEmpty:  # pragma: no cover - permits and items stay in step
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
                if self._pending <= 0:
                    self._idle.set()

    async def flush(self, wait: float = 5.0) -> None:
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._idle.wait(), wait)

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
            "important_limited": self.important_limited,
            "queue_full": self.queue_full,
            "publish_failed": self.publish_failed,
            "invalid": self.invalid,
            "tracked_ips": len(self._per_ip),
        }

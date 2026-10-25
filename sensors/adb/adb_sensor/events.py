"""Event emission: bounded queue, per-IP rate limit, background publishing.

Handlers never wait for Redis. ``emit`` builds the event, applies a per-source token bucket
and puts it on a bounded queue; background workers call the publisher. Anything that cannot be
queued, or that the publisher refuses, is only counted.
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

log = logging.getLogger("adb_sensor.events")

_MAX_TRACKED_IPS = 10_000
_WORKERS = 2


class Publisher(Protocol):
    async def publish(self, event: Event) -> bool: ...

    async def close(self) -> None: ...


class TokenBuckets:
    """Token buckets keyed by string, bounded in size (oldest keys are evicted)."""

    def __init__(self, rate: float, burst: float, max_keys: int = _MAX_TRACKED_IPS) -> None:
        self.rate = rate
        self.burst = burst
        self._max = max_keys
        self._items: OrderedDict[str, tuple[float, float]] = OrderedDict()

    def allow(self, key: str, reserve: float = 0.0) -> bool:
        """Take one token. ``reserve`` tokens must remain afterwards (kept for priority use)."""
        now = time.monotonic()
        tokens, last = self._items.get(key, (self.burst, now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        allowed = tokens >= 1.0 + reserve
        if allowed:
            tokens -= 1.0
        self._items[key] = (tokens, now)
        self._items.move_to_end(key)
        while len(self._items) > self._max:
            self._items.popitem(last=False)
        return allowed

    def drop(self, key: str) -> None:
        self._items.pop(key, None)


# Event types and how they are limited:
#   connect                          per source IP (connection floods)
#   scan, login_attempt              per session, so one noisy connection cannot starve another
#   command, download_attempt        per session, separate and generous quota (bounded by the
#                                    session caps), never shared with the noisy types
#   disconnect                       no per-key bucket (carries the replay and the counters)
# A sensor-wide bucket caps EVERYTHING, disconnect and forced events included. A small reserve
# of it is kept for priority events (the disconnect of a session that logged in or ran a
# command, and forced events), so they are only dropped when the reserve is exhausted too.
# Connections that never sent an authentication request (port scans, banner grabs) produce no
# connect/disconnect events at all: they are summarised per source IP (``note_connection``)
# into one periodic ``scan`` event with ``kind = connection_summary``.
_GLOBAL_RESERVE_FRACTION = 0.1
_NOISY = frozenset({EventType.scan, EventType.login_attempt})
_VALUABLE = frozenset({EventType.command, EventType.download_attempt})


_PRIORITY_TYPES = frozenset({EventType.connect, EventType.disconnect, EventType.download_attempt})
_PRIORITY_FLAGS = frozenset({"adb_push", "adb_install", "adb_reboot", "adb_service"})


def is_priority(type_: EventType, data: dict[str, Any]) -> bool:
    if type_ in _PRIORITY_TYPES or type_ == EventType.login_attempt:
        return True
    flags = data.get("flags")
    return isinstance(flags, list) and any(f in _PRIORITY_FLAGS for f in flags)


def _approx_size(data: dict[str, Any]) -> int:
    """Cheap size estimate of the string payload (data is already capped by truncate_data)."""
    total = 64
    for value in data.values():
        total += len(value) if isinstance(value, str) else 16
    return total


class EventSink:
    def __init__(
        self,
        publisher: Publisher,
        *,
        rate: float = 20.0,
        burst: float = 40.0,
        queue_size: int = 5000,
        dst_port: int = 5555,
        noisy_rate: float = 5.0,
        noisy_burst: float = 20.0,
        valuable_rate: float = 50.0,
        valuable_burst: float = 200.0,
        global_rate: float = 200.0,
        global_burst: float = 400.0,
        summary_interval: float = 60.0,
        ip_rate: float = 30.0,
        ip_burst: float = 150.0,
        ip_bytes_rate: float = 64 * 1024.0,
        ip_bytes_burst: float = 512 * 1024.0,
        priority_ip_rate: float = 10.0,
        priority_ip_burst: float = 60.0,
        priority_queue_size: int = 2000,
        repeat_limit: int = 5,
    ) -> None:
        self._publisher = publisher
        self._dst_port = dst_port
        # Two bounded queues: important events never wait behind (or get evicted by) bulk ones.
        self._queue_size = queue_size
        self._priority_size = priority_queue_size
        self._bulk: deque[Event] = deque()
        self._prio: deque[Event] = deque()
        self._wake = asyncio.Event()
        self._idle = asyncio.Event()
        self._idle.set()
        self._inflight = 0
        # Per source IP, BEFORE the shared queues: event rate and bytes (bulk), and a small
        # separate rate for important events so one IP cannot drown the others.
        self._ip_all = TokenBuckets(ip_rate, ip_burst)
        self._ip_bytes = TokenBuckets(ip_bytes_rate, ip_bytes_burst)
        self._ip_prio = TokenBuckets(priority_ip_rate, priority_ip_burst)
        self._repeat_limit = repeat_limit
        self._repeats: dict[str, tuple[str, int]] = {}
        self.ip_limited = 0
        self.repeat_limited = 0
        self.priority_full = 0
        self._ip = TokenBuckets(rate, burst)
        self._noisy = TokenBuckets(noisy_rate, noisy_burst)
        self._valuable = TokenBuckets(valuable_rate, valuable_burst)
        self._global = TokenBuckets(global_rate, global_burst, max_keys=1)
        self._reserve = max(1.0, global_burst * _GLOBAL_RESERVE_FRACTION)
        self._suppressed: dict[str, int] = {}
        self._summary_interval = summary_interval
        # src_ip -> [connections, rejected, first_seen, last_seen]; bounded like the buckets
        self._summary: OrderedDict[str, list[Any]] = OrderedDict()
        self.summary_overflow = 0
        self.priority_dropped = 0
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
        self._tasks.append(asyncio.create_task(self._summary_loop()))

    # ---- per-IP connection summary ------------------------------------------------------------
    def note_connection(self, src_ip: str, *, rejected: bool = False) -> None:
        """Count a connection that gets no events of its own (pre-auth, or refused by admit)."""
        now = datetime.now(UTC)
        entry = self._summary.get(src_ip)
        if entry is None:
            if len(self._summary) >= _MAX_TRACKED_IPS:
                self.summary_overflow += 1
                return
            entry = [0, 0, now, now]
            self._summary[src_ip] = entry
        entry[0] += 1
        entry[1] += 1 if rejected else 0
        entry[3] = now

    def flush_summaries(self) -> int:
        """Emit one ``scan`` summary event per source IP; returns how many were queued.

        Summaries that the global bucket refuses are kept (and merged) for the next round."""
        sent = 0
        for ip in list(self._summary):
            count, rejected, first, last = self._summary[ip]
            invalid = self.invalid
            ok = self.emit(
                session_id=uuid.uuid4().hex[:24],
                src_ip=ip,
                src_port=0,
                type_=EventType.scan,
                data={
                    "kind": "connection_summary",
                    "count": count,
                    "rejected": rejected,
                    "first_seen": first.isoformat(),
                    "last_seen": last.isoformat(),
                    "interval_s": self._summary_interval,
                },
                ts=last,
                summary=True,
            )
            if not ok and self.invalid == invalid:
                break  # global cap or queue full: keep the rest for the next round
            del self._summary[ip]
            sent += 1
        return sent

    async def _summary_loop(self) -> None:
        while True:
            await asyncio.sleep(self._summary_interval)
            self.flush_summaries()

    def _suppress(self, session_id: str) -> None:
        self.rate_limited += 1
        if session_id in self._suppressed or len(self._suppressed) < _MAX_TRACKED_IPS:
            self._suppressed[session_id] = self._suppressed.get(session_id, 0) + 1

    def end_session(self, session_id: str) -> int:
        """Forget a session's buckets; returns how many of its events were suppressed."""
        self._repeats.pop(session_id, None)
        self._noisy.drop(session_id)
        self._valuable.drop(session_id)
        return self._suppressed.pop(session_id, 0)

    def emit(
        self,
        *,
        session_id: str,
        src_ip: str,
        src_port: int,
        type_: EventType,
        data: dict[str, Any],
        ts: datetime | None = None,
        max_string: int = 4096,
        cap_data: bool = True,
        force: bool = False,
        priority: bool = False,
        summary: bool = False,
    ) -> bool:
        """Queue one event. Returns False if it was dropped. Never raises.

        ``force`` skips the per-key buckets; ``force`` and ``priority`` may also use the
        reserve of the global bucket. ``summary`` (internal) skips the per-key buckets only.
        """
        if not (force or summary) and type_ != EventType.disconnect:
            if type_ in _NOISY:
                ok = self._noisy.allow(session_id)
            elif type_ in _VALUABLE:
                ok = self._valuable.allow(session_id)
            else:
                ok = self._ip.allow(src_ip)
            if not ok:
                self._suppress(session_id)
                return False
        important = force or priority or is_priority(type_, data)
        if not (force or summary) and type_ != EventType.disconnect:
            if important:
                ok = self._ip_prio.allow(src_ip)
            else:
                ok = self._ip_all.allow(src_ip) and self._ip_bytes_ok(src_ip, data)
                if ok and type_ == EventType.command:
                    ok = self._repeat_ok(session_id, data)
            if not ok:
                self.ip_limited += 1
                self._suppress(session_id)
                return False
        urgent = force or priority
        if not self._global.allow("*", 0.0 if urgent else self._reserve):
            self.global_limited += 1
            if urgent:
                self.priority_dropped += 1
            if force or summary or type_ == EventType.disconnect:
                self.rate_limited += 1  # the session is over: nothing to report it on
            else:
                self._suppress(session_id)
            return False
        try:
            event = Event(
                ts=ts or datetime.now(UTC),
                sensor=SensorName.adb,
                session_id=session_id,
                src_ip=src_ip,  # type: ignore[arg-type]
                src_port=src_port,
                dst_port=self._dst_port,
                type=type_,
                data=truncate_data(data, max_string=max_string) if cap_data else data,
            )
        except (ValidationError, ValueError, TypeError):
            self.invalid += 1
            log.warning("event rejected by schema validation (type=%s)", type_)
            return False
        queue, cap = (
            (self._prio, self._priority_size) if important else (self._bulk, self._queue_size)
        )
        if len(queue) >= cap:
            if important:
                self.priority_full += 1
            self.queue_full += 1
            return False
        queue.append(event)
        self._inflight += 1
        self._idle.clear()
        self._wake.set()
        self.emitted += 1
        return True

    def _ip_bytes_ok(self, src_ip: str, data: dict[str, Any]) -> bool:
        cost = max(1, _approx_size(data) // 1024)  # 1 KiB per token
        return all(self._ip_bytes.allow(src_ip) for _ in range(min(cost, 64)))

    def _repeat_ok(self, session_id: str, data: dict[str, Any]) -> bool:
        """The same command line again and again in one session is counted, not stored."""
        key = str(data.get("input", ""))[:256]
        last, count = self._repeats.get(session_id, ("", 0))
        count = count + 1 if key == last else 1
        if len(self._repeats) >= _MAX_TRACKED_IPS and session_id not in self._repeats:
            self._repeats.pop(next(iter(self._repeats)))
        self._repeats[session_id] = (key, count)
        if count > self._repeat_limit:
            self.repeat_limited += 1
            return False
        return True

    async def _worker(self) -> None:
        while True:
            event = self._prio.popleft() if self._prio else None
            if event is None and self._bulk:
                event = self._bulk.popleft()
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
                self._inflight -= 1
                if self._inflight <= 0:
                    self._idle.set()

    async def flush(self, wait: float = 5.0) -> None:
        """Wait until both queues are drained (bounded)."""
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._idle.wait(), wait)

    async def close(self) -> None:
        self.flush_summaries()
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
            "ip_limited": self.ip_limited,
            "repeat_limited": self.repeat_limited,
            "priority_full": self.priority_full,
            "queued": len(self._bulk) + len(self._prio),
            "publish_failed": self.publish_failed,
            "invalid": self.invalid,
            "priority_dropped": self.priority_dropped,
            "summary_pending": len(self._summary),
            "summary_overflow": self.summary_overflow,
        }

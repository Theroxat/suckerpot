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
from collections import OrderedDict
from datetime import UTC, datetime
from typing import Any, Protocol

from pydantic import ValidationError
from suckerpot_common import Event, EventType, SensorName, truncate_data

log = logging.getLogger("ssh_sensor.events")

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

    def allow(self, key: str, reserve: float = 0.0, cost: float = 1.0) -> bool:
        """Take ``cost`` tokens. ``reserve`` tokens must remain afterwards (priority use)."""
        tokens = self._refill(key)
        allowed = tokens >= cost + reserve
        if allowed:
            self._items[key] = (tokens - cost, self._items[key][1])
        return allowed

    def charge(self, key: str, cost: float) -> None:
        """Take ``cost`` tokens unconditionally; the balance may go negative (bounded debt)."""
        tokens = self._refill(key)
        self._items[key] = (max(-self.burst, tokens - cost), self._items[key][1])

    def balance(self, key: str) -> float:
        """Current tokens of ``key`` (negative while in debt)."""
        return self._refill(key)

    def refund(self, key: str, cost: float) -> None:
        if key in self._items:
            tokens, last = self._items[key]
            self._items[key] = (min(self.burst, tokens + cost), last)

    def _refill(self, key: str) -> float:
        now = time.monotonic()
        tokens, last = self._items.get(key, (self.burst, now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        self._items[key] = (tokens, now)
        self._items.move_to_end(key)
        while len(self._items) > self._max:
            self._items.popitem(last=False)
        return tokens

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
#
# Byte budgets (approximate JSON size of ``data``) come on top of the event counts: one per
# source IP and one sensor-wide. When an event does not fit, a ``command`` event loses its full
# ``output`` (``input`` and a 1 KiB ``output_preview`` stay, ``output_omitted`` is set) and a
# ``disconnect`` loses its replay (``replay_omitted``); if even that does not fit, the event is
# dropped and counted (``events_suppressed`` of the session). Priority events are charged to
# the per-IP budget without being refused by it, and may use the reserve of the global one.
# The queue itself is capped in bytes too.
_GLOBAL_RESERVE_FRACTION = 0.1
_PREVIEW_CHARS = 1024
_EVENT_OVERHEAD = 256  # envelope fields (ts, sensor, session_id, addresses...)
_NOISY = frozenset({EventType.scan, EventType.login_attempt})
_VALUABLE = frozenset({EventType.command, EventType.download_attempt})


class EventSink:
    def __init__(
        self,
        publisher: Publisher,
        *,
        rate: float = 20.0,
        burst: float = 40.0,
        queue_size: int = 5000,
        dst_port: int = 22,
        noisy_rate: float = 5.0,
        noisy_burst: float = 20.0,
        valuable_rate: float = 50.0,
        valuable_burst: float = 200.0,
        global_rate: float = 200.0,
        global_burst: float = 400.0,
        summary_interval: float = 60.0,
        ip_bytes_rate: float = 20_000.0,
        ip_bytes_burst: float = 1_000_000.0,
        global_bytes_rate: float = 200_000.0,
        global_bytes_burst: float = 2_000_000.0,
        queue_bytes: int = 8 * 1024 * 1024,
    ) -> None:
        self._publisher = publisher
        self._dst_port = dst_port
        self._queue: asyncio.Queue[tuple[Event, int]] = asyncio.Queue(maxsize=queue_size)
        self._queue_bytes_max = queue_bytes
        self.queued_bytes = 0
        self._ip_bytes = TokenBuckets(ip_bytes_rate, ip_bytes_burst)
        self._global_bytes = TokenBuckets(global_bytes_rate, global_bytes_burst, max_keys=1)
        self._bytes_reserve = global_bytes_burst * _GLOBAL_RESERVE_FRACTION
        self.degraded = 0
        self.byte_limited = 0
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
            if cap_data:
                data = truncate_data(data, max_string=max_string)
        except (ValueError, TypeError):
            self.invalid += 1
            return False
        size = approx_size(data) + _EVENT_OVERHEAD
        byte_urgent = urgent or type_ == EventType.disconnect
        if not self._take_bytes(src_ip, size, byte_urgent):
            reduced = _degrade(type_, data)
            if reduced is not None:
                data = reduced
                size = approx_size(data) + _EVENT_OVERHEAD
            if reduced is None or not self._take_bytes(src_ip, size, byte_urgent):
                self.byte_limited += 1
                if urgent or summary or type_ == EventType.disconnect:
                    self.rate_limited += 1
                else:
                    self._suppress(session_id)
                return False
            self.degraded += 1
        if self.queued_bytes + size > self._queue_bytes_max:
            self.queue_full += 1
            return False
        try:
            event = Event(
                ts=ts or datetime.now(UTC),
                sensor=SensorName.ssh,
                session_id=session_id,
                src_ip=src_ip,  # type: ignore[arg-type]
                src_port=src_port,
                dst_port=self._dst_port,
                type=type_,
                data=data,
            )
        except (ValidationError, ValueError, TypeError):
            self.invalid += 1
            log.warning("event rejected by schema validation (type=%s)", type_)
            return False
        try:
            self._queue.put_nowait((event, size))
        except asyncio.QueueFull:
            self.queue_full += 1
            return False
        self.queued_bytes += size
        self.emitted += 1
        return True

    def _take_bytes(self, ip: str, size: int, urgent: bool) -> bool:
        """Charge ``size`` bytes to the per-IP and the global byte budgets."""
        if urgent:
            if not self._global_bytes.allow("*", 0.0, size):
                return False
            self._ip_bytes.charge(ip, size)
            return True
        if not self._ip_bytes.allow(ip, 0.0, size):
            return False
        if not self._global_bytes.allow("*", self._bytes_reserve, size):
            self._ip_bytes.refund(ip, size)
            return False
        return True

    async def _worker(self) -> None:
        while True:
            event, size = await self._queue.get()
            self.queued_bytes = max(0, self.queued_bytes - size)
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
            "publish_failed": self.publish_failed,
            "invalid": self.invalid,
            "degraded": self.degraded,
            "byte_limited": self.byte_limited,
            "queued_bytes": self.queued_bytes,
            "priority_dropped": self.priority_dropped,
            "summary_pending": len(self._summary),
            "summary_overflow": self.summary_overflow,
        }


def approx_size(value: Any, depth: int = 0) -> int:
    """Approximate JSON size of ``value`` in bytes (cheap; no serialisation)."""
    if isinstance(value, str):
        return (len(value) if value.isascii() else len(value.encode("utf-8", "replace"))) + 2
    if depth > 8:
        return 8
    if isinstance(value, dict):
        return 2 + sum(len(str(k)) + 4 + approx_size(v, depth + 1) for k, v in value.items())
    if isinstance(value, list | tuple):
        return 2 + sum(approx_size(v, depth + 1) + 1 for v in value)
    return 8


def _degrade(type_: EventType, data: dict[str, Any]) -> dict[str, Any] | None:
    """A smaller version of an event that went over a byte budget, or None if there is none."""
    if type_ == EventType.command and "output" in data:
        reduced = {k: v for k, v in data.items() if k != "output"}
        reduced["output_preview"] = str(data.get("output_preview", ""))[:_PREVIEW_CHARS]
        reduced["output_omitted"] = True
        return reduced
    if type_ == EventType.disconnect and "replay" in data:
        reduced = {k: v for k, v in data.items() if k not in ("replay", "replay_truncated")}
        reduced["replay_omitted"] = True
        return reduced
    return None

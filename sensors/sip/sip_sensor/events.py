"""Event emission: a bounded queue plus per-source-IP sessions with aggregation.

UDP has no connections, so a *session* is one source IP and the time it keeps talking (it
ends after ``session_idle`` seconds of silence or ``session_max`` seconds in all). Per session:

* high-value events (``login_attempt`` with credentials, ``command`` for INVITE) are emitted
  one by one, up to a quota;
* the first low-value message (OPTIONS, unknown methods, REGISTER without credentials, junk)
  is emitted at once as a ``scan``; every later one is only counted and reported in a single
  summary ``scan`` when the session ends. An OPTIONS flood is therefore one event per source.

Sources that do not get a session (global or per-IP admission buckets) are counted and
reported every ``summary_interval`` seconds as one ``scan`` (``rate_limited``) per top IP.
Handlers never wait for Redis: events go through a bounded queue drained by background tasks.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
import uuid
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from pydantic import ValidationError
from suckerpot_common import Event, EventType, SensorName, truncate_data

log = logging.getLogger("sip_sensor.events")

MAX_TRACKED_IPS = 10_000
SUMMARY_MAX_IPS = 100
_WORKERS = 2
_SAMPLES = 8


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

    def allow(self, key: str, cost: float = 1.0, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        tokens, last = self._items.get(key, (self.burst, now))
        tokens = min(self.burst, tokens + max(0.0, now - last) * self.rate)
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


class CpuBuckets:
    """Token buckets measured in CPU seconds. A key may go into debt (down to ``-burst``)."""

    def __init__(self, rate: float, burst: float, max_keys: int = MAX_TRACKED_IPS) -> None:
        self.rate = rate
        self.burst = burst
        self._max = max_keys
        self._items: OrderedDict[str, tuple[float, float]] = OrderedDict()

    def ready(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        tokens, last = self._items.get(key, (self.burst, now))
        return min(self.burst, tokens + max(0.0, now - last) * self.rate) > 0.0

    def charge(self, key: str, cost: float, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        tokens, last = self._items.get(key, (self.burst, now))
        tokens = min(self.burst, tokens + max(0.0, now - last) * self.rate) - cost
        self._items[key] = (max(-self.burst, tokens), now)
        self._items.move_to_end(key)
        while len(self._items) > self._max:
            self._items.popitem(last=False)


IMPORTANT = frozenset(
    {EventType.connect, EventType.disconnect, EventType.login_attempt, EventType.command}
)


class EventSink:
    """Fair, bounded event queues in front of the publisher.

    Fairness (lesson 18): every event first passes a per-source-IP event bucket and a per-IP
    byte budget, and only then the global bucket, so one flooding source cannot use up the
    shared budget. Important events (connect, disconnect, login_attempt, command) have their
    own queue, which the workers always drain first; scans and summaries wait behind them.
    """

    def __init__(
        self,
        publisher: Publisher,
        *,
        dst_port: int = 5060,
        events_rate: float = 200.0,
        priority_rate: float = 300.0,
        disconnect_rate: float = 60.0,
        queue_size: int = 5000,
        ip_events_rate: float = 5.0,
        ip_priority_rate: float = 20.0,
        ip_bytes_rate: float = 16384.0,
    ) -> None:
        self._publisher = publisher
        self._dst_port = dst_port
        self._max_normal = queue_size
        self._max_important = queue_size
        self._normal: deque[Event] = deque()
        self._important: deque[Event] = deque()
        self._wake = asyncio.Event()
        self._busy = 0
        self._forced = Buckets(100.0, 300.0, max_keys=1)
        self._ip_events = Buckets(ip_events_rate, ip_events_rate * 6)
        self._ip_priority = Buckets(ip_priority_rate, ip_priority_rate * 6)
        self._ip_bytes = Buckets(ip_bytes_rate, ip_bytes_rate * 4)
        self._events = Buckets(events_rate, events_rate * 2, max_keys=1)
        self._priority = Buckets(priority_rate, priority_rate * 2, max_keys=1)
        self._disconnects = Buckets(disconnect_rate, disconnect_rate * 2, max_keys=1)
        self._tasks: list[asyncio.Task[None]] = []
        self.emitted = 0
        self.published = 0
        self.events_limited = 0
        self.queue_full = 0
        self.publish_failed = 0
        self.invalid = 0

    def start(self) -> None:
        self._tasks = [asyncio.create_task(self._worker()) for _ in range(_WORKERS)]

    def emit(
        self,
        *,
        session_id: str,
        src_ip: str,
        src_port: int,
        type_: EventType,
        data: dict[str, Any],
        force: bool = False,
        priority: bool = False,
    ) -> bool:
        """Queue one event. Returns False if it was dropped. Never raises."""
        if force:
            # Summaries and rate_limited reports are bounded too (a sweep of many sessions).
            if not self._forced.allow("*"):
                self.events_limited += 1
                return False
        else:
            cost = float(min(16384, len(str(data)) + 200))
            per_ip = self._ip_priority if priority or type_ in IMPORTANT else self._ip_events
            if not (per_ip.allow(src_ip) and self._ip_bytes.allow(src_ip, cost=cost)):
                self.events_limited += 1
                return False
            if type_ == EventType.disconnect:
                bucket = self._disconnects
            else:
                bucket = self._priority if priority else self._events
            if not bucket.allow("*"):
                self.events_limited += 1
                return False
        try:
            event = Event(
                ts=datetime.now(UTC),
                sensor=SensorName.sip,
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
        important = type_ in IMPORTANT
        queue = self._important if important else self._normal
        if len(queue) >= (self._max_important if important else self._max_normal):
            self.queue_full += 1
            return False
        queue.append(event)
        self._wake.set()
        self.emitted += 1
        return True

    async def _worker(self) -> None:
        while True:
            if self._important:
                event = self._important.popleft()
            elif self._normal:
                event = self._normal.popleft()
            else:
                self._wake.clear()
                if not self._important and not self._normal:
                    await self._wake.wait()
                continue
            self._busy += 1
            try:
                if await self._publisher.publish(event):
                    self.published += 1
                else:
                    self.publish_failed += 1
            except Exception:
                self.publish_failed += 1
                log.exception("publisher raised unexpectedly")
            finally:
                self._busy -= 1

    async def flush(self, wait: float = 5.0) -> None:
        deadline = time.monotonic() + wait
        while (  # noqa: ASYNC110
            self._important or self._normal or self._busy
        ) and time.monotonic() < deadline:
            await asyncio.sleep(0.01)

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
            "events_limited": self.events_limited,
            "queue_full": self.queue_full,
            "publish_failed": self.publish_failed,
            "invalid": self.invalid,
        }


@dataclass
class Session:
    id: str
    ip: str
    port: int
    started: float
    last: float
    messages: int = 0
    bytes_in: int = 0
    replies: int = 0
    silent: int = 0  # requests we deliberately did not answer
    methods: dict[str, int] = field(default_factory=dict)
    user_agents: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)  # sample of dialled / probed users
    flags: set[str] = field(default_factory=set)
    noisy_sent: int = 0
    priority_sent: int = 0
    aggregated: int = 0  # low-value messages folded into the summary
    suppressed: int = 0  # high-value events dropped by the session quota
    transports: set[str] = field(default_factory=set)
    verified: bool = False  # source proven not spoofed (valid nonce or TCP)

    def note(self, method: str, ua: str, target: str, size: int, transport: str) -> None:
        self.messages += 1
        self.bytes_in += size
        self.transports.add(transport)
        if method in self.methods or len(self.methods) < 16:
            self.methods[method] = self.methods.get(method, 0) + 1
        if ua and ua not in self.user_agents and len(self.user_agents) < _SAMPLES:
            self.user_agents.append(ua)
        if target and target not in self.targets and len(self.targets) < _SAMPLES * 2:
            self.targets.append(target)


class Tracker:
    """Per-source-IP sessions, admission control and aggregation."""

    def __init__(
        self,
        sink: EventSink,
        *,
        per_ip_rate: float = 0.1,
        per_ip_burst: float = 5.0,
        global_rate: float = 50.0,
        verified_rate: float = 20.0,
        max_sessions: int = 5000,
        idle: float = 30.0,
        max_age: float = 300.0,
        quota_priority: int = 200,
        quiet_loopback: bool = True,
    ) -> None:
        self.sink = sink
        self._admit_ip = Buckets(per_ip_rate, per_ip_burst)
        self._admit_global = Buckets(global_rate, global_rate * 2, max_keys=1)
        self._admit_verified = Buckets(verified_rate, verified_rate * 2, max_keys=1)
        self._sessions: dict[str, Session] = {}
        self._max_sessions = max_sessions
        self._idle = idle
        self._max_age = max_age
        self._quota_priority = quota_priority
        self._quiet_loopback = quiet_loopback
        self._unrecorded: OrderedDict[str, int] = OrderedDict()
        self.unrecorded_total = 0
        self.sessions_opened = 0

    def __len__(self) -> int:
        return len(self._sessions)

    def _quiet(self, ip: str) -> bool:
        return self._quiet_loopback and (ip == "::1" or ip.startswith("127."))

    def note_unrecorded(self, ip: str) -> None:
        self.unrecorded_total += 1
        if ip in self._unrecorded:
            self._unrecorded[ip] += 1
        elif len(self._unrecorded) < MAX_TRACKED_IPS:
            self._unrecorded[ip] = 1

    def session(self, ip: str, port: int, now: float, *, verified: bool = False) -> Session | None:
        """The session of ``ip`` (opened on demand); ``None`` when it may not be recorded.

        Sources with a proven address (``verified``) are admitted through their own lane, so a
        flood of spoofed sources cannot exhaust the admission of real ones.
        """
        sess = self._sessions.get(ip)
        if sess is not None:
            sess.last = now
            sess.verified = sess.verified or verified
            return sess
        if self._quiet(ip):
            return None
        room = self._max_sessions if verified else int(self._max_sessions * 0.8)
        lane = self._admit_verified if verified else self._admit_global
        if len(self._sessions) >= room or not (
            self._admit_ip.allow(ip, now=now) and lane.allow("*", now=now)
        ):
            self.note_unrecorded(ip)
            return None
        sess = Session(uuid.uuid4().hex[:24], ip, port, now, now, verified=verified)
        self._sessions[ip] = sess
        self.sessions_opened += 1
        self.sink.emit(
            session_id=sess.id,
            src_ip=ip,
            src_port=port,
            type_=EventType.connect,
            data={"transport": "udp/tcp", "protocol": "sip", "source_verified": verified},
        )
        return sess

    def high(self, sess: Session, port: int, type_: EventType, data: dict[str, Any]) -> bool:
        """Emit a high-value event (credentials, INVITE) within the session quota."""
        if sess.priority_sent >= self._quota_priority:
            sess.suppressed += 1
            return False
        sess.priority_sent += 1
        return self.sink.emit(
            session_id=sess.id,
            src_ip=sess.ip,
            src_port=port,
            type_=type_,
            data={**data, "source_verified": sess.verified},
            priority=True,
        )

    def low(self, sess: Session, port: int, data: dict[str, Any]) -> bool:
        """First low-value message: a ``scan`` at once; later ones are only counted."""
        if sess.noisy_sent >= 1:
            sess.aggregated += 1
            return False
        sess.noisy_sent += 1
        return self.sink.emit(
            session_id=sess.id,
            src_ip=sess.ip,
            src_port=port,
            type_=EventType.scan,
            data={**data, "source_verified": sess.verified},
        )

    def _close(self, sess: Session, reason: str, now: float) -> None:
        self._sessions.pop(sess.ip, None)
        if sess.aggregated:
            self.sink.emit(
                session_id=sess.id,
                src_ip=sess.ip,
                src_port=sess.port,
                type_=EventType.scan,
                force=True,
                data={
                    "kind": "sip_summary",
                    "source_verified": sess.verified,
                    "messages": sess.messages,
                    "aggregated": sess.aggregated,
                    "methods": dict(sess.methods),
                    "user_agents": list(sess.user_agents),
                    "targets": list(sess.targets),
                    "flags": sorted(sess.flags),
                    "window_s": round(sess.last - sess.started, 1),
                },
            )
        self.sink.emit(
            session_id=sess.id,
            src_ip=sess.ip,
            src_port=sess.port,
            type_=EventType.disconnect,
            data={
                "duration_s": round(max(0.0, sess.last - sess.started), 1),
                "reason": reason,
                "source_verified": sess.verified,
                "messages": sess.messages,
                "bytes_in": sess.bytes_in,
                "replies": sess.replies,
                "silent": sess.silent,
                "methods": dict(sess.methods),
                "flags": sorted(sess.flags),
                "transports": sorted(sess.transports),
                "suppressed_events": sess.suppressed,
            },
        )

    def sweep(self, now: float | None = None) -> int:
        """Close idle or over-age sessions. Returns how many were closed."""
        now = time.monotonic() if now is None else now
        done = [
            (s, "idle" if now - s.last >= self._idle else "max_session")
            for s in list(self._sessions.values())
            if now - s.last >= self._idle or now - s.started >= self._max_age
        ]
        for sess, reason in done:
            self._close(sess, reason, now)
        return len(done)

    def close_all(self, reason: str = "shutdown") -> None:
        for sess in list(self._sessions.values()):
            self._close(sess, reason, sess.last)

    def flush_unrecorded(self, window_s: float) -> int:
        """One ``scan`` per top IP that was not recorded, plus an aggregate for the rest."""
        top = sorted(self._unrecorded.items(), key=lambda kv: kv[1], reverse=True)
        rest = top[SUMMARY_MAX_IPS:]
        top = top[:SUMMARY_MAX_IPS]
        self._unrecorded.clear()
        sent = 0
        for ip, count in top:
            self.sink.emit(
                session_id=uuid.uuid4().hex[:24],
                src_ip=ip,
                src_port=0,
                type_=EventType.scan,
                force=True,
                data={
                    "kind": "rate_limited",
                    "suppressed_packets": count,
                    "window_s": round(window_s, 1),
                },
            )
            sent += 1
        if rest:
            self.sink.emit(
                session_id=uuid.uuid4().hex[:24],
                src_ip="0.0.0.0",  # noqa: S104 - aggregate over many sources
                src_port=0,
                type_=EventType.scan,
                force=True,
                data={
                    "kind": "rate_limited_aggregate",
                    "suppressed_packets": sum(c for _, c in rest),
                    "source_ips": len(rest),
                    "window_s": round(window_s, 1),
                },
            )
            sent += 1
        return sent

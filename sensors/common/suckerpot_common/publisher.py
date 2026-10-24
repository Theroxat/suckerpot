"""Publish events to the Redis stream. Only XADD is ever issued.

Publishing never raises on Redis problems (OOM, NOPERM, connection loss, timeouts): an
attacker-facing handler must not crash or hang because the queue is unhealthy. Failed events
are dropped, counted in ``dropped`` and logged at most once per error kind every 30 s. There
is no internal buffer, so memory use stays bounded.

A token bucket on serialized event bytes (``EVENTS_MAX_BYTES_PER_SEC``, default 200 kB/s, with
a burst of ``EVENTS_MAX_BYTES_BURST``, default 2 MB) is a last line of defence against a single
noisy attacker filling the disk. When it is empty, events are dropped without blocking and
counted in ``dropped_bytes`` / ``dropped_by_reason["byte_budget"]``. The lowest 10% of the
bucket is reserved for ``disconnect`` and ``login_attempt`` events so that session boundaries
and credentials survive a flood. A rate of 0 disables the limiter.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable, Iterable
from typing import Any

from redis.asyncio import Redis
from redis.asyncio.retry import Retry
from redis.backoff import NoBackoff
from redis.exceptions import RedisError

from suckerpot_common.models import Event, EventType

log = logging.getLogger("suckerpot.publisher")

DEFAULT_STREAM = "events"
DEFAULT_MAXLEN = 10_000
DEFAULT_BYTES_PER_SEC = 200_000
DEFAULT_BYTES_BURST = 2_000_000
RESERVED_SHARE = 0.10
PRIORITY_TYPES = frozenset({EventType.disconnect, EventType.login_attempt})
BYTE_BUDGET = "byte_budget"
SOCKET_TIMEOUT_S = 2.0
LOG_INTERVAL_S = 30.0

_ERRORS = (RedisError, OSError, TimeoutError)


class EventPublisher:
    """Async publisher. The `sensor` ACL user may only run XADD on the events stream."""

    def __init__(
        self,
        *,
        host: str,
        port: int = 6379,
        username: str | None = None,
        password: str | None = None,
        stream: str = DEFAULT_STREAM,
        maxlen: int = DEFAULT_MAXLEN,
        client: Any = None,
        max_bytes_per_sec: float = DEFAULT_BYTES_PER_SEC,
        burst_bytes: float = DEFAULT_BYTES_BURST,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._stream = stream
        self._maxlen = maxlen
        self._clock = clock
        self._rate = float(max_bytes_per_sec)
        self._burst = float(max(burst_bytes, 1))
        self._tokens = self._burst
        self._refilled_at = clock()
        self.published = 0
        self.published_bytes = 0
        self.dropped = 0
        self.dropped_bytes = 0
        self.dropped_by_reason: dict[str, int] = {}
        self.dropped_by_error: dict[str, int] = {}
        self._last_log: dict[str, float] = {}
        # `client` is for tests. lib_name/lib_version=None stops redis-py from sending
        # CLIENT SETINFO, which the sensor ACL user is not allowed to run.
        self._redis: Any = client or Redis(
            host=host,
            port=port,
            username=username,
            password=password,
            decode_responses=True,
            socket_connect_timeout=SOCKET_TIMEOUT_S,
            socket_timeout=SOCKET_TIMEOUT_S,
            retry=Retry(NoBackoff(), 0),
            lib_name=None,
            lib_version=None,
        )

    @classmethod
    def from_env(cls) -> EventPublisher:
        return cls(
            host=os.environ["REDIS_HOST"],
            port=int(os.environ.get("REDIS_PORT", "6379")),
            username=os.environ.get("REDIS_USER") or None,
            password=os.environ.get("REDIS_PASSWORD") or None,
            stream=os.environ.get("EVENTS_STREAM", DEFAULT_STREAM),
            maxlen=int(os.environ.get("EVENTS_MAXLEN") or DEFAULT_MAXLEN),
            max_bytes_per_sec=float(
                os.environ.get("EVENTS_MAX_BYTES_PER_SEC") or DEFAULT_BYTES_PER_SEC
            ),
            burst_bytes=float(os.environ.get("EVENTS_MAX_BYTES_BURST") or DEFAULT_BYTES_BURST),
        )

    def stats(self) -> dict[str, Any]:
        """Counters for the sensors' periodic stats logs."""
        return {
            "published": self.published,
            "published_bytes": self.published_bytes,
            "dropped": self.dropped,
            "dropped_bytes": self.dropped_bytes,
            "dropped_by_reason": dict(self.dropped_by_reason),
            "dropped_by_error": dict(self.dropped_by_error),
        }

    def _admit(self, event: Event, size: int) -> bool:
        """Token bucket on bytes. Never blocks. Ordinary events may not dip into the reserve."""
        if self._rate <= 0:
            return True
        now = self._clock()
        elapsed = max(0.0, now - self._refilled_at)
        self._refilled_at = now
        self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
        floor = 0.0 if event.type in PRIORITY_TYPES else self._burst * RESERVED_SHARE
        if self._tokens - size >= floor:
            self._tokens -= size
            return True
        self.dropped += 1
        self.dropped_bytes += size
        self.dropped_by_reason[BYTE_BUDGET] = self.dropped_by_reason.get(BYTE_BUDGET, 0) + 1
        self._log_rate_limited(BYTE_BUDGET, f"byte budget exhausted; total dropped={self.dropped}")
        return False

    def _log_rate_limited(self, kind: str, message: str) -> None:
        now = time.monotonic()
        if now - self._last_log.get(kind, -LOG_INTERVAL_S) >= LOG_INTERVAL_S:
            self._last_log[kind] = now
            log.warning("event dropped (%s): %s", kind, message)

    def _note_drop(self, exc: BaseException, count: int = 1) -> None:
        kind = type(exc).__name__
        self.dropped += count
        self.dropped_by_error[kind] = self.dropped_by_error.get(kind, 0) + count
        self.dropped_by_reason["redis_error"] = self.dropped_by_reason.get("redis_error", 0) + count
        self._log_rate_limited(kind, f"{exc}; total dropped={self.dropped}")

    async def publish(self, event: Event, *, stream: str | None = None) -> bool:
        """XADD one event. Returns True on success, False if it was dropped.

        ``stream`` overrides the constructor stream for this call.
        """
        fields = event.to_stream_fields()
        size = len(fields["event"].encode("utf-8"))
        if not self._admit(event, size):
            return False
        try:
            await self._redis.xadd(
                stream or self._stream, fields, maxlen=self._maxlen, approximate=True
            )
        except _ERRORS as exc:
            self._note_drop(exc)
            return False
        self.published += 1
        self.published_bytes += size
        return True

    async def publish_batch(
        self, events: Iterable[Event], *, stream: str | None = None
    ) -> list[bool]:
        """Pipeline XADDs. Returns one success flag per event, in order. Never raises."""
        batch = list(events)
        if not batch:
            return []
        flags = [False] * len(batch)
        admitted: list[tuple[int, dict[str, str], int]] = []
        for i, event in enumerate(batch):
            fields = event.to_stream_fields()
            size = len(fields["event"].encode("utf-8"))
            if self._admit(event, size):
                admitted.append((i, fields, size))
        if not admitted:
            return flags
        try:
            pipe = self._redis.pipeline(transaction=False)
            target = stream or self._stream
            for _, fields, _ in admitted:
                pipe.xadd(target, fields, maxlen=self._maxlen, approximate=True)
            results = await pipe.execute(raise_on_error=False)
        except _ERRORS as exc:
            self._note_drop(exc, len(admitted))
            return flags
        for (i, _, size), res in zip(admitted, results, strict=True):
            if isinstance(res, BaseException):
                self._note_drop(res)
            else:
                flags[i] = True
                self.published += 1
                self.published_bytes += size
        return flags

    async def publish_many(self, events: Iterable[Event], *, stream: str | None = None) -> int:
        """Like :meth:`publish_batch` but returns the number of events published."""
        return sum(await self.publish_batch(events, stream=stream))

    async def close(self) -> None:
        try:
            await self._redis.aclose()
        except _ERRORS:
            pass

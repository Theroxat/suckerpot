"""Publish events to the Redis stream. Only XADD is ever issued.

Publishing never raises on Redis problems (OOM, NOPERM, connection loss, timeouts): an
attacker-facing handler must not crash or hang because the queue is unhealthy. Failed events
are dropped, counted in ``dropped`` and logged at most once per error kind every 30 s. There
is no internal buffer, so memory use stays bounded.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Iterable
from typing import Any

from redis.asyncio import Redis
from redis.asyncio.retry import Retry
from redis.backoff import NoBackoff
from redis.exceptions import RedisError

from suckerpot_common.models import Event

log = logging.getLogger("suckerpot.publisher")

DEFAULT_STREAM = "events"
DEFAULT_MAXLEN = 10_000
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
    ) -> None:
        self._stream = stream
        self._maxlen = maxlen
        self.published = 0
        self.dropped = 0
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
        )

    def _note_drop(self, exc: BaseException, count: int = 1) -> None:
        kind = type(exc).__name__
        self.dropped += count
        self.dropped_by_error[kind] = self.dropped_by_error.get(kind, 0) + count
        now = time.monotonic()
        if now - self._last_log.get(kind, -LOG_INTERVAL_S) >= LOG_INTERVAL_S:
            self._last_log[kind] = now
            log.warning("event dropped (%s): %s; total dropped=%d", kind, exc, self.dropped)

    async def publish(self, event: Event) -> bool:
        """XADD one event. Returns True on success, False if it was dropped."""
        try:
            await self._redis.xadd(
                self._stream, event.to_stream_fields(), maxlen=self._maxlen, approximate=True
            )
        except _ERRORS as exc:
            self._note_drop(exc)
            return False
        self.published += 1
        return True

    async def publish_batch(self, events: Iterable[Event]) -> list[bool]:
        """Pipeline XADDs. Returns one success flag per event, in order. Never raises."""
        batch = list(events)
        if not batch:
            return []
        try:
            pipe = self._redis.pipeline(transaction=False)
            for event in batch:
                pipe.xadd(
                    self._stream, event.to_stream_fields(), maxlen=self._maxlen, approximate=True
                )
            results = await pipe.execute(raise_on_error=False)
        except _ERRORS as exc:
            self._note_drop(exc, len(batch))
            return [False] * len(batch)
        flags: list[bool] = []
        for res in results:
            if isinstance(res, BaseException):
                self._note_drop(res)
                flags.append(False)
            else:
                flags.append(True)
        self.published += sum(flags)
        return flags

    async def publish_many(self, events: Iterable[Event]) -> int:
        """Like :meth:`publish_batch` but returns the number of events published."""
        return sum(await self.publish_batch(events))

    async def close(self) -> None:
        try:
            await self._redis.aclose()
        except _ERRORS:
            pass

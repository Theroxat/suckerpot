"""Where generated events go: Redis (via EventPublisher) or stdout as JSON lines."""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Sequence
from typing import Protocol, TextIO

from suckerpot_common import Event, EventPublisher


class Sink(Protocol):
    async def emit(self, events: Sequence[Event]) -> None: ...

    async def close(self) -> None: ...


class RedisSink:
    """Publishes through EventPublisher, which drops events instead of raising.

    With a small stream MAXLEN the backfill only survives if ingest drains it, so events the
    publisher reports as dropped are retried with a growing back-off (demo only). Retries are
    bounded: after ``max_retries`` rounds the remaining events are given up on.
    """

    def __init__(
        self,
        publisher: EventPublisher | None = None,
        *,
        max_retries: int = 40,
        max_backoff: float = 5.0,
    ) -> None:
        self._pub = publisher or EventPublisher.from_env()
        self._max_retries = max_retries
        self._max_backoff = max_backoff
        self.gave_up = 0

    async def emit(self, events: Sequence[Event]) -> None:
        pending = list(events)
        delay = 0.25
        for attempt in range(self._max_retries + 1):
            flags = await self._pub.publish_batch(pending)
            pending = [e for e, ok in zip(pending, flags, strict=True) if not ok]
            if not pending:
                return
            if attempt < self._max_retries:
                await asyncio.sleep(delay)
                delay = min(delay * 2, self._max_backoff)
        self.gave_up += len(pending)
        print(f"gave up on {len(pending)} events after retries", file=sys.stderr)

    async def close(self) -> None:
        await self._pub.close()


class JsonLinesSink:
    def __init__(self, out: TextIO | None = None) -> None:
        self._out = out or sys.stdout

    async def emit(self, events: Sequence[Event]) -> None:
        for e in events:
            self._out.write(e.model_dump_json() + "\n")
        self._out.flush()

    async def close(self) -> None:
        self._out.flush()

"""Ingest-side disk guard: keep writing, but small, when the database nears its ceiling.

The size is checked at most every ``interval_s`` seconds (one cheap ``pg_database_size`` query).
Above 95% of the ceiling the guard turns "degraded" and stays so until the size is back under
90%; while degraded, ``command`` and ``http_request`` events keep their keys but every value is
cut to a short preview and the whole payload to about 1 KB. The retention side of the guard (a
TimescaleDB job) drops old raw chunks; see ``suckerpot_db.diskguard``.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

log = logging.getLogger(__name__)

ENTER_RATIO = 0.95
LEAVE_RATIO = 0.90
DEGRADED_TYPES = frozenset({"command", "http_request"})
PAYLOAD_BUDGET = 1024
VALUE_BUDGET = 256

StatusSink = Callable[[dict[str, Any]], Awaitable[None]]


def shrink_data(data: dict[str, Any]) -> dict[str, Any]:
    """Same keys (while the budget lasts), short values, about 1 KB at most."""
    out: dict[str, Any] = {}
    used = 0
    for key, value in data.items():
        k = str(key)[:64]
        if isinstance(value, str):
            v: Any = value[:VALUE_BUDGET]
        elif isinstance(value, bool | int | float) or value is None:
            v = value
        else:
            v = json.dumps(value, default=str)[:VALUE_BUDGET]
        cost = len(json.dumps(k)) + len(json.dumps(v, default=str)) + 2
        if used + cost > PAYLOAD_BUDGET:
            break
        out[k] = v
        used += cost
    out["_truncated"] = True
    return out


class DiskGuard:
    def __init__(
        self,
        factory: async_sessionmaker[AsyncSession],
        max_bytes: int,
        *,
        interval_s: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
        on_status: StatusSink | None = None,
    ) -> None:
        self.factory = factory
        self.max_bytes = max_bytes
        self.interval_s = interval_s
        self.clock = clock
        self.on_status = on_status
        self.degraded = False
        self.degraded_writes = 0
        self.size_bytes = 0
        self._next_check = 0.0
        self._published = False

    async def is_degraded(self) -> bool:
        """Cached answer; refreshes at most once per interval."""
        if self.clock() >= self._next_check:
            await self.refresh()
        return self.degraded

    async def refresh(self) -> None:
        self._next_check = self.clock() + self.interval_s
        try:
            async with self.factory() as session:
                size = int(
                    await session.scalar(text("SELECT pg_database_size(current_database())")) or 0
                )
        except Exception as exc:  # fail open: never block ingestion on a failed size check
            log.warning("disk guard: size check failed (%s)", type(exc).__name__)
            return
        self.size_bytes = size
        ratio = size / self.max_bytes
        was = self.degraded
        if not was and ratio > ENTER_RATIO:
            self.degraded = True
            log.error(
                "DISK GUARD: database at %.0f%% of its %d MB ceiling, "
                "keeping only small command and http payloads",
                ratio * 100,
                self.max_bytes // 1048576,
            )
        elif was and ratio < LEAVE_RATIO:
            self.degraded = False
            log.warning("disk guard: database back to %.0f%%, full payloads again", ratio * 100)
        await self._publish(ratio, changed=was != self.degraded)

    async def _publish(self, ratio: float, *, changed: bool) -> None:
        if self.on_status is None:
            return
        if not (changed or self.degraded or not self._published):
            return
        try:
            await self.on_status(
                {
                    "degraded": self.degraded,
                    "degraded_writes": self.degraded_writes,
                    "size_bytes": self.size_bytes,
                    "max_bytes": self.max_bytes,
                    "percent": round(ratio * 100, 1),
                }
            )
            self._published = True
        except Exception as exc:
            log.warning("disk guard: publishing status failed (%s)", type(exc).__name__)

    def degrade_rows(self, rows: list[dict[str, Any]]) -> None:
        """Shrink the payloads of ``rows`` in place and count them in ``degraded_writes``."""
        for row in rows:
            if row["type"] in DEGRADED_TYPES:
                row["data"] = shrink_data(row["data"])
                self.degraded_writes += 1


async def publish_system_status(
    factory: async_sessionmaker[AsyncSession], key: str, value: dict[str, Any]
) -> None:
    async with factory() as session, session.begin():
        await session.execute(
            text(
                """
                INSERT INTO system_status (key, value, updated_at)
                VALUES (:k, CAST(:v AS jsonb), now())
                ON CONFLICT (key) DO UPDATE SET value = CAST(:v AS jsonb), updated_at = now()
                """
            ),
            {"k": key, "v": json.dumps(value)},
        )

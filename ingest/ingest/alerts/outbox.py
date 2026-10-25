"""The outbox: queueing with deduplication, and delivery within rate limits.

* One row per rule, key and channel (``UNIQUE``), so a restart or a repeated cycle never sends the
  same alert twice.
* Limits per channel (10 a minute, 100 a day) and for all channels together (300 a day, rolling
  24 h). When more alerts wait than the minute allows, they leave as ONE digest message; when a
  daily limit is reached the rest is dropped as ``suppressed`` (kept visible in the list).
* A failed send is retried on the next cycles (up to 3 attempts) only when the error can pass.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

log = logging.getLogger(__name__)

MINUTE_LIMIT = 10
DAY_LIMIT = 100
GLOBAL_DAY_LIMIT = 300
CYCLE_LIMIT = 50
MAX_ATTEMPTS = 3
MAX_PENDING_READ = 50  # per channel and cycle
MAX_PENDING_PER_CHANNEL = 50  # more than this waiting: new alerts are kept as suppressed


class Plan(StrEnum):
    WAIT = "wait"
    EACH = "each"
    DIGEST = "digest"
    DROP = "drop"


@dataclass(frozen=True, slots=True)
class Pending:
    id: int
    rule_kind: str
    channel_id: int
    payload: dict[str, Any]
    attempts: int


@dataclass(slots=True)
class Usage:
    """What a channel (and everybody) has already sent."""

    minute: int = 0
    day: int = 0
    global_day: int = 0


def plan_channel(count: int, usage: Usage, cycle_left: int) -> Plan:
    """Decide what to do with ``count`` waiting alerts of one channel."""
    if count <= 0:
        return Plan.WAIT
    if usage.day >= DAY_LIMIT or usage.global_day >= GLOBAL_DAY_LIMIT:
        return Plan.DROP
    budget = min(MINUTE_LIMIT - usage.minute, DAY_LIMIT - usage.day, cycle_left,
                 GLOBAL_DAY_LIMIT - usage.global_day)  # fmt: skip
    if budget <= 0:
        return Plan.WAIT
    return Plan.EACH if count <= budget else Plan.DIGEST


async def enqueue(
    session: AsyncSession, rule_kind: str, dedupe_key: str, channel_id: int, payload: dict[str, Any]
) -> bool:
    """Queue one alert. False when the same alert was queued before.

    A channel that already has ``MAX_PENDING_PER_CHANNEL`` alerts waiting gets the new one stored
    as ``suppressed`` (``backlog``): visible in the list, never sent, so the backlog stays bounded
    whatever the channel does.
    """
    result = await session.execute(
        text(
            """
            INSERT INTO alert_outbox (rule_kind, dedupe_key, channel_id, payload, state, error_code)
            SELECT :r, :k, :c, CAST(:p AS jsonb),
                   CASE WHEN waiting >= :cap THEN 'suppressed' ELSE 'pending' END,
                   CASE WHEN waiting >= :cap THEN 'backlog' END
            FROM (SELECT count(*) AS waiting FROM alert_outbox
                  WHERE channel_id = :c AND state = 'pending') w
            ON CONFLICT (rule_kind, dedupe_key, channel_id) DO NOTHING
            """
        ),
        {
            "r": rule_kind,
            "k": dedupe_key[:128],
            "c": channel_id,
            "p": json.dumps(payload),
            "cap": MAX_PENDING_PER_CHANNEL,
        },
    )
    return bool(result.rowcount)  # type: ignore[attr-defined]


async def read_usage(
    factory: async_sessionmaker[AsyncSession],
) -> tuple[dict[int, Usage], int]:
    async with factory() as session:
        rows = (
            await session.execute(
                text(
                    """
                    SELECT channel_id,
                           count(*) FILTER (WHERE sent_at > now() - interval '1 minute') AS minute,
                           count(*) AS day
                    FROM alert_outbox
                    WHERE state = 'sent' AND sent_at > now() - interval '24 hours'
                    GROUP BY channel_id
                    """
                )
            )
        ).all()
    usage = {int(r.channel_id): Usage(minute=int(r.minute), day=int(r.day)) for r in rows}
    total = sum(u.day for u in usage.values())
    for u in usage.values():
        u.global_day = total
    return usage, total


async def pending_channels(factory: async_sessionmaker[AsyncSession]) -> list[int]:
    """Channels with something waiting, the one waiting longest first."""
    async with factory() as session:
        rows = (
            await session.execute(
                text(
                    "SELECT channel_id FROM alert_outbox WHERE state = 'pending' "
                    "GROUP BY channel_id ORDER BY min(id)"
                )
            )
        ).all()
    return [int(r.channel_id) for r in rows]


async def read_pending(
    factory: async_sessionmaker[AsyncSession], channel_id: int
) -> tuple[list[Pending], int]:
    """The oldest waiting alerts of ONE channel (bounded) and how many wait in all."""
    async with factory() as session:
        rows = (
            await session.execute(
                text(
                    """
                    SELECT id, rule_kind, channel_id, payload, attempts,
                           count(*) OVER () AS total
                    FROM alert_outbox WHERE state = 'pending' AND channel_id = :c
                    ORDER BY id LIMIT :n
                    """
                ),
                {"c": channel_id, "n": MAX_PENDING_READ},
            )
        ).all()
    items = [Pending(r.id, r.rule_kind, r.channel_id, dict(r.payload), r.attempts) for r in rows]
    return items, int(rows[0].total) if rows else 0


async def mark_channel_pending(
    factory: async_sessionmaker[AsyncSession], channel_id: int, state: str, error: str
) -> None:
    """Every waiting alert of a channel at once (one statement, however many there are)."""
    async with factory() as session, session.begin():
        await session.execute(
            text(
                "UPDATE alert_outbox SET state = :s, error_code = :e "
                "WHERE channel_id = :c AND state = 'pending'"
            ),
            {"s": state, "e": error, "c": channel_id},
        )


async def mark(
    factory: async_sessionmaker[AsyncSession],
    ids: list[int],
    state: str,
    *,
    error: str | None = None,
    attempt: bool = False,
) -> None:
    if not ids:
        return
    async with factory() as session, session.begin():
        await session.execute(
            text(
                """
                UPDATE alert_outbox
                SET state = :s, error_code = :e,
                    attempts = attempts + CASE WHEN :a THEN 1 ELSE 0 END,
                    sent_at = CASE WHEN :s = 'sent' THEN now() ELSE sent_at END
                WHERE id = ANY(:ids)
                """
            ),
            {"s": state, "e": error, "a": attempt, "ids": ids},
        )


async def record_retry(
    factory: async_sessionmaker[AsyncSession], items: list[Pending], code: str, retryable: bool
) -> None:
    """A failed send: keep the rows pending while a retry makes sense, otherwise fail them."""
    final = [p.id for p in items if not retryable or p.attempts + 1 >= MAX_ATTEMPTS]
    again = [p.id for p in items if p.id not in set(final)]
    await mark(factory, final, "failed", error=code, attempt=True)
    await mark(factory, again, "pending", error=code, attempt=True)


async def record_digest(
    factory: async_sessionmaker[AsyncSession],
    channel_id: int,
    rule_kind: str,
    key: str,
    payload: dict[str, Any],
) -> None:
    """The digest message itself, recorded as sent (it counts against the limits)."""
    async with factory() as session, session.begin():
        await session.execute(
            text(
                """
                INSERT INTO alert_outbox (rule_kind, dedupe_key, channel_id, payload, state,
                                          attempts, sent_at)
                VALUES (:r, :k, :c, CAST(:p AS jsonb), 'sent', 1, now())
                ON CONFLICT (rule_kind, dedupe_key, channel_id) DO NOTHING
                """
            ),
            {"r": rule_kind, "k": key[:128], "c": channel_id, "p": json.dumps(payload)},
        )

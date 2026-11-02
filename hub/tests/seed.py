"""Direct database seeding for worker tests (no API round trip)."""

from __future__ import annotations

import os
import uuid
from datetime import date, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

TODAY = date(2026, 11, 1)


async def add_nodes(
    sm: async_sessionmaker[AsyncSession],
    count: int,
    *,
    enrolled: list[date] | None = None,
    reputation: float = 0.8,
    active_days: int = 7,
    countries: list[str | None] | None = None,
    show_country: bool = False,
    today: date = TODAY,
) -> list[uuid.UUID]:
    """Aged nodes (one enrolment week each by default) that submitted batches recently."""
    ids: list[uuid.UUID] = []
    async with sm() as s:
        for i in range(count):
            day = enrolled[i] if enrolled else today - timedelta(days=20 + 7 * i)
            country = countries[i] if countries else None
            node_id = (
                await s.execute(
                    text(
                        "INSERT INTO nodes (pubkey, enrolled_day, last_active_day, reputation, "
                        "protocol, country, show_country) VALUES (:k, :e, :a, :r, 'spn/1', :c, :sc) "
                        "RETURNING id"
                    ),
                    {
                        "k": os.urandom(32),
                        "e": day,
                        "a": today,
                        "r": reputation,
                        "c": country,
                        "sc": show_country,
                    },
                )
            ).scalar_one()
            for d in range(1, active_days + 1):
                await s.execute(
                    text(
                        "INSERT INTO batches (node_id, day, batch_id, items) VALUES (:n, :d, :b, 1)"
                    ),
                    {"n": node_id, "d": today - timedelta(days=d), "b": os.urandom(16)},
                )
            ids.append(node_id)
        await s.commit()
    return ids


async def observe(
    sm: async_sessionmaker[AsyncSession],
    nodes: list[uuid.UUID],
    kind: str,
    value: str,
    days: list[date],
    **fields: Any,
) -> None:
    """Every node saw ``value`` on every day in ``days`` (one row per node and day)."""
    row = {
        "services": ["ssh"],
        "activity": ["login", "command"],
        "tags": ["mirai"],
        "families": [],
        "sessions": 1,
        "attempts": 3,
        "fetched": False,
        "file_type": None,
        "via": None,
        **fields,
    }
    async with sm() as s:
        for n in nodes:
            for d in days:
                await s.execute(
                    text(
                        "INSERT INTO observations (node_id, day, kind, value, services, activity, "
                        "tags, families, sessions, attempts, fetched, file_type, via) VALUES "
                        "(:n, :d, :k, :v, :services, :activity, :tags, :families, :sessions, "
                        ":attempts, :fetched, :file_type, :via) ON CONFLICT DO NOTHING"
                    ),
                    {"n": n, "d": d, "k": kind, "v": value, **row},
                )
        await s.commit()


async def target(sm: async_sessionmaker[AsyncSession], kind: str, value: str) -> Any:
    async with sm() as s:
        return (
            (
                await s.execute(
                    text("SELECT * FROM targets WHERE kind = :k AND coalesce(value_b, value) = :v"),
                    {"k": kind, "v": value},
                )
            )
            .mappings()
            .first()
        )


async def shipped_ranges(
    sm: async_sessionmaker[AsyncSession], day: date = TODAY, *, skip: frozenset[str] = frozenset()
) -> None:
    """One harmless documentation prefix for every range source the feed job requires, fetched
    on ``day`` (the job fails closed unless every source has a fresh copy)."""
    from hub.feeds.filter import required_sources

    async with sm() as s:
        for i, name in enumerate(sorted(required_sources() - skip)):
            await s.execute(
                text(
                    "INSERT INTO feed_auto_ranges (source, prefix, fetched_day) VALUES (:s, :p, :d) "
                    "ON CONFLICT (source, prefix) DO UPDATE SET fetched_day = EXCLUDED.fetched_day"
                ),
                {"s": name, "p": f"2001:db8:fffe:{i}::/64", "d": day},
            )
        await s.commit()

"""Answer the dashboard's "Check now" (M24): wake the egress gate, then stamp the request.

The API inserts a row in ``egress_check_requests``; this loop polls pending rows every few
seconds. Ingest may only SELECT and UPDATE ``done_at`` on the table: it never deletes (a trigger
keeps the newest 100 rows).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

log = logging.getLogger(__name__)

POLL_S = 5.0
MAX_PER_POLL = 100


async def answer_pending(
    factory: async_sessionmaker[AsyncSession], wake: Callable[[], None]
) -> int:
    """Wake the gate once if any request is pending, then mark them done. Returns the count."""
    async with factory() as session:
        ids = (
            await session.scalars(
                text(
                    "SELECT id FROM egress_check_requests WHERE done_at IS NULL "
                    "ORDER BY id LIMIT :n"
                ),
                {"n": MAX_PER_POLL},
            )
        ).all()
    if not ids:
        return 0
    wake()  # before the stamp: a crash in between only repeats a check
    async with factory() as session, session.begin():
        await session.execute(
            text(
                "UPDATE egress_check_requests SET done_at = now() "
                "WHERE id = ANY(:ids) AND done_at IS NULL"
            ),
            {"ids": list(ids)},
        )
    return len(ids)


async def run(
    factory: async_sessionmaker[AsyncSession],
    wake: Callable[[], None],
    *,
    interval_s: float = POLL_S,
) -> None:
    while True:
        try:
            if await answer_pending(factory, wake):
                log.info("egress check requested from the dashboard")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("could not read egress check requests (%s)", type(exc).__name__)
        await asyncio.sleep(interval_s)

"""M24: ingest answers the dashboard's "Check now" with the ingest role's narrow grants."""

import asyncio
import os

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from ingest.check_requests import answer_pending, run

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]


async def test_pending_requests_wake_the_gate_and_are_stamped(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    async with engine.begin() as conn:
        await conn.execute(text("TRUNCATE egress_check_requests"))
        await conn.execute(
            text("INSERT INTO egress_check_requests (requested_by) VALUES ('a'), ('b')")
        )
    wakes: list[int] = []
    assert await answer_pending(factory, lambda: wakes.append(1)) == 2
    assert wakes == [1]  # one wake for the batch
    async with engine.connect() as conn:
        pending = await conn.scalar(
            text("SELECT count(*) FROM egress_check_requests WHERE done_at IS NULL")
        )
    assert pending == 0
    assert await answer_pending(factory, lambda: wakes.append(1)) == 0
    assert wakes == [1]


async def test_the_loop_survives_and_answers(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    async with engine.begin() as conn:
        await conn.execute(text("TRUNCATE egress_check_requests"))
    woken = asyncio.Event()
    task = asyncio.create_task(run(factory, woken.set, interval_s=0.05))
    try:
        await asyncio.sleep(0.1)
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO egress_check_requests (requested_by) VALUES ('a')")
            )
        await asyncio.wait_for(woken.wait(), 3)
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

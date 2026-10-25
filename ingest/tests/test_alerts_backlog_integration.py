# ruff: noqa: F811
"""Backlog bounds, history replay and error isolation of the alert worker (real database)."""

import os
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from .test_alerts_integration import (
    HOOK,
    FakeSender,
    add_campaign,
    add_channel,
    clean,  # noqa: F401 - fixture
    enable,
    outbox,
    worker,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

SENT_OLD = (
    "INSERT INTO alert_outbox (rule_kind, dedupe_key, channel_id, payload, state, attempts, "
    "sent_at) SELECT 'new_campaign', 'old:' || g, :c, '{}'::jsonb, 'sent', 1, "
    "now() - interval '2 hours' FROM generate_series(1, 100) g"
)


async def test_the_backlog_of_a_channel_is_bounded(
    clean: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    ch = await add_channel(clean)
    other = await add_channel(clean)
    await enable(clean, "new_campaign", [ch, other])
    w = worker(factory, FakeSender())
    await w._evaluate()
    for i in range(70):
        await add_campaign(clean, f"Flood #{i}", "severe")
    await w._evaluate()
    rows = await outbox(clean)
    for channel in (ch, other):
        mine = [r for r in rows if r["channel_id"] == channel]
        assert sum(r["state"] == "pending" for r in mine) == 50
        extra = [r for r in mine if r["state"] == "suppressed"]
        assert len(extra) == 20 and {r["error_code"] for r in extra} == {"backlog"}


async def test_a_daily_limit_drops_every_waiting_alert_at_once(
    clean: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    ch = await add_channel(clean)
    await enable(clean, "new_campaign", [ch])
    async with clean.begin() as conn:
        await conn.execute(text(SENT_OLD), {"c": ch})
    w = worker(factory, FakeSender())
    await w._evaluate()
    for i in range(40):
        await add_campaign(clean, f"Late #{i}", "severe")
    await w._evaluate()
    await w._deliver()
    rows = [r for r in await outbox(clean) if not r["dedupe_key"].startswith("old:")]
    assert len(rows) == 40
    assert {(r["state"], r["error_code"]) for r in rows} == {("suppressed", "daily_limit")}


async def test_one_noisy_channel_cannot_starve_another(
    clean: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    noisy = await add_channel(clean)
    quiet = await add_channel(clean)
    await enable(clean, "new_campaign", [noisy])
    async with clean.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO alert_outbox (rule_kind, dedupe_key, channel_id, payload) "
                "SELECT 'new_campaign', 'n:' || g, :c, jsonb_build_object('title', 't', "
                "'rule', 'new_campaign', 'severity', 'info') FROM generate_series(1, 50) g"
            ),
            {"c": noisy},
        )
        await conn.execute(
            text(
                "INSERT INTO alert_outbox (rule_kind, dedupe_key, channel_id, payload) VALUES "
                "('new_campaign', 'q:1', :c, jsonb_build_object('title', 'quiet', "
                "'rule', 'new_campaign', 'severity', 'info'))"
            ),
            {"c": quiet},
        )
    s = FakeSender()
    await worker(factory, s)._deliver()
    assert any(m.get("title") == "quiet" for _, _, m in s.sent)


async def test_a_rule_switched_off_and_on_does_not_replay_history(
    clean: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    ch = await add_channel(clean)
    await enable(clean, "new_campaign", [ch])
    s = FakeSender()
    w = worker(factory, s)
    await w._evaluate()
    await add_campaign(clean, "While on #1", "severe")
    await w._evaluate()
    async with clean.begin() as conn:
        await conn.execute(
            text("UPDATE alert_rules SET enabled = false WHERE kind = 'new_campaign'")
        )
    await add_campaign(clean, "While off #2", "severe")
    async with clean.begin() as conn:
        await conn.execute(
            text(
                "UPDATE alert_rules SET enabled = true, enabled_at = now() "
                "WHERE kind = 'new_campaign'"
            )
        )
    await w._evaluate()
    await add_campaign(clean, "After on #3", "severe")
    await w._evaluate()
    await w._deliver()
    titles = sorted(m["title"] for _, _, m in s.sent)
    assert titles == ["New campaign: After on #3", "New campaign: While on #1"]


class Exploding(FakeSender):
    """Raises something that is not a SendError, once for alerts and always for tests."""

    armed = True

    async def send(self, kind: str, target: str, message: dict[str, Any]) -> None:
        if message.get("title") == "Test message" or self.armed:
            self.armed = False
            raise RuntimeError("boom " + target)
        await super().send(kind, target, message)


async def test_an_unexpected_exception_does_not_block_other_alerts_or_tests(
    clean: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    ch = await add_channel(clean)
    other = await add_channel(clean)
    await enable(clean, "new_campaign", [ch, other])
    w = worker(factory, Exploding())
    await w._evaluate()
    await add_campaign(clean, "Boom #1", "severe")
    await w._evaluate()
    await w._deliver()
    rows = await outbox(clean)
    assert sorted(r["state"] for r in rows) == ["pending", "sent"]
    assert HOOK not in str(rows) and "boom" not in str(rows)
    async with clean.begin() as conn:
        await conn.execute(
            text("INSERT INTO alert_test_requests (channel_id, requested_by) VALUES (:c, 'a')"),
            {"c": ch},
        )
    await w._answer_tests()
    async with clean.connect() as conn:
        row = (await conn.execute(text("SELECT state, detail FROM alert_test_requests"))).one()
    assert tuple(row) == ("failed", "internal")

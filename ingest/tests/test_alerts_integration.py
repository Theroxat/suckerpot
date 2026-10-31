"""Alert rules, outbox, limits, tests and the weekly report against a real TimescaleDB."""

import os
from collections.abc import AsyncIterator
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from suckerpot_db.alert_targets import encrypt_target
from suckerpot_db.secretbox import SecretBox

from ingest.alerts.config import AlertSettings
from ingest.alerts.send import SendError
from ingest.alerts.worker import AlertWorker
from ingest.features import FeatureSettings
from ingest.reports.worker import ReportWorker

from .db_fixtures import reset_tables

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

BOX = SecretBox(bytes(range(32)))
HOOK = "https://discord.com/api/webhooks/123456789012345678/" + "T" * 30
SETTINGS = FeatureSettings(alerts_enabled=True, reports_enabled=True, site_timezone="UTC")


class FakeSender:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str, dict[str, Any]]] = []
        self.error: SendError | None = None
        self.smtp_password = ""

    async def send(self, kind: str, target: str, message: dict[str, Any]) -> None:
        if self.error is not None:
            raise self.error
        self.sent.append((kind, target, message))

    async def aclose(self) -> None:
        return None


RESET = (
    "TRUNCATE alert_outbox, alert_cursors, alert_test_requests, weekly_reports, "
    "alert_channels, watched_cves, campaigns RESTART IDENTITY CASCADE"
)


@pytest.fixture
async def clean(engine: AsyncEngine) -> AsyncIterator[AsyncEngine]:
    """Empty alert tables before and after, so other tests see the seeded, disabled rules."""

    async def reset() -> None:
        await reset_tables(
            engine,
            RESET,
            "UPDATE alert_rules SET enabled = false, channel_ids = '{}'",
            "TRUNCATE sessions",
        )

    await reset()
    yield engine
    await reset()


async def add_channel(engine: AsyncEngine, kind: str = "discord", mask: bool = True) -> int:
    async with engine.begin() as conn:
        cid = (
            await conn.execute(
                text(
                    "INSERT INTO alert_channels (kind, name, target_ciphertext, mask_ips, created_by) "
                    "VALUES (:k, 'c', decode(repeat('00', 40), 'hex'), :m, 'test') RETURNING id"
                ),
                {"k": kind, "m": mask},
            )
        ).scalar_one()
        blob = encrypt_target(BOX, cid, HOOK if kind != "email" else "analyst@example.org")
        await conn.execute(
            text("UPDATE alert_channels SET target_ciphertext = :b WHERE id = :i"),
            {"b": blob, "i": cid},
        )
    return int(cid)


async def enable(
    engine: AsyncEngine, rule: str, channels: list[int], severity: str = "info"
) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "UPDATE alert_rules SET enabled = true, channel_ids = :c, min_severity = :s "
                "WHERE kind = :k"
            ),
            {"c": channels, "s": severity, "k": rule},
        )


def worker(factory: async_sessionmaker[AsyncSession], sender: FakeSender) -> AlertWorker:
    return AlertWorker(
        SETTINGS,
        factory,
        BOX,
        AlertSettings(),
        sender=sender,  # type: ignore[arg-type]
    )


async def add_campaign(
    engine: AsyncEngine, name: str, severity: str = "warning", demo: bool = False
) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO campaigns (name, first_seen, last_seen, sessions, sources, severity, demo) "
                "VALUES (:n, now(), now(), 10, 3, :s, :d)"
            ),
            {"n": name, "s": severity, "d": demo},
        )


async def add_session(
    engine: AsyncEngine, sid: str, ip: str, tags: list[str], when: datetime | None = None
) -> None:
    ts = when or datetime.now(UTC)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, started_at, "
                "last_event_at, tags, country, org) VALUES (:i, 'ssh', CAST(:ip AS inet), 1, 22, "
                ":t, :t, :tags, 'NL', 'Example Hosting')"
            ),
            {"i": sid, "ip": ip, "t": ts, "tags": tags},
        )


async def outbox(engine: AsyncEngine) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text("SELECT * FROM alert_outbox ORDER BY id"))).mappings())


async def test_everything_is_off_until_enabled(
    clean: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    await add_channel(clean)
    s = FakeSender()
    w = worker(factory, s)
    await w._evaluate()
    await w._deliver()
    assert s.sent == [] and await outbox(clean) == []


async def test_a_new_campaign_alerts_once_and_history_is_not_replayed(
    clean: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    ch = await add_channel(clean)
    await add_campaign(clean, "Old campaign")
    await enable(clean, "new_campaign", [ch], "warning")
    s = FakeSender()
    w = worker(factory, s)
    await w._evaluate()  # first run: the cursor starts at the newest campaign
    await add_campaign(clean, "Mirai loader over Telnet #2", "severe")
    await add_campaign(clean, "Quiet scan #3", "info")  # below the minimum severity
    await add_campaign(clean, "Demo #4", "severe", demo=True)
    await w._evaluate()
    await w._evaluate()  # nothing new: no duplicate
    await w._deliver()
    await w._deliver()
    assert [m["title"] for _, _, m in s.sent] == ["New campaign: Mirai loader over Telnet #2"]
    assert s.sent[0][1] == HOOK
    rows = await outbox(clean)
    assert [r["state"] for r in rows] == ["sent"] and rows[0]["attempts"] == 1
    assert HOOK not in str(rows)


async def test_malware_drop_masks_the_address_per_channel_and_skips_demo_ranges(
    clean: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    masked = await add_channel(clean, mask=True)
    shown = await add_channel(clean, mask=False)
    await enable(clean, "malware_drop", [masked, shown])
    s = FakeSender()
    w = worker(factory, s)
    await w._evaluate()
    await add_session(clean, "real-1", "8.8.4.4", ["malware-drop", "mirai"])
    await add_session(clean, "demo-1", "203.0.113.9", ["malware-drop"])
    await add_session(clean, "plain-1", "8.8.8.8", ["recon"])
    await w._evaluate()
    await w._deliver()
    facts = sorted(str(dict(m["facts"])["Source"]) for _, _, m in s.sent)
    assert facts == ["8.8.x.x", "8[.]8[.]4[.]4"]
    assert all(m["severity"] == "severe" for _, _, m in s.sent)


async def test_watched_cve_alerts_once_per_day(
    clean: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    ch = await add_channel(clean)
    await enable(clean, "watched_cve_seen", [ch])
    async with clean.begin() as conn:
        await conn.execute(text("TRUNCATE cve"))
        await conn.execute(
            text(
                "INSERT INTO cve (cve_id, title, tags) VALUES "
                "('CVE-2026-0001', 'Example flaw', ARRAY['php2shell'])"
            )
        )
        await conn.execute(
            text("INSERT INTO watched_cves (cve_id, added_by) VALUES ('CVE-2026-0001', 't')")
        )
    s = FakeSender()
    w = worker(factory, s)
    await w._evaluate()
    await add_session(clean, "c-1", "8.8.4.4", ["php2shell"])
    await w._evaluate()
    await add_session(clean, "c-2", "8.8.8.8", ["php2shell"])
    await w._evaluate()  # same CVE, same day: deduplicated
    await w._deliver()
    assert len(s.sent) == 1 and "CVE-2026-0001" in s.sent[0][2]["title"]


async def test_a_burst_leaves_as_one_digest(
    clean: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    ch = await add_channel(clean)
    await enable(clean, "new_campaign", [ch])
    s = FakeSender()
    w = worker(factory, s)
    await w._evaluate()
    for i in range(14):
        await add_campaign(clean, f"Burst #{i}", "severe")
    await w._evaluate()
    await w._deliver()
    assert len(s.sent) == 1 and s.sent[0][2].get("digest") is True
    rows = await outbox(clean)
    assert sorted({r["state"] for r in rows}) == ["sent", "suppressed"]
    assert sum(r["state"] == "suppressed" and r["error_code"] == "digested" for r in rows) == 14


async def test_retryable_error_is_retried_then_given_up(
    clean: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    ch = await add_channel(clean)
    await enable(clean, "new_campaign", [ch])
    s = FakeSender()
    w = worker(factory, s)
    await w._evaluate()
    await add_campaign(clean, "Flaky #1", "severe")
    await w._evaluate()
    s.error = SendError("timeout", retryable=True)
    await w._deliver()
    assert [r["state"] for r in await outbox(clean)] == ["pending"]
    await w._deliver()
    await w._deliver()
    rows = await outbox(clean)
    assert rows[0]["state"] == "failed" and rows[0]["error_code"] == "timeout"
    assert rows[0]["attempts"] == 3


async def test_a_permanent_error_fails_at_once_and_a_disabled_channel_suppresses(
    clean: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    ch = await add_channel(clean)
    gone = await add_channel(clean)
    await enable(clean, "new_campaign", [ch, gone])
    s = FakeSender()
    w = worker(factory, s)
    await w._evaluate()
    await add_campaign(clean, "Perm #1", "severe")
    await w._evaluate()
    async with clean.begin() as conn:
        await conn.execute(
            text("UPDATE alert_channels SET enabled = false WHERE id = :i"), {"i": gone}
        )
    s.error = SendError("http_404")
    await w._deliver()
    states = {r["channel_id"]: (r["state"], r["error_code"]) for r in await outbox(clean)}
    assert states == {ch: ("failed", "http_404"), gone: ("suppressed", "channel_disabled")}


async def test_daily_limit_drops_the_rest(
    clean: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    ch = await add_channel(clean)
    await enable(clean, "new_campaign", [ch])
    async with clean.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO alert_outbox (rule_kind, dedupe_key, channel_id, payload, state, "
                "attempts, sent_at) SELECT 'new_campaign', 'old:' || g, :c, '{}'::jsonb, 'sent', "
                "1, now() - interval '2 hours' FROM generate_series(1, 100) g"
            ),
            {"c": ch},
        )
    s = FakeSender()
    w = worker(factory, s)
    await w._evaluate()
    await add_campaign(clean, "Late #1", "severe")
    await w._evaluate()
    await w._deliver()
    assert s.sent == []
    last = (await outbox(clean))[-1]
    assert last["state"] == "suppressed" and last["error_code"] == "daily_limit"


async def test_send_test_requests_are_answered(
    clean: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    ch = await add_channel(clean)
    async with clean.begin() as conn:
        await conn.execute(
            text("INSERT INTO alert_test_requests (channel_id, requested_by) VALUES (:c, 'a')"),
            {"c": ch},
        )
    s = FakeSender()
    w = worker(factory, s)
    await w._answer_tests()
    assert len(s.sent) == 1 and s.sent[0][2]["title"] == "Test message"
    async with clean.connect() as conn:
        row = (await conn.execute(text("SELECT state, detail FROM alert_test_requests"))).one()
    assert tuple(row) == ("done", "sent")
    # a refused target is reported, not retried
    s.error = SendError("private_address")
    async with clean.begin() as conn:
        await conn.execute(
            text("INSERT INTO alert_test_requests (channel_id, requested_by) VALUES (:c, 'a')"),
            {"c": ch},
        )
    await w._answer_tests()
    async with clean.connect() as conn:
        rows = (
            await conn.execute(text("SELECT state, detail FROM alert_test_requests ORDER BY id"))
        ).all()
    assert [tuple(r) for r in rows] == [("done", "sent"), ("refused", "private_address")]


async def test_wrong_encryption_key_fails_without_sending(
    clean: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    ch = await add_channel(clean)
    await enable(clean, "new_campaign", [ch])
    s = FakeSender()
    w = AlertWorker(SETTINGS, factory, SecretBox(bytes(range(1, 33))), AlertSettings(), sender=s)  # type: ignore[arg-type]
    await w._evaluate()
    await add_campaign(clean, "Key #1", "severe")
    await w._evaluate()
    await w._deliver()
    assert s.sent == []
    assert (await outbox(clean))[0]["error_code"] == "cannot_decrypt"


async def test_weekly_report_is_built_once_stored_escaped_and_queued(
    clean: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    ch = await add_channel(clean)
    await enable(clean, "weekly_report", [ch])
    monday = datetime(2026, 10, 19, 7, 0, tzinfo=UTC)
    in_week = monday - timedelta(days=5)
    await add_session(clean, "w-1", "8.8.4.4", ["recon"], in_week)
    await add_session(clean, "w-2", "8.8.8.8", ["malware-drop"], in_week)
    await add_session(clean, "demo", "203.0.113.5", ["recon"], in_week)  # not counted
    evil = '<script>alert("x")</script>'
    async with clean.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO campaigns (name, first_seen, last_seen, sessions, sources, severity) "
                "VALUES (:n, :t, :t, 4, 2, 'severe')"
            ),
            {"n": evil, "t": in_week},
        )
    rw = ReportWorker(SETTINGS, factory)
    assert await rw.build_due(datetime(2026, 10, 19, 5, 0, tzinfo=UTC)) is False  # before 06:00
    assert await rw.build_due(monday) is True
    assert await rw.build_due(monday + timedelta(hours=1)) is False  # built once
    async with clean.connect() as conn:
        row = (await conn.execute(text("SELECT * FROM weekly_reports"))).mappings().one()
    assert row["week_start"] == date(2026, 10, 12)
    assert row["summary"]["totals"]["sessions"] == 2
    assert "<script>alert" not in row["html"] and "&lt;script&gt;" in row["html"]
    assert "8.8." not in row["html"]
    queued = await outbox(clean)
    assert [(r["rule_kind"], r["dedupe_key"]) for r in queued] == [
        ("weekly_report", "week:2026-10-12")
    ]

"""The feed store against a real TimescaleDB: atomic swap, seen_here, wipe, grants (M30)."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from suckerpot_netproto.feeds import FeedEntry

from ingest.network.feed import FeedState, SqlFeedStore

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

NOW = datetime.now(UTC)


def entry(value: str, family: Any, **kw: Any) -> FeedEntry:
    base: dict[str, Any] = {
        "value": value,
        "family": family,
        "tier": "standard",
        "categories": ["c2"],
        "first_seen": "2026-10-28",
        "last_seen": "2026-10-30",
        "expires": "2026-11-29",
    }
    base.update(kw)
    return FeedEntry.model_validate(base)


def state(serial: int) -> FeedState:
    return FeedState(
        serial=serial,
        generated_at=NOW,
        valid_until=NOW + timedelta(days=2),
        key_id="0102030405060708",
        index_sha256="a" * 64,
        files={"index.json": {"sha256": "a" * 64, "etag": '"x"'}},
        last_fetch_at=NOW,
        last_ok_at=NOW,
    )


async def rows(engine: AsyncEngine) -> list[tuple[str, str]]:
    async with engine.connect() as conn:
        res = await conn.execute(
            text("SELECT list, value FROM network_feed_entries ORDER BY list, value")
        )
        return [(r.list, r.value) for r in res]


@pytest.fixture(autouse=True)
async def clean(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(text("TRUNCATE network_feed_entries, network_feed_state"))


async def test_apply_replaces_changed_lists_only_and_drops_unconfigured_ones(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    store = SqlFeedStore(factory)
    assert await store.state() is None
    await store.apply(
        state(1),
        {
            "outbound": [entry("203.0.113.50", 4, families=["mirai"], ports=[23, 2323])],
            "outbound-domains": [entry("dl.example.net", "dns")],
            "inbound": [entry("198.51.100.9", 4, categories=["brute-force"], services=["ssh"])],
        },
        {"outbound", "outbound-domains", "inbound"},
    )
    assert len(await rows(engine)) == 3
    await store.apply(
        state(2),
        {"outbound": [entry("203.0.113.51", 4)]},
        {"outbound", "outbound-domains"},  # inbound is no longer configured
    )
    assert await rows(engine) == [
        ("outbound", "203.0.113.51"),
        ("outbound-domains", "dl.example.net"),
    ]
    got = await store.state()
    assert got and got.serial == 2 and got.error_code is None
    assert got.files["index.json"]["etag"] == '"x"'
    async with engine.connect() as conn:
        dns = (
            await conn.execute(
                text("SELECT family FROM network_feed_entries WHERE list LIKE '%domains'")
            )
        ).scalar_one()
    assert dns is None


async def test_a_failed_swap_changes_nothing(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    store = SqlFeedStore(factory)
    await store.apply(state(1), {"outbound": [entry("203.0.113.50", 4)]}, {"outbound"})
    bad = state(2)
    bad.files = {"x": object()}  # type: ignore[dict-item]  # not JSON: the upsert fails last
    with pytest.raises(Exception):  # noqa: B017
        await store.apply(bad, {"outbound": [entry("203.0.113.99", 4)]}, {"outbound"})
    assert await rows(engine) == [("outbound", "203.0.113.50")]
    got = await store.state()
    assert got and got.serial == 1


async def test_record_error_keeps_the_data_and_touch_ok_clears_it(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    store = SqlFeedStore(factory)
    await store.apply(state(3), {"outbound": [entry("203.0.113.50", 4)]}, {"outbound"})
    await store.record_error("bad_signature", NOW)
    got = await store.state()
    assert got and got.error_code == "bad_signature" and got.serial == 3
    assert len(await rows(engine)) == 1
    await store.touch_ok(NOW)
    got = await store.state()
    assert got and got.error_code is None


async def test_seen_here_uses_local_data_only(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    store = SqlFeedStore(factory)
    await store.apply(
        state(1),
        {
            "inbound": [
                entry("198.51.100.9", 4, categories=["brute-force"]),  # real session
                entry("198.51.100.10", 4, categories=["brute-force"]),  # benign session
                entry("198.51.100.11", 4, categories=["brute-force"]),  # demo session
                entry("198.51.100.12", 4, categories=["brute-force"]),  # session too old
                entry("198.51.100.13", 4, categories=["brute-force"]),  # never seen
            ],
            "outbound-domains": [
                entry("dl.example.net", "dns"),  # indicator host
                entry("old.example.net", "dns"),  # indicator too old
                entry("c2.example.net", "dns"),  # sample link
                entry("none.example.net", "dns"),
            ],
        },
        {"inbound", "outbound-domains"},
    )
    async with engine.begin() as conn:
        for sid, ip, ago_h, benign in (
            ("s1", "198.51.100.9", 2, False),
            ("s2", "198.51.100.10", 2, True),
            ("s3", "198.51.100.11", 2, False),
            ("s4", "198.51.100.12", 24 * 40, False),
        ):
            t = NOW - timedelta(hours=ago_h)
            await conn.execute(
                text(
                    "INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, "
                    "started_at, last_event_at, benign) VALUES (:sid, 'ssh', CAST(:ip AS inet), "
                    "40000, 2222, :t, :t, :b)"
                ),
                {"sid": sid, "ip": ip, "t": t, "b": benign},
            )
        await conn.execute(
            text(
                "INSERT INTO events (ts, sensor, session_id, src_ip, src_port, dst_port, type, "
                "data) VALUES (:t, 'ssh', 's3', CAST('198.51.100.11' AS inet), 40000, 2222, "
                "'connect', CAST('{\"demo\": true}' AS jsonb))"
            ),
            {"t": NOW - timedelta(hours=2)},
        )
        await conn.execute(
            text(
                "INSERT INTO indicators (type, value, role, host, first_seen, last_seen) VALUES "
                "('url', 'http://dl.example.net/x.sh', 'download_host', 'dl.example.net', now(), now()), "
                "('url', 'http://old.example.net/x.sh', 'download_host', 'old.example.net', "
                "now() - interval '90 days', now() - interval '60 days')"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO samples (sha256, sha1, md5, size, first_seen, last_seen) "
                "VALUES (repeat('a', 64), repeat('b', 40), repeat('c', 32), 10, now(), now())"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO sample_links (sha256, kind, value, source, confidence) "
                "VALUES (repeat('a', 64), 'c2_domain', 'C2.example.net', 'static', 'high')"
            )
        )
    await store.recompute_seen_here(NOW)
    async with engine.connect() as conn:
        res = await conn.execute(
            text("SELECT value FROM network_feed_entries WHERE seen_here ORDER BY value")
        )
        assert [r.value for r in res] == ["198.51.100.9", "c2.example.net", "dl.example.net"]
    # Cleared when the local data ages out.
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM sessions WHERE session_id = 's1'"))
    await store.recompute_seen_here(NOW)
    async with engine.connect() as conn:
        n = (
            await conn.execute(
                text("SELECT count(*) FROM network_feed_entries WHERE seen_here AND family = 4")
            )
        ).scalar_one()
    assert n == 0


async def test_wipe_deletes_both_tables_and_reports_whether_anything_was_there(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    store = SqlFeedStore(factory)
    assert await store.wipe() is False
    await store.apply(state(1), {"outbound": [entry("203.0.113.50", 4)]}, {"outbound"})
    assert await store.wipe() is True
    assert await rows(engine) == [] and await store.state() is None

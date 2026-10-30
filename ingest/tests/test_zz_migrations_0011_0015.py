"""Migrations 0011 to 0015 go down one revision at a time and up again.

Named test_zz_* on purpose: re-running the migrations re-schedules the TimescaleDB jobs, which
must not fire while the retention tests drive them by hand. This file runs last. It covers the
``ADD COLUMN`` on the ``events`` hypertable while it holds compressed chunks.
"""

import os
import subprocess
import sys

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from .db_fixtures import DB_DIR, ROLE_ENV, _migrate

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

# revision -> (tables it creates, columns it adds as (table, column))
REVISIONS: dict[str, tuple[tuple[str, ...], tuple[tuple[str, str], ...]]] = {
    "0011": (
        (
            "attack_techniques",
            "technique_daily",
            "campaigns",
            "campaign_keys",
            "campaign_sessions",
        ),
        (
            ("events", "techniques"),
            ("sessions", "techniques"),
            ("sessions", "campaign_id"),
            ("sessions", "clustered_at"),
        ),
    ),
    "0012": (
        ("blocklist_entries", "blocklist_overrides", "feed_tokens", "inventory_services"),
        (),
    ),
    "0013": (("scripts", "script_sessions", "script_explanations", "llm_requests"), ()),
    "0014": (
        (
            "alert_channels",
            "alert_rules",
            "watched_cves",
            "alert_outbox",
            "alert_cursors",
            "weekly_reports",
            "alert_test_requests",
        ),
        (),
    ),
    "0015": ((), (("sessions", "benign"), ("sessions", "scanner_name"), ("events", "benign"))),
    "0016": (("indicator_contacts", "indicator_contact_checks"), ()),
    "0017": ((), ()),
}
ORDER = ["0011", "0012", "0013", "0014", "0015", "0016", "0017"]
PRUNE_JOBS = {
    "0011": "suckerpot_campaign_prune",
    "0013": "suckerpot_script_prune",
    "0014": "suckerpot_alert_prune",
}


def alembic(*args: str) -> None:
    subprocess.run(  # noqa: S603
        [sys.executable, "-m", "alembic", *args],
        cwd=DB_DIR,
        env={**os.environ, **ROLE_ENV},
        check=True,
        timeout=180,
    )


async def has_table(engine: AsyncEngine, name: str) -> bool:
    async with engine.connect() as conn:
        return bool(await conn.scalar(text("SELECT to_regclass(:n) IS NOT NULL"), {"n": name}))


async def has_column(engine: AsyncEngine, table: str, column: str) -> bool:
    async with engine.connect() as conn:
        return bool(
            await conn.scalar(
                text(
                    "SELECT count(*) = 1 FROM information_schema.columns "
                    "WHERE table_schema = 'public' AND table_name = :t AND column_name = :c"
                ),
                {"t": table, "c": column},
            )
        )


async def has_proc(engine: AsyncEngine, name: str) -> bool:
    async with engine.connect() as conn:
        return bool(
            await conn.scalar(
                text("SELECT to_regprocedure(:p) IS NOT NULL"), {"p": f"{name}(integer, jsonb)"}
            )
        )


async def current(engine: AsyncEngine) -> str:
    async with engine.connect() as conn:
        return str(await conn.scalar(text("SELECT version_num FROM alembic_version")))


async def assert_state(engine: AsyncEngine, applied: list[str]) -> None:
    for rev in ORDER:
        tables, columns = REVISIONS[rev]
        want = rev in applied
        for table in tables:
            assert await has_table(engine, table) == want, f"{table} at {applied}"
        for table, column in columns:
            assert await has_column(engine, table, column) == want, f"{table}.{column}"
        proc = PRUNE_JOBS.get(rev)
        if proc:
            assert await has_proc(engine, proc) == want, proc


async def test_each_revision_goes_down_and_up(engine: AsyncEngine) -> None:
    assert await current(engine) == "0017"
    await assert_state(engine, ORDER)

    # Back to 0010 one revision at a time; then raw events with a compressed chunk.
    for i in range(len(ORDER) - 1, -1, -1):
        alembic("downgrade", "0010" if i == 0 else ORDER[i - 1])
        await assert_state(engine, ORDER[:i])
    assert await current(engine) == "0010"

    async with engine.connect() as raw:
        auto = await raw.execution_options(isolation_level="AUTOCOMMIT")
        for day in (30, 20, 2):
            await auto.execute(
                text(
                    "INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, dst_port, "
                    "data, tags) VALUES (now() - make_interval(days => :d), 'ssh', :s, 'connect', "
                    "'198.51.100.7', 40000, 22, '{}', '{}')"
                ),
                {"d": day, "s": f"old-{day}"},
            )
        compressed = await auto.scalar(
            text(
                "SELECT count(*) FROM (SELECT compress_chunk(c, if_not_compressed => true) "
                "FROM show_chunks('events', older_than => INTERVAL '7 days') AS c) AS x"
            )
        )
        assert compressed and compressed >= 1

    # Up again, one revision at a time, with the compressed chunks in place.
    for i, rev in enumerate(ORDER):
        alembic("upgrade", rev)
        await assert_state(engine, ORDER[: i + 1])
    async with engine.connect() as conn:
        assert await conn.scalar(text("SELECT count(*) FROM events")) == 3
        # Old rows read back with NULL in the new nullable columns; a new row can set them.
        assert (
            await conn.scalar(
                text("SELECT count(*) FROM events WHERE techniques IS NULL AND benign IS NULL")
            )
            == 3
        )
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO events (ts, sensor, session_id, type, src_ip, src_port, dst_port, "
                "data, tags, techniques, benign) VALUES (now(), 'ssh', 'new', 'connect', "
                "'198.51.100.7', 40000, 22, '{}', '{}', '{T1110}', false)"
            )
        )
    async with engine.connect() as conn:
        assert await conn.scalar(text("SELECT count(*) FROM events")) == 4

    # Dropping the columns again with compressed chunks present.
    alembic("downgrade", "0010")
    assert not await has_column(engine, "events", "techniques")
    assert not await has_column(engine, "events", "benign")
    async with engine.connect() as conn:
        assert await conn.scalar(text("SELECT count(*) FROM events")) == 4

    _migrate()  # upgrade head + roles + retention again
    assert await current(engine) == "0017"
    await assert_state(engine, ORDER)
    async with engine.connect() as conn:
        jobs = {
            r[0]
            for r in await conn.execute(text("SELECT proc_name FROM timescaledb_information.jobs"))
        }
    assert set(PRUNE_JOBS.values()) <= jobs

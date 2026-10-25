"""Research scanners against a real TimescaleDB: the writer labels, and never hides an attack."""

import os
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from ingest.enrichment import GeoResolver
from ingest.enrichment.enricher import Enricher
from ingest.scanners import load_scanners
from ingest.tagging import load_rules
from ingest.writer import write_batch

from .helpers import make_event

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
UA = {"user_agent": "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)"}


async def rows(engine: AsyncEngine, sql: str) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(sql))).all())


async def test_research_scanner_is_benign_until_it_does_more(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], tmp_path: Path
) -> None:
    enricher = Enricher(
        GeoResolver(tmp_path, fake_for_private=True),
        load_rules(RULES_DIR),
        scanners=load_scanners(RULES_DIR),
    )
    ip = "203.0.113.60"
    await write_batch(
        factory,
        [
            make_event("connect", sid="b1", ip=ip, sensor="web"),
            make_event("http_request", sid="b1", offset_s=1, ip=ip, sensor="web", data=UA),
            make_event(
                "http_request",
                sid="n1",
                ip="203.0.113.61",
                sensor="web",
                data={"user_agent": "curl/8"},
            ),
        ],
        enricher,
    )
    got = {
        r.session_id: r
        for r in await rows(engine, "SELECT session_id, benign, scanner_name FROM sessions")
    }
    assert (got["b1"].benign, got["b1"].scanner_name) == (True, "Censys")
    assert (got["n1"].benign, got["n1"].scanner_name) == (False, None)
    flags = {
        r.session_id: r.benign for r in await rows(engine, "SELECT session_id, benign FROM events")
    }
    assert flags == {"b1": True, "n1": False}

    # A forged user-agent cannot hide an attack: the first command clears the label for good.
    await write_batch(
        factory,
        [make_event("command", sid="b1", offset_s=5, ip=ip, data={"input": "uname -a"})],
        enricher,
    )
    (s,) = await rows(engine, "SELECT benign, scanner_name FROM sessions WHERE session_id = 'b1'")
    assert s.benign is False and s.scanner_name == "Censys"
    await write_batch(
        factory,
        [make_event("http_request", sid="b1", offset_s=9, ip=ip, sensor="web", data=UA)],
        enricher,
    )
    (s,) = await rows(engine, "SELECT benign FROM sessions WHERE session_id = 'b1'")
    assert s.benign is False

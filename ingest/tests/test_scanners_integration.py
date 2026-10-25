"""Research scanners against a real TimescaleDB: the writer labels, and never hides an attack."""

import os
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from ingest.enrichment import GeoResolver
from ingest.enrichment.enricher import Enricher
from ingest.scanners import Scanner, ScannerSet
from ingest.tagging import load_rules
from ingest.writer import write_batch

from .helpers import make_event

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
UA = {"user_agent": "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)"}
IP = "203.0.113.60"


def enricher_for(tmp_path: Path, scanner_ips: tuple[str, ...] = (IP,)) -> Enricher:
    """An enricher whose scanner list matches the (fake) network of ``scanner_ips``."""
    geo = GeoResolver(tmp_path, fake_for_private=True)
    asns = frozenset(a for ip in scanner_ips if (a := geo.lookup(ip).asn) is not None)
    scanners = ScannerSet((Scanner("Censys", asns=asns),)) if asns else ScannerSet()
    return Enricher(geo, load_rules(RULES_DIR), scanners=scanners)


async def rows(engine: AsyncEngine, sql: str, **params: Any) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(sql), params)).all())


async def flags(engine: AsyncEngine, sid: str) -> tuple[bool, list[bool | None]]:
    (s,) = await rows(engine, "SELECT benign FROM sessions WHERE session_id = :sid", sid=sid)
    ev = await rows(
        engine, "SELECT benign FROM events WHERE session_id = :sid ORDER BY ts", sid=sid
    )
    return s.benign, [e.benign for e in ev]


def web(kind: str, sid: str, offset: float, data: dict[str, Any] | None = None) -> Any:
    return make_event(kind, sid=sid, offset_s=offset, ip=IP, sensor="web", data=data or {})


async def test_a_network_match_that_only_looks_around_is_benign(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], tmp_path: Path
) -> None:
    await write_batch(
        factory,
        [
            web("connect", "b1", 0),
            web("http_request", "b1", 1, {"method": "GET", "path": "/", **UA}),
        ],
        enricher_for(tmp_path),
    )
    assert await flags(engine, "b1") == (True, [True, True])
    (s,) = await rows(engine, "SELECT scanner_name FROM sessions WHERE session_id = 'b1'")
    assert s.scanner_name == "Censys"


async def test_a_user_agent_alone_never_makes_a_session_benign(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], tmp_path: Path
) -> None:
    enricher = enricher_for(tmp_path, scanner_ips=())  # no network matches
    await write_batch(
        factory, [web("http_request", "u1", 0, {"method": "GET", "path": "/", **UA})], enricher
    )
    assert await flags(engine, "u1") == (False, [False])


ATTACKS: dict[str, dict[str, Any]] = {
    "phpunit": {
        "method": "POST",
        "path": "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "body_preview": "<?php system('id');",
        **UA,
    },
    "shellshock": {
        "method": "GET",
        "path": "/cgi-bin/status",
        "flags": ["shellshock"],
        **UA,
    },
    "wp-login": {
        "method": "POST",
        "path": "/wp-login.php",
        "body_preview": "log=admin&pwd=x",
        **UA,
    },
}


@pytest.mark.parametrize("attack", sorted(ATTACKS))
async def test_a_scanner_that_attacks_is_not_benign_anywhere(
    attack: str, engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], tmp_path: Path
) -> None:
    await write_batch(
        factory,
        [web("connect", "a1", 0), web("http_request", "a1", 1, ATTACKS[attack])],
        enricher_for(tmp_path),
    )
    assert await flags(engine, "a1") == (False, [False, False])


async def test_earlier_same_and_later_batches(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], tmp_path: Path
) -> None:
    enricher = enricher_for(tmp_path)
    get = {"method": "GET", "path": "/", **UA}
    # Earlier batch: harmless, flagged benign.
    await write_batch(
        factory, [web("connect", "m1", 0), web("http_request", "m1", 1, get)], enricher
    )
    assert await flags(engine, "m1") == (True, [True, True])
    # Later batch: the attack arrives. The session and its earlier events lose the flag.
    await write_batch(
        factory, [web("http_request", "m1", 5, {"method": "POST", "path": "/x", **UA})], enricher
    )
    assert await flags(engine, "m1") == (False, [False, False, False])
    # A still later harmless batch never flags anything again.
    await write_batch(factory, [web("http_request", "m1", 9, get)], enricher)
    assert await flags(engine, "m1") == (False, [False, False, False, False])
    # Same batch: harmless and attack together.
    await write_batch(
        factory,
        [web("http_request", "m2", 0, get), web("http_request", "m2", 1, {"method": "POST", **UA})],
        enricher,
    )
    assert await flags(engine, "m2") == (False, [False, False])


async def test_a_login_attempt_demotes(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], tmp_path: Path
) -> None:
    enricher = enricher_for(tmp_path)
    await write_batch(factory, [make_event("connect", sid="s1", ip=IP)], enricher)
    assert (await flags(engine, "s1"))[0] is True
    await write_batch(
        factory,
        [make_event("login_attempt", sid="s1", offset_s=2, ip=IP, data={"success": False})],
        enricher,
    )
    assert await flags(engine, "s1") == (False, [False, False])


async def test_retract_benign_refuses_a_huge_list(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    from sqlalchemy.exc import DBAPIError

    async with factory() as session:
        with pytest.raises(DBAPIError):
            await session.execute(
                text("SELECT retract_benign(CAST(:ids AS text[]))"),
                {"ids": [f"s{i}" for i in range(1001)]},
            )

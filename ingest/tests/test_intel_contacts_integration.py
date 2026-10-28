"""Contacted addresses against a real TimescaleDB: candidates, caching, bounds, grants, scoring."""

import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from ingest.blocklist import BlocklistWorker
from ingest.enrichment.contacts import (
    CONTACTS_PER_SOURCE_PER_DAY,
    PER_SOURCE,
    Contact,
    Source,
    candidates,
    cleanup_stored,
    store,
)
from ingest.features import FeatureSettings
from ingest.indicators import IndicatorSettings

from .db_fixtures import ROLE_ENV

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

NOW = datetime.now(UTC)
H_KNOWN = "a1" * 32
H_UNKNOWN = "b2" * 32
H_DEMO = "c3" * 32
H_NOT_CHECKED = "d4" * 32
SOURCES: tuple[Source, ...] = ("virustotal", "threatfox")


async def seed(engine: AsyncEngine) -> dict[str, int]:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE blocklist_entries, indicator_intel, indicator_sessions, "
                "indicator_contacts, indicator_contact_checks, indicators"
            )
        )
        ids: dict[str, int] = {}
        for value, demo, known, tags in [
            (H_KNOWN, False, True, []),
            (H_UNKNOWN, False, False, []),
            (H_DEMO, True, True, []),
            (H_NOT_CHECKED, False, True, ["not-checked"]),
        ]:
            ids[value] = int(
                await conn.scalar(
                    text(
                        "INSERT INTO indicators (type, value, role, first_seen, last_seen, "
                        "sightings, sensors, trusted, demo) VALUES ('hash', :v, 'hash', now(), "
                        "now(), 1, '{ssh}', true, :d) RETURNING id"
                    ),
                    {"v": value, "d": demo},
                )
                or 0
            )
            await conn.execute(
                text(
                    "INSERT INTO indicator_intel (indicator_id, source, known, family, tags) "
                    "VALUES (:i, 'virustotal', :k, 'mirai', :t)"
                ),
                {"i": ids[value], "k": known, "t": tags},
            )
    return ids


def contact(addr: str, source: str = "virustotal", **kw: object) -> Contact:
    base: dict[str, object] = {
        "address": addr, "kind": "ip", "port": None, "source": source,
        "confidence": "high" if source == "threatfox" else "medium",
    }  # fmt: skip
    return Contact(**{**base, **kw})  # type: ignore[arg-type]


async def rows(engine: AsyncEngine, sql: str) -> list[tuple[object, ...]]:
    async with engine.connect() as conn:
        return [tuple(r) for r in (await conn.execute(text(sql))).all()]


async def test_only_known_real_hashes_without_a_fresh_check_are_candidates(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    ids = await seed(engine)
    got = await candidates(factory, SOURCES, 10)
    assert [(c.value, c.missing) for c in got] == [(H_KNOWN, SOURCES)]

    await store(factory, ids[H_KNOWN], "virustotal", [])  # cached: nothing found
    got = await candidates(factory, SOURCES, 10)
    assert [(c.value, c.missing) for c in got] == [(H_KNOWN, ("threatfox",))]
    assert await candidates(factory, ("virustotal",), 10) == []
    assert await candidates(factory, (), 10) == []

    await store(factory, ids[H_KNOWN], "threatfox", [])
    assert await candidates(factory, SOURCES, 10) == []

    async with engine.begin() as conn:  # a day later the answer is stale again
        await conn.execute(
            text("UPDATE indicator_contact_checks SET checked_at = now() - interval '25 hours'")
        )
    assert [c.value for c in await candidates(factory, SOURCES, 10)] == [H_KNOWN]


async def link(engine: AsyncEngine, hash_id: int, ips: list[str], tag: str) -> None:
    async with engine.begin() as conn:
        for n, ip in enumerate(ips):
            await conn.execute(
                text(
                    "INSERT INTO indicator_sessions VALUES (:i, :s, CAST(:ip AS inet), 'ssh', "
                    "now())"
                ),
                {"i": hash_id, "s": f"{tag}-{n}", "ip": ip},
            )


async def test_a_planted_hash_needs_three_independent_networks(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    ids = await seed(engine)
    async with engine.begin() as conn:  # same hash, but typed in a command: not sensor-computed
        await conn.execute(text("UPDATE indicators SET trusted = false"))
    assert await candidates(factory, SOURCES, 10) == []
    h = ids[H_KNOWN]
    # Many addresses in two /24 networks are still two sources.
    await link(engine, h, ["203.0.113.1", "203.0.113.2", "198.51.100.1"], "a")
    assert await candidates(factory, SOURCES, 10) == []
    await link(engine, h, ["192.0.2.1"], "b")
    assert [c.value for c in await candidates(factory, SOURCES, 10)] == [H_KNOWN]


async def test_one_source_address_cannot_spend_the_contact_budget(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    ids = await seed(engine)
    await link(engine, ids[H_KNOWN], ["203.0.113.1"], "one")
    assert [c.value for c in await candidates(factory, SOURCES, 10)] == [H_KNOWN]
    async with engine.begin() as conn:
        for n in range(CONTACTS_PER_SOURCE_PER_DAY):
            other = int(
                await conn.scalar(
                    text(
                        "INSERT INTO indicators (type, value, role, first_seen, last_seen, "
                        "sensors, trusted) VALUES ('hash', :v, 'hash', now(), now(), '{ssh}', "
                        "true) RETURNING id"
                    ),
                    {"v": f"{n:02x}" * 32},
                )
                or 0
            )
            await conn.execute(
                text(
                    "INSERT INTO indicator_sessions VALUES (:i, :s, CAST('203.0.113.1' AS inet), "
                    "'ssh', now())"
                ),
                {"i": other, "s": f"o-{n}"},
            )
            await conn.execute(
                text("INSERT INTO indicator_contact_checks (indicator_id, source) VALUES (:i, "
                     "'virustotal')"),
                {"i": other},
            )  # fmt: skip
    assert await candidates(factory, SOURCES, 10) == []


async def test_store_replaces_one_source_keeps_first_seen_and_is_bounded(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    ids = await seed(engine)
    h = ids[H_KNOWN]
    t0 = NOW - timedelta(days=3)
    await store(factory, h, "virustotal", [contact("203.0.113.5"), contact("203.0.113.6")])
    await store(factory, h, "threatfox", [contact("203.0.113.5", "threatfox", port=4444,
                                                  family="Mirai", provider_score=75,
                                                  first_seen=t0)])  # fmt: skip
    assert await rows(
        engine, "SELECT address, source, confidence, port FROM indicator_contacts ORDER BY 1, 2"
    ) == [
        ("203.0.113.5", "threatfox", "high", 4444),
        ("203.0.113.5", "virustotal", "medium", None),
        ("203.0.113.6", "virustotal", "medium", None),
    ]
    (first,) = await rows(
        engine, "SELECT first_seen FROM indicator_contacts WHERE source = 'threatfox'"
    )
    assert first[0] == t0

    # A second pass: 203.0.113.6 is gone from the provider, 203.0.113.7 is new.
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE indicator_contacts SET first_seen = now() - interval '2 days'")
        )
    await store(factory, h, "virustotal", [contact("203.0.113.5"), contact("203.0.113.7")])
    got = await rows(engine, "SELECT address, source FROM indicator_contacts ORDER BY 1, 2")
    assert got == [
        ("203.0.113.5", "threatfox"),
        ("203.0.113.5", "virustotal"),
        ("203.0.113.7", "virustotal"),
    ]
    (old,) = await rows(
        engine,
        "SELECT first_seen < now() - interval '1 day' FROM indicator_contacts "
        "WHERE address = '203.0.113.5' AND source = 'virustotal'",
    )
    assert old[0] is True  # an address seen before keeps its first_seen

    many = [contact(f"c{i}.example.net", kind="domain") for i in range(100)]
    await store(factory, h, "virustotal", many)
    (n,) = await rows(engine, "SELECT count(*) FROM indicator_contacts WHERE source = 'virustotal'")
    assert n[0] == PER_SOURCE


async def test_contacts_go_with_their_hash(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    ids = await seed(engine)
    await store(factory, ids[H_KNOWN], "virustotal", [contact("203.0.113.5")])
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM indicators"))
    assert await rows(engine, "SELECT 1 FROM indicator_contacts") == []
    assert await rows(engine, "SELECT 1 FROM indicator_contact_checks") == []


async def test_grants(engine: AsyncEngine) -> None:
    async def priv(role: str, table: str, p: str) -> bool:
        async with engine.connect() as conn:
            return bool(
                await conn.scalar(
                    text("SELECT has_table_privilege(:r, :t, :p)"), {"r": role, "t": table, "p": p}
                )
            )

    ing, api = ROLE_ENV["POSTGRES_INGEST_USER"], ROLE_ENV["POSTGRES_API_USER"]
    for table in ("indicator_contacts", "indicator_contact_checks"):
        assert all([await priv(ing, table, p) for p in ("SELECT", "INSERT", "UPDATE", "DELETE")])
        assert not await priv(ing, table, "TRUNCATE")
        assert not any([await priv(api, table, p) for p in ("INSERT", "UPDATE", "DELETE")])
    assert await priv(api, "indicator_contacts", "SELECT")
    assert not await priv(api, "indicator_contact_checks", "SELECT")  # an ingest-only cache


async def test_the_blocklist_lists_probable_c2_addresses(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    ids = await seed(engine)
    h = ids[H_KNOWN]
    await store(factory, h, "threatfox", [contact("203.0.113.5", "threatfox", family="Mirai")])
    await store(
        factory,
        h,
        "virustotal",
        [contact("198.51.100.7"), contact("c2.example.net", kind="domain"), contact("203.0.113.5")],
    )
    async with engine.begin() as conn:
        # An attacker that also happens to be a medium-confidence C2 address.
        await conn.execute(
            text(
                "INSERT INTO sessions (session_id, sensor, src_ip, src_port, dst_port, started_at, "
                "last_event_at, commands, downloads, tags) VALUES ('s1', 'ssh', "
                "CAST('198.51.100.7' AS inet), 40000, 2222, now(), now(), 3, 1, '{malware-drop}')"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO indicator_sessions VALUES (:i, 's1', CAST('198.51.100.7' AS inet), "
                "'ssh', now())"
            ),
            {"i": h},
        )
        # A demo hash's contacts are never listed.
        await conn.execute(
            text(
                "INSERT INTO indicator_contacts (hash_indicator_id, address, kind, source, "
                "confidence) VALUES (:i, '192.0.2.99', 'ip', 'threatfox', 'high')"
            ),
            {"i": ids[H_DEMO]},
        )
    async with engine.begin() as conn:  # a planted (not sensor-computed) hash with one source
        planted = int(
            await conn.scalar(
                text(
                    "INSERT INTO indicators (type, value, role, first_seen, last_seen, sensors, "
                    "trusted) VALUES ('hash', :v, 'hash', now(), now(), '{ssh}', false) "
                    "RETURNING id"
                ),
                {"v": "e5" * 32},
            )
            or 0
        )
        await conn.execute(
            text(
                "INSERT INTO indicator_contacts (hash_indicator_id, address, kind, source, "
                "confidence) VALUES (:i, '203.0.113.88', 'ip', 'threatfox', 'high')"
            ),
            {"i": planted},
        )
    w = BlocklistWorker(FeatureSettings(blocklist_enabled=True), factory)
    await w.run_once()
    async with engine.connect() as conn:
        found = (
            await conn.execute(text("SELECT kind, value, score, reasons FROM blocklist_entries"))
        ).all()
    got: dict[tuple[str, str], tuple[int, list[str]]] = {
        (r.kind, r.value): (r.score, list(r.reasons)) for r in found
    }
    high = got[("ip", "203.0.113.5")]
    assert high[0] == 75 and high[1] == ["probable-c2"]
    domain = got[("domain", "c2.example.net")]
    assert domain[0] == 40 and domain[1] == ["probable-c2"]
    merged = got[("ip", "198.51.100.7")]
    assert "probable-c2" in merged[1] and "dropped-malware" in merged[1]
    assert ("ip", "192.0.2.99") not in got
    assert got[("ip", "203.0.113.88")][0] == 45  # unconfirmed: capped even for ThreatFox


async def test_stored_rows_that_fail_todays_filters_are_removed(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    ids = await seed(engine)
    h = ids[H_KNOWN]
    keep = IndicatorSettings(keep_documentation=True)
    await store(
        factory,
        h,
        "virustotal",
        [
            contact("203.0.113.5"),  # in a shared network: goes
            contact("203.0.113.6"),  # stays
            contact("edgedl.me.gvt1.com", kind="domain"),  # CDN name: goes
            contact("c9.example.net", kind="domain"),  # stays
        ],
    )
    # ThreatFox rows are never dropped for their network, only if the address itself is invalid.
    await store(factory, h, "threatfox", [contact("203.0.113.5", "threatfox")])
    removed = await cleanup_stored(factory, keep, lambda ip: ip == "203.0.113.5")
    assert removed == 2
    got = await rows(engine, "SELECT address, source FROM indicator_contacts ORDER BY 1, 2")
    assert got == [
        ("203.0.113.5", "threatfox"),
        ("203.0.113.6", "virustotal"),
        ("c9.example.net", "virustotal"),
    ]
    assert await cleanup_stored(factory, keep, None) == 0  # idempotent

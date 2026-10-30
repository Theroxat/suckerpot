"""CVE watch against a real TimescaleDB: merge across sources, state, quota, grants."""

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from ingest.cve.relevance import load_relevance
from ingest.cve.watch import CveWatch
from ingest.enrichment import EnrichmentSettings

from .db_fixtures import ROLE_ENV
from .test_cve_sources import KEV, NVD

RULES = Path(__file__).resolve().parents[1] / "rules"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

GITHUB = [
    {
        "ghsa_id": "GHSA-cfgh-2345-wxvq",
        "cve_id": "CVE-2026-0001",
        "summary": "GitHub summary",
        "severity": "high",
        "cvss": {"score": 7.0},
        "references": ["https://example.org/ghsa"],
    }
]


def handler(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    if host == "www.cisa.gov":
        return httpx.Response(200, content=json.dumps(KEV))
    if host == "services.nvd.nist.gov":
        doc = {**NVD, "totalResults": 1}
        return httpx.Response(200, content=json.dumps(doc))
    return httpx.Response(200, content=json.dumps(GITHUB))


def watch(factory: async_sessionmaker[AsyncSession], **env: str) -> CveWatch:
    async def no_sleep(_: float) -> None:
        return None

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return CveWatch(factory, EnrichmentSettings.from_env(env), client, sleep=no_sleep)


async def rows(engine: AsyncEngine) -> dict[str, Any]:
    async with engine.connect() as conn:
        res = await conn.execute(text("SELECT * FROM cve"))
        return {r.cve_id: r for r in res}


async def test_run_once_merges_sources_and_is_idempotent(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    w = watch(factory)
    assert await w.run_once() >= 2
    got = await rows(engine)
    one = got["CVE-2026-0001"]
    assert one.in_kev and one.kev_ransomware and one.vendor == "Example"
    assert one.title == "Example Widget RCE"  # KEV wins; GitHub only fills gaps
    assert one.cvss_score == 7.0 and one.ghsa_ids == ["GHSA-cfgh-2345-wxvq"]
    assert sorted(one.sources) == ["github", "kev"]
    two = got["CVE-2026-0002"]
    assert not two.in_kev and float(two.cvss_score) == 9.2 and two.sources == ["nvd"]

    # Fresh state: nothing is due, so a second pass does not fetch again.
    before = (await rows(engine))["CVE-2026-0001"].updated_at
    assert await w.run_once() == 0
    assert (await rows(engine))["CVE-2026-0001"].updated_at == before
    # A forced re-sync upserts the same rows, it does not duplicate them.
    await w.sync_source("kev")
    assert len(await rows(engine)) == len(got)

    status = await w.status()
    assert status["kev"]["last_success_at"] and status["kev"]["items_last_run"] == 1
    await w.aclose()


async def test_failure_is_recorded_and_backs_off(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    w = CveWatch(factory, EnrichmentSettings.from_env({}), client)
    assert await w.run_once() == 0
    assert w.last_error == {"kev": "error", "nvd": "error", "github": "error"}
    async with engine.connect() as conn:
        n = await conn.scalar(text("SELECT count(*) FROM cve_sync_state WHERE last_error='error'"))
    assert n == 3
    calls = 0

    def counting(r: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    w.client = httpx.AsyncClient(transport=httpx.MockTransport(counting))
    await w.run_once()
    assert calls == 0  # backing off for an hour
    await w.aclose()


async def test_quota_is_enforced(factory: async_sessionmaker[AsyncSession]) -> None:
    w = watch(factory, CVE_NVD_DAILY_QUOTA="0")
    assert await w.sync_source("nvd") == 0
    assert w.last_error["nvd"] == "quota_exhausted"
    await w.aclose()


async def test_key_test_needs_a_key_and_uses_header(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    seen: list[httpx.Request] = []

    def spy(r: httpx.Request) -> httpx.Response:
        seen.append(r)
        return httpx.Response(200, content=json.dumps({"vulnerabilities": []}))

    w = CveWatch(
        factory,
        EnrichmentSettings.from_env({"NVD_API_KEY": "n" * 24}),
        httpx.AsyncClient(transport=httpx.MockTransport(spy)),
    )
    assert (await w.run_key_test("github"))["error"] == "no_key"
    assert (await w.run_key_test("nvd"))["ok"] is True
    assert seen[0].headers["apiKey"] == "n" * 24
    await w.aclose()


async def test_relevance_tags_and_retention(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    w = watch(factory)
    w.relevance = load_relevance(RULES)
    await w.run_once()
    got = await rows(engine)
    one = got["CVE-2026-0001"]  # KEV vendor "Example": no service matches
    assert one.relevance == "none" and one.rank_score > 0
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO cve (cve_id, vendor, product, published_at, in_kev) VALUES "
                "('CVE-2099-0100', 'PHP Group', 'PHP', now(), false), "
                "('CVE-2099-0101', 'Nobody', 'Thing', now() - interval '200 days', false), "
                "('CVE-2099-0102', 'Nobody', 'Thing', now() - interval '200 days', true), "
                "('CVE-2026-109618', 'PHP Group', 'PHP', now() - interval '200 days', false)"
            )
        )
    await w.maintenance()
    got = await rows(engine)
    assert got["CVE-2099-0100"].relevance == "high"
    assert got["CVE-2099-0100"].matched_services == ["web-php"]
    assert got["CVE-2026-109618"].tags == ["php2shell"]
    assert "CVE-2099-0101" not in got  # old, not KEV, not relevant: pruned
    assert "CVE-2099-0102" in got  # KEV is kept
    assert "CVE-2026-109618" in got  # old but relevant is kept
    assert await w.recompute() == 0  # idempotent
    await w.aclose()


async def test_ingest_role_grants(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    api = ROLE_ENV["POSTGRES_API_USER"]
    async with engine.connect() as conn:
        assert await conn.scalar(
            text("SELECT has_table_privilege(:r, 'cve', 'SELECT')"), {"r": api}
        )
        for p in ("INSERT", "UPDATE", "DELETE"):
            assert not await conn.scalar(
                text("SELECT has_table_privilege(:r, 'cve', :p)"), {"r": api, "p": p}
            )
    async with factory() as session:
        with pytest.raises(DBAPIError):
            await session.execute(text("TRUNCATE cve"))


async def test_a_bad_row_is_skipped_not_fatal(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    from ingest.cve.sources import Batch, CveRecord

    w = watch(factory)
    good = CveRecord(cve_id="CVE-2099-0200", title="ok")
    bad = CveRecord(cve_id="CVE-2099-0201", cvss_score=99.0)  # violates the table's CHECK
    batch = Batch([good, bad, CveRecord(cve_id="CVE-2099-0202")])
    assert await w.store("nvd", batch) == 2
    assert batch.skipped == 1
    assert set(await rows(engine)) == {"CVE-2099-0200", "CVE-2099-0202"}
    await w.aclose()


async def test_unexpected_failures_are_recorded_in_the_sync_state(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    w = watch(factory)

    async def boom(source: str, since: Any) -> Any:
        raise RecursionError

    monkeypatch.setattr(w, "_fetch", boom)
    assert await w.sync_source("kev") == 0
    async with engine.connect() as conn:
        err = await conn.scalar(text("SELECT last_error FROM cve_sync_state WHERE source = 'kev'"))
    assert err == "error"
    await w.aclose()


async def test_partial_nvd_fetch_moves_the_cursor_only_as_far_as_it_got(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    w = watch(factory, CVE_NVD_DAILY_QUOTA="3")
    assert await w.sync_source("nvd") > 0
    async with engine.connect() as conn:
        last = await conn.scalar(
            text("SELECT last_success_at FROM cve_sync_state WHERE source='nvd'")
        )
    assert last is not None
    assert datetime.now(UTC) - last > timedelta(days=50)  # resumes the next cycle, not tomorrow
    await w.aclose()


async def test_a_shallow_history_is_rewound_once(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    w = watch(factory)
    await w.sync_source("nvd")
    async with engine.begin() as conn:
        await conn.execute(text("UPDATE cve SET published_at = now() - interval '5 days'"))
        await conn.execute(text("UPDATE cve_sync_state SET last_success_at = now()"))
    await w.rewind_shallow_history()
    async with engine.connect() as conn:
        last = await conn.scalar(
            text("SELECT last_success_at FROM cve_sync_state WHERE source='nvd'")
        )
    assert last is not None and datetime.now(UTC) - last > timedelta(days=55)
    await w.aclose()


async def test_watched_cves_missing_from_the_table_are_fetched_by_id_once_a_day(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO watched_cves (cve_id, added_by) VALUES ('CVE-2024-10441', 'test')")
        )
    w = watch(factory)
    assert await w.sync_watched() >= 0
    assert await w.sync_watched() == 0  # not asked again within 24 h, found or not
    await w.aclose()


async def test_unresolvable_watched_ids_do_not_starve_the_ones_behind_them(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    ids = [f"CVE-2099-{i:04d}" for i in range(1, 13)]
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM watched_cves"))
        for n, cve_id in enumerate(ids):
            await conn.execute(
                text(
                    "INSERT INTO watched_cves (cve_id, added_by, added_at) "
                    "VALUES (:i, 'test', now() + make_interval(secs => :n))"
                ),
                {"i": cve_id, "n": n},
            )
    asked: list[str] = []

    def empty(request: httpx.Request) -> httpx.Response:
        asked.append(request.url.params["cveId"])
        return httpx.Response(200, content=json.dumps({"totalResults": 0, "vulnerabilities": []}))

    async def no_sleep(_: float) -> None:
        return None

    client = httpx.AsyncClient(transport=httpx.MockTransport(empty))
    w = CveWatch(factory, EnrichmentSettings.from_env({}), client, sleep=no_sleep)
    await w.sync_watched()
    assert asked == ids[:10]
    await w.sync_watched()  # the first ten are not retried within 24 h
    assert asked[10:] == ids[10:]
    await w.aclose()

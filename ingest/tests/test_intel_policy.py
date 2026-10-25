"""Who gets looked up, and how much of the quota one source address can spend."""

from __future__ import annotations

import os
import time

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from ingest.enrichment import EnrichmentSettings
from ingest.enrichment import intel as intel_mod
from ingest.indicators import IndicatorSettings

from .test_intel import AB_KEY, SETTINGS, SHA, Remote

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]


@pytest.fixture(autouse=True)
def no_rate_gap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(intel_mod, "MIN_GAP_S", {})


async def add(
    engine: AsyncEngine,
    value: str,
    ips: list[str],
    *,
    kind: str = "domain",
    role: str = "download_host",
    sightings: int = 1,
    trusted: bool = False,
    demo: bool = False,
    host: str | None = None,
) -> int:
    async with engine.begin() as conn:
        iid = await conn.scalar(
            text(
                "INSERT INTO indicators (type, value, role, host, first_seen, last_seen, sightings, "
                "trusted, demo) VALUES (:t, :v, :r, :h, now(), now(), :n, :tr, :d) RETURNING id"
            ),
            {"t": kind, "v": value, "r": role, "h": host, "n": sightings, "tr": trusted, "d": demo},
        )
        for i, ip in enumerate(ips):
            await conn.execute(
                text(
                    "INSERT INTO indicator_sessions VALUES (:i, :s, CAST(:ip AS inet), 'ssh', now())"
                ),
                {"i": iid, "s": f"{value}-{i}", "ip": ip},
            )
    return int(iid)


def worker(
    remote: Remote,
    factory: async_sessionmaker[AsyncSession],
    settings: EnrichmentSettings = SETTINGS,
    ind: IndicatorSettings | None = None,
) -> intel_mod.IntelWorker:
    client = httpx.AsyncClient(transport=httpx.MockTransport(remote), follow_redirects=False)
    return intel_mod.IntelWorker(factory, settings, client, ind or IndicatorSettings())


async def test_candidates_are_ranked_by_distinct_sources_then_role_then_sightings(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    await add(engine, "loud.badhost.ru", ["198.51.100.1"], sightings=500)  # one address, many hits
    await add(engine, "shared.badhost.ru", ["198.51.100.1", "198.51.100.2", "198.51.100.3"])
    await add(engine, "pair-dl.badhost.ru", ["198.51.100.1", "198.51.100.2"], sightings=2)
    await add(
        engine, "pair-c.badhost.ru", ["198.51.100.1", "198.51.100.2"], role="contacted_host",
        sightings=900,
    )  # fmt: skip
    order = [c.value for c in await worker(Remote(), factory).candidates("abusech", limit=10)]
    assert order == [
        "shared.badhost.ru",
        "pair-dl.badhost.ru",
        "pair-c.badhost.ru",
        "loud.badhost.ru",
    ]


async def test_one_address_cannot_spend_more_than_its_daily_share(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(intel_mod, "PER_SOURCE_PER_DAY", 3)
    for i in range(8):
        await add(engine, f"spray{i}.badhost.ru", ["198.51.100.9"], sightings=10 - i)
    await add(engine, "other.badhost.ru", ["198.51.100.77"], sightings=1)
    remote = Remote()
    w = worker(remote, factory)
    for _ in range(6):
        await w.run_once()
    asked = {r.read().decode().removeprefix("host=") for r in remote.requests if r.method == "POST"}
    spray = {a for a in asked if a.startswith("spray")}
    assert len(spray) == 3  # the cap, whatever the number of unique values sprayed
    assert "other.badhost.ru" in asked  # another address is not affected


async def test_urls_wait_for_a_listed_host_and_hosts_come_first(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    host = await add(engine, "dl.badhost.ru", ["198.51.100.1", "198.51.100.2"])
    await add(
        engine, "http://dl.badhost.ru/a.sh", ["198.51.100.1", "198.51.100.2"], kind="url",
        host="dl.badhost.ru",
    )  # fmt: skip
    w = worker(Remote(), factory)
    assert [c.value for c in await w.candidates("abusech")] == ["dl.badhost.ru"]
    async with engine.begin() as conn:  # the host turns out to be listed
        await conn.execute(
            text(
                "INSERT INTO indicator_intel (indicator_id, source, known) VALUES (:i, 'urlhaus', true)"
            ),
            {"i": host},
        )
    got = {c.value for c in await w.candidates("abusech")}
    assert "http://dl.badhost.ru/a.sh" in got


async def test_hashes_need_a_sensor_digest_or_two_sources(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    await add(engine, "a" * 63 + "1", ["198.51.100.1"], kind="hash", role="hash")  # bare token
    await add(engine, "b" * 63 + "2", ["198.51.100.1"], kind="hash", role="hash", trusted=True)
    await add(engine, "c" * 63 + "3", ["198.51.100.1", "198.51.100.2"], kind="hash", role="hash")
    for provider in ("virustotal", "abusech"):
        got = {c.value[0] for c in await worker(Remote(), factory).candidates(provider, limit=10)}
        assert got == {"b", "c"}, provider


async def test_unknown_single_source_answers_are_remembered_for_a_week(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    solo = await add(engine, "solo.badhost.ru", ["198.51.100.1"])
    pair = await add(engine, "pair.badhost.ru", ["198.51.100.1", "198.51.100.2"])
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO indicator_intel (indicator_id, source, known, checked_at) "
                "SELECT i, s, false, now() - interval '3 days' "
                "FROM unnest(CAST(:ids AS bigint[])) i, unnest(ARRAY['urlhaus', 'threatfox']) s"
            ),
            {"ids": [solo, pair]},
        )
    w = worker(Remote(), factory)
    assert [c.value for c in await w.candidates("abusech")] == ["pair.badhost.ru"]
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE indicator_intel SET checked_at = now() - interval '8 days'")
        )
    assert {c.value for c in await w.candidates("abusech")} == {
        "solo.badhost.ru",
        "pair.badhost.ru",
    }


async def test_a_share_of_the_quota_is_kept_for_shared_indicators(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    for i in range(10):
        await add(engine, f"s{i}.badhost.ru", [f"198.51.100.{i + 10}"])
    capped = EnrichmentSettings.from_env({"ABUSECH_AUTH_KEY": AB_KEY, "ABUSECH_DAILY_QUOTA": "10"})
    remote = Remote()
    w = worker(remote, factory, capped)
    for _ in range(10):
        await w.run_once()
    assert len(remote.requests) == 7  # 70 % of 10: single-source indicators stop there
    await add(engine, "shared.badhost.ru", ["198.51.100.1", "198.51.100.2"])
    await w.run_once()
    assert len(remote.requests) == 9  # the reserved 30 % is there for a shared one (2 requests)


async def test_the_ignore_list_is_applied_when_looking_up(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    await add(engine, "mine.badhost.ru", ["198.51.100.1", "198.51.100.2"])
    await add(engine, "8.8.4.4", ["198.51.100.1", "198.51.100.2"], kind="ip")
    await add(engine, "theirs.badhost.ru", ["198.51.100.1", "198.51.100.2"])
    ind = IndicatorSettings(ignore=("mine.badhost.ru", "8.8.4.0/24"), keep_documentation=True)
    remote = Remote()
    await worker(remote, factory, ind=ind).run_once()
    bodies = b"".join(r.read() for r in remote.requests)
    assert b"theirs.badhost.ru" in bodies
    assert b"mine.badhost.ru" not in bodies and b"8.8.4.4" not in bodies
    async with engine.connect() as conn:
        marked = {
            r.value
            for r in await conn.execute(
                text(
                    "SELECT i.value FROM indicator_intel n JOIN indicators i ON i.id = n.indicator_id "
                    "WHERE 'not-checked' = ANY (n.tags)"
                )
            )
        }
    assert marked == {"mine.badhost.ru", "8.8.4.4"}


async def test_documentation_values_are_never_sent_even_with_keep_documentation(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    await add(engine, "203.0.113.66", ["198.51.100.1", "198.51.100.2"], kind="ip")
    remote = Remote()
    await worker(remote, factory, ind=IndicatorSettings(keep_documentation=True)).run_once()
    assert remote.requests == []


async def test_demo_indicators_are_marked_and_never_sent(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    await add(engine, "demo.badhost.ru", ["198.51.100.1", "198.51.100.2"], demo=True)
    await add(
        engine, f"{SHA[:63]}d", ["198.51.100.1"], kind="hash", role="hash", trusted=True, demo=True
    )
    remote = Remote()
    w = worker(remote, factory)
    await w.run_once()
    assert remote.requests == []
    async with engine.connect() as conn:
        n = await conn.scalar(
            text("SELECT count(*) FROM indicator_intel WHERE 'not-checked' = ANY (tags)")
        )
    assert n and n >= 2


async def test_expired_retry_entries_are_dropped_each_cycle(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    w = worker(Remote(), factory)
    w.state.retry_after = {
        ("abusech", 1): time.monotonic() - 5,
        ("abusech", 2): time.monotonic() + 500,
    }
    await w.run_once()
    assert list(w.state.retry_after) == [("abusech", 2)]


async def test_requests_ask_for_an_uncompressed_body() -> None:
    remote = Remote()
    await worker(remote, None).urlhaus("domain", "files.badhost.ru")  # type: ignore[arg-type]
    assert remote.requests[0].headers["Accept-Encoding"] == "identity"


def test_nothing_but_the_value_leaves() -> None:
    # The request builders only take a kind and a value: there is no parameter for event data.
    import inspect

    for fn in (intel_mod.IntelWorker.urlhaus, intel_mod.IntelWorker.threatfox):
        assert list(inspect.signature(fn).parameters) == ["self", "kind", "value"]

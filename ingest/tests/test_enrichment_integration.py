"""Enrichment against a real TimescaleDB: writer, tagging, reputation worker, grants."""

import os
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from suckerpot_db import create_engine

from ingest.enrichment import EnrichmentSettings, GeoResolver
from ingest.enrichment.enricher import Enricher
from ingest.enrichment.reputation import ReputationWorker
from ingest.enrichment.status import publish_status
from ingest.tagging import load_rules
from ingest.writer import write_batch

from .db_fixtures import _role_url
from .helpers import make_event

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

RULES = load_rules(Path(__file__).resolve().parents[1] / "rules")
TEST_IPS = ["198.51.100.10", "198.51.100.11", "198.51.100.12", "198.51.100.13"]


@pytest.fixture
def enricher(tmp_path: Path) -> Enricher:
    return Enricher(GeoResolver(tmp_path, fake_for_private=True), RULES)


async def rows(engine: AsyncEngine, sql: str, **params: Any) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(sql), params)).all())


async def test_writer_enriches_and_tags(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], enricher: Enricher
) -> None:
    ip = "203.0.113.50"
    batch1 = [
        make_event("connect", sid="e1", offset_s=0, ip=ip),
        make_event("login_attempt", sid="e1", offset_s=1, ip=ip, data={"success": True}),
        make_event("command", sid="e1", offset_s=2, ip=ip, data={"input": "uname -a"}),
        make_event("download_attempt", sid="e1", offset_s=3, ip=ip, data={"url": "http://x/a.sh"}),
    ]
    await write_batch(factory, batch1, enricher)
    ev = await rows(engine, "SELECT type, country, asn, org, tags FROM events ORDER BY ts")
    assert all(r.country and r.asn for r in ev)
    assert next(r for r in ev if r.type == "command").tags == ["recon"]
    assert next(r for r in ev if r.type == "connect").tags == []
    (s,) = await rows(engine, "SELECT country, city, asn, org, tags FROM sessions")
    assert s.country and s.city and s.asn and s.org
    assert s.tags == ["recon"]

    # The exec step arrives in a later batch: session-scope malware-drop fires then.
    batch2 = [
        make_event("command", sid="e1", offset_s=4, ip=ip, data={"input": "chmod +x a.sh; ./a.sh"}),
        make_event("command", sid="e1", offset_s=5, ip=ip, data={"input": "uname"}),
    ]
    await write_batch(factory, batch2, enricher)
    (s,) = await rows(engine, "SELECT tags, event_count, downloads, country FROM sessions")
    assert s.tags == ["exec-attempt", "malware-drop", "recon"]  # sorted, no duplicates
    assert (s.event_count, s.downloads) == (6, 1) and s.country


async def test_credential_stuffing_and_cached_reputation(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], enricher: Enricher
) -> None:
    ip = "198.51.100.77"
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO ip_reputation (ip, abuse_score, abuse_checked_at, gn_noise, "
                "gn_checked_at) VALUES (CAST(:ip AS inet), 77, now(), true, now())"
            ),
            {"ip": ip},
        )
    events = [
        make_event("login_attempt", sid="cs1", offset_s=i, ip=ip, data={"success": False})
        for i in range(25)
    ]
    await write_batch(factory, events, enricher)
    (s,) = await rows(engine, "SELECT tags, abuse_score, known_scanner FROM sessions")
    assert s.tags == ["credential-stuffing", "scanner"]
    assert s.abuse_score == 77 and s.known_scanner is True
    (e,) = await rows(engine, "SELECT abuse_score, known_scanner FROM events LIMIT 1")
    assert (e.abuse_score, e.known_scanner) == (77, True)


async def test_writer_without_enricher_still_works(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    await write_batch(factory, [make_event("command", data={"input": "uname"})])
    (e,) = await rows(engine, "SELECT country, tags FROM events")
    assert e.country is None and e.tags == []


# ---- reputation worker ------------------------------------------------------------------------


class Providers:
    """Mock AbuseIPDB + GreyNoise."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.abuse_status = 200
        self.gn_status = 200

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        if req.url.host == "api.abuseipdb.com":
            if self.abuse_status != 200:
                return httpx.Response(self.abuse_status)
            return httpx.Response(
                200, json={"data": {"abuseConfidenceScore": 88, "totalReports": 12}}
            )
        if req.url.host == "api.greynoise.io":
            ip = req.url.path.rsplit("/", 1)[-1]
            if self.gn_status != 200:
                return httpx.Response(self.gn_status)
            if ip.endswith(".13"):
                return httpx.Response(404, json={"message": "not seen"})
            return httpx.Response(
                200, json={"noise": True, "riot": False, "classification": "malicious", "name": "x"}
            )
        raise AssertionError(f"unexpected host {req.url.host}")

    def calls(self, host: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.host == host]


def worker(
    factory: async_sessionmaker[AsyncSession], providers: Providers, **env: str
) -> ReputationWorker:
    base = {"ABUSEIPDB_API_KEY": "k1", "GREYNOISE_API_KEY": "k2"}
    settings = EnrichmentSettings.from_env({**base, **env})
    client = httpx.AsyncClient(transport=httpx.MockTransport(providers))
    return ReputationWorker(factory, settings, client)


async def seed_sessions(factory: async_sessionmaker[AsyncSession]) -> None:
    a, b, c, d = TEST_IPS
    events = [make_event("login_attempt", sid="ra", ip=a, offset_s=0, data={"success": True})]
    events += [
        make_event("command", sid="ra", ip=a, offset_s=i, data={"input": "x"}) for i in range(1, 6)
    ]
    events += [make_event("command", sid="rb", ip=b, data={"input": "ls"})]
    events += [make_event("connect", sid="rc", ip=c)]  # one idle event: not worth a lookup
    events += [make_event("connect", sid=f"rd{i}", ip=d, offset_s=i) for i in range(12)]
    await write_batch(factory, events)


@pytest.fixture(autouse=False)
def routable(monkeypatch: pytest.MonkeyPatch) -> None:
    # Documentation addresses are never looked up; pretend they are routable for the test.
    monkeypatch.setattr("ingest.enrichment.reputation.is_routable", lambda _a: True)


async def test_quota_priority_cache_and_session_updates(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession], routable: None
) -> None:
    await seed_sessions(factory)
    p = Providers()
    w = worker(factory, p, ABUSEIPDB_DAILY_QUOTA="2", GREYNOISE_DAILY_QUOTA="50")
    made = await w.run_once()
    ips = [r.url.params["ipAddress"] for r in p.calls("api.abuseipdb.com")]
    assert ips == [TEST_IPS[3], TEST_IPS[0]]  # most active first (12 events, then 6)
    assert TEST_IPS[2] not in ips  # one idle connect is not worth a lookup
    gn_ips = [r.url.path.rsplit("/", 1)[-1] for r in p.calls("api.greynoise.io")]
    assert set(gn_ips) == {TEST_IPS[0], TEST_IPS[1], TEST_IPS[3]} and made == len(ips) + 3
    # read-only: only GET, only the two providers, never a report endpoint
    assert all(r.method == "GET" for r in p.requests)
    assert not any("report" in r.url.path for r in p.requests)
    assert p.requests[0].headers.get("key") or p.requests[0].headers.get("Key")

    quota = {
        r.provider: r.used
        for r in await rows(engine, "SELECT provider, used FROM enrichment_quota")
    }
    assert quota == {"abuseipdb": 2, "greynoise": 3}
    ses = {
        r.sid: r
        for r in await rows(
            engine, "SELECT session_id AS sid, abuse_score, known_scanner, tags FROM sessions"
        )
    }
    assert ses["ra"].abuse_score == 88 and ses["ra"].known_scanner is True
    assert "scanner" in ses["ra"].tags
    assert ses["rd0"].known_scanner is False and "scanner" not in ses["rd0"].tags  # GN 404

    # Cached for 24 h and the abuse quota is spent: a new worker (restart) makes no calls.
    p2 = Providers()
    w2 = worker(factory, p2, ABUSEIPDB_DAILY_QUOTA="2", GREYNOISE_DAILY_QUOTA="50")
    assert await w2.run_once() == 0 and not p2.requests
    # With a larger quota the remaining uncached IP is looked up; cached ones are not.
    p3 = Providers()
    w3 = worker(factory, p3, ABUSEIPDB_DAILY_QUOTA="10")
    await w3.run_once()
    checked = {r.url.params["ipAddress"] for r in p3.calls("api.abuseipdb.com")}
    assert checked == {TEST_IPS[1]}  # the other two are cached for 24 h
    st = await w3.status()
    assert st["abuseipdb"]["configured"] and "k1" not in str(st)


async def test_rate_limit_pauses_and_auth_disables(
    factory: async_sessionmaker[AsyncSession], routable: None
) -> None:
    await seed_sessions(factory)
    p = Providers()
    p.abuse_status, p.gn_status = 429, 401
    w = worker(factory, p)
    await w.run_once()
    assert len(p.calls("api.abuseipdb.com")) == 1 and len(p.calls("api.greynoise.io")) == 1
    assert w.last_error == {"abuseipdb": "rate_limited", "greynoise": "auth"}
    await w.run_once()  # paused / disabled: no retry storm
    assert len(p.requests) == 2
    assert not w.enabled("greynoise") and w.enabled("abuseipdb")


async def test_without_keys_nothing_happens(
    factory: async_sessionmaker[AsyncSession], routable: None
) -> None:
    await seed_sessions(factory)
    p = Providers()
    w = worker(factory, p, ABUSEIPDB_API_KEY="", GREYNOISE_API_KEY="")
    assert await w.run_once() == 0 and not p.requests


async def test_private_and_documentation_ips_are_not_sent_to_providers(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    await seed_sessions(factory)  # documentation range, real is_routable
    p = Providers()
    assert await worker(factory, p).run_once() == 0 and not p.requests


# ---- grants -----------------------------------------------------------------------------------


async def test_role_grants_for_enrichment_tables(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    await publish_status(factory, "geoip", {"provider": "dbip", "available": True})
    async with factory() as s, s.begin():
        await s.execute(text("INSERT INTO ip_reputation (ip, abuse_score) VALUES ('192.0.2.1', 5)"))
        await s.execute(text("UPDATE ip_reputation SET abuse_score = 6"))
        await s.execute(
            text("INSERT INTO enrichment_quota (provider, day, used) VALUES ('x', current_date, 1)")
        )
    async with factory() as s:
        with pytest.raises(DBAPIError):
            await s.execute(text("DELETE FROM ip_reputation"))

    api = create_engine(_role_url("API"), pool_size=1)
    try:
        async with api.connect() as conn:
            assert await conn.scalar(text("SELECT count(*) FROM ip_reputation")) == 1
            assert await conn.scalar(text("SELECT count(*) FROM enrichment_status")) == 1
            assert await conn.scalar(text("SELECT count(*) FROM enrichment_quota")) == 1
        for stmt in (
            "INSERT INTO ip_reputation (ip) VALUES ('192.0.2.2')",
            "UPDATE enrichment_quota SET used = 0",
            "DELETE FROM enrichment_status",
        ):
            async with api.connect() as conn:
                with pytest.raises(DBAPIError):
                    await conn.execute(text(stmt))
    finally:
        await api.dispose()

"""Takedown re-checks against a real database, as the least-privilege collector role."""

from __future__ import annotations

import asyncio
import hashlib
import os
import subprocess
import sys
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from suckerpot_db import create_session_factory, database_url_from_env
from suckerpot_db.roles import apply_roles

from collector.config import CollectorSettings
from collector.service import CollectorService
from collector.store import Quarantine
from tests.fakes import FakeProxy, Reply, open_gate

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
DB_DIR = Path(os.environ.get("DB_DIR", ROOT / "db"))
COLLECTOR_PW = "collector-test-password-0123456789"
ENV: dict[str, str] = {
    **os.environ,
    "POSTGRES_INGEST_USER": os.environ.get("POSTGRES_INGEST_USER", "suckerpot_ingest"),
    "POSTGRES_INGEST_PASSWORD": os.environ.get("POSTGRES_INGEST_PASSWORD", "ingest-test-password"),
    "POSTGRES_API_USER": os.environ.get("POSTGRES_API_USER", "suckerpot_api"),
    "POSTGRES_API_PASSWORD": os.environ.get("POSTGRES_API_PASSWORD", "api-test-password"),
    "POSTGRES_COLLECTOR_PASSWORD": COLLECTOR_PW,
    "POSTGRES_ANALYZER_PASSWORD": "analyzer-test-password-0123456789",
}
NOW = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
HOST = "http://files.example.test"
BODY = b"#!/bin/sh\necho one\n" * 8
OTHER = b"#!/bin/sh\necho two\n" * 8
SHA = hashlib.sha256(BODY).hexdigest()
TABLES = (
    "takedown_checks, takedown_targets, fetch_targets, fetch_attempts, samples, sample_sources, "
    "indicators, enrichment_quota, enrichment_status"
)


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now


def _alembic(*args: str) -> None:
    subprocess.run(
        [sys.executable, "-m", "alembic", *args], cwd=DB_DIR, env=ENV, check=True, timeout=180
    )


@pytest.fixture
async def owner() -> AsyncIterator[AsyncEngine]:
    _alembic("upgrade", "head")
    engine = create_async_engine(database_url_from_env(ENV))
    for attempt in range(5):
        try:
            async with engine.begin() as conn:
                await conn.run_sync(lambda c: apply_roles(c, ENV))
                await conn.execute(text(f"TRUNCATE {TABLES} CASCADE"))
            break
        except DBAPIError as exc:
            if getattr(exc.orig, "sqlstate", None) != "40P01" or attempt == 4:
                raise
            await asyncio.sleep(0.2 * (attempt + 1))
    yield engine
    await engine.dispose()


@pytest.fixture
async def factory(owner: AsyncEngine) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    url = database_url_from_env(
        {
            **ENV,
            "POSTGRES_USER": os.environ.get("POSTGRES_COLLECTOR_USER", "suckerpot_collector"),
            "POSTGRES_PASSWORD": COLLECTOR_PW,
        }
    )
    engine = create_async_engine(url)
    yield create_session_factory(engine)
    await engine.dispose()


def settings(tmp_path: Path, **kw: Any) -> CollectorSettings:
    base: dict[str, Any] = {
        "enabled": True,
        "takedown_enabled": True,
        "max_bytes": 64 * 1024,
        "timeout_s": 10,
        "connect_timeout_s": 2,
        "host_interval_s": 0.0,
        "quarantine_dir": tmp_path / "q",
        "heartbeat_path": tmp_path / "hb",
    }
    base.update(kw)
    return CollectorSettings(**base)


async def add_target(owner: AsyncEngine, url: str, **kw: Any) -> tuple[int, int]:
    """A fetched fetch target with its sample and a takedown target. Returns (takedown id, fetch id)."""
    fields: dict[str, Any] = {
        "kind": "url", "elig": True, "demo": False, "tracking": True, "state": "up",
        "next": NOW - timedelta(minutes=1), "until": NOW + timedelta(days=20),
    }  # fmt: skip
    fields.update(kw)
    async with owner.begin() as conn:
        fid = int(
            await conn.scalar(
                text(
                    "INSERT INTO fetch_targets (url, scheme, host, status, first_seen, last_sha256) "
                    "VALUES (:u, 'http', 'files.example.test', 'fetched', :n, :s) RETURNING id"
                ),
                {"u": url, "n": NOW, "s": SHA},
            )
            or 0
        )
        await conn.execute(
            text(
                "INSERT INTO samples (sha256, sha1, md5, size, kind, first_seen, last_seen) "
                "VALUES (:s, 'x', 'y', 10, 'script', :n, :n) ON CONFLICT DO NOTHING"
            ),
            {"s": SHA, "n": NOW},
        )
        tid = await conn.scalar(
            text(
                "INSERT INTO takedown_targets (kind, role, value, target_key, fetch_target_id, "
                "provider_key, reported_at, track_until, http_eligible, demo, tracking, state, "
                "http_next_at, baseline_sha256) VALUES (:kind, 'payload_url', :u, :k, :f, 'as64500', "
                ":rep, :until, :elig, :demo, :tracking, :state, :next, :s) RETURNING id"
            ),
            {
                "kind": fields["kind"], "u": url, "k": hashlib.sha256(url.encode()).hexdigest(),
                "f": fid, "rep": NOW - timedelta(hours=2), "until": fields["until"],
                "elig": fields["elig"], "demo": fields["demo"], "tracking": fields["tracking"],
                "state": fields["state"], "next": fields["next"], "s": SHA,
            },
        )  # fmt: skip
    return int(tid or 0), fid


async def rows(owner: AsyncEngine, sql: str, **params: Any) -> list[Any]:
    async with owner.connect() as conn:
        return list((await conn.execute(text(sql), params)).all())


def service(
    tmp_path: Path, factory: Any, gate: Any, clock: Clock, **kw: Any
) -> tuple[CollectorService, Quarantine]:
    s = settings(tmp_path, **kw)
    store = Quarantine(s.quarantine_dir)
    store.prepare()
    return CollectorService(s, factory, store, gate, clock=clock), store


async def test_same_file_writes_a_check_and_no_sample(
    owner: AsyncEngine, factory: Any, tmp_path: Path
) -> None:
    tid, _ = await add_target(owner, f"{HOST}/a.sh")
    proxy = FakeProxy(lambda u, h: Reply(body=BODY))
    async with proxy.running():
        gate = await open_gate(proxy.url)
        svc, store = service(tmp_path, factory, gate, Clock())
        assert await svc.rechecker.run() == 1
    checks = await rows(
        owner, "SELECT outcome, sha256 FROM takedown_checks WHERE target_id = :t", t=tid
    )
    assert [(c.outcome, c.sha256) for c in checks] == [("same", SHA)]
    assert len(await rows(owner, "SELECT 1 FROM samples")) == 1  # the seeded one only
    assert [p for p in store.root.rglob("*") if p.is_file()] == []
    t = (await rows(owner, "SELECT * FROM takedown_targets WHERE id = :t", t=tid))[0]
    assert t.http_step == 2 and t.http_next_at == NOW + timedelta(hours=4) and t.last_sha256 is None
    assert t.state == "up"  # the state is ingest's, the collector never touches it
    quota = await rows(owner, "SELECT used FROM enrichment_quota WHERE provider = 'takedown_http'")
    assert [q.used for q in quota] == [1]


async def test_changed_file_becomes_a_sample(
    owner: AsyncEngine, factory: Any, tmp_path: Path
) -> None:
    tid, fid = await add_target(owner, f"{HOST}/b.sh")
    proxy = FakeProxy(lambda u, h: Reply(body=OTHER))
    async with proxy.running():
        gate = await open_gate(proxy.url)
        svc, _ = service(tmp_path, factory, gate, Clock())
        await svc.rechecker.run()
    new = hashlib.sha256(OTHER).hexdigest()
    assert [r.outcome for r in await rows(owner, "SELECT outcome FROM takedown_checks")] == [
        "changed"
    ]
    assert len(await rows(owner, "SELECT 1 FROM samples WHERE sha256 = :s", s=new)) == 1
    assert (
        len(
            await rows(
                owner,
                "SELECT 1 FROM sample_sources WHERE sha256 = :s AND target_id = :f",
                s=new,
                f=fid,
            )
        )
        == 1
    )
    t = (await rows(owner, "SELECT last_sha256 FROM takedown_targets WHERE id = :t", t=tid))[0]
    assert t.last_sha256 == new


async def test_only_eligible_tracked_non_demo_urls_are_selected(
    owner: AsyncEngine, factory: Any, tmp_path: Path
) -> None:
    await add_target(owner, f"{HOST}/ok.sh")
    await add_target(owner, f"{HOST}/not-eligible.sh", elig=False)
    await add_target(owner, f"{HOST}/demo.sh", demo=True)
    await add_target(owner, f"{HOST}/stopped.sh", tracking=False)
    await add_target(owner, f"{HOST}/future.sh", next=NOW + timedelta(hours=1))
    await add_target(owner, f"{HOST}/expired.sh", until=NOW - timedelta(days=1))
    async with owner.begin() as conn:  # a C2 host row: kind 'ip', never http_eligible
        await conn.execute(
            text(
                "INSERT INTO takedown_targets (kind, role, value, target_key, provider_key, "
                "reported_at, track_until, http_next_at) VALUES ('ip', 'c2', '198.51.100.7', :k, "
                "'as64500', :n, :u, :n)"
            ),
            {"k": "b" * 64, "n": NOW - timedelta(hours=1), "u": NOW + timedelta(days=5)},
        )
    proxy = FakeProxy(lambda u, h: Reply(body=BODY))
    async with proxy.running():
        gate = await open_gate(proxy.url)
        svc, _ = service(tmp_path, factory, gate, Clock())
        due = await svc.rechecker.due()
        assert [t.url for t in due] == [f"{HOST}/ok.sh"]
        await svc.rechecker.run()
    assert [u for u, _ in proxy.seen] == [f"{HOST}/ok.sh"]


async def test_gate_closed_writes_no_row_and_spends_no_quota(
    owner: AsyncEngine, factory: Any, tmp_path: Path
) -> None:
    await add_target(owner, f"{HOST}/c.sh")
    proxy = FakeProxy(lambda u, h: Reply(body=BODY))
    async with proxy.running():
        gate = await open_gate(proxy.url, open_=False)
        svc, _ = service(tmp_path, factory, gate, Clock())
        assert await svc.rechecker.run() == 0
    assert await rows(owner, "SELECT 1 FROM takedown_checks") == []
    used = await rows(owner, "SELECT used FROM enrichment_quota WHERE provider = 'takedown_http'")
    assert all(u.used == 0 for u in used)  # reserved then refunded
    assert proxy.seen == []


async def test_proxy_down_writes_no_row(owner: AsyncEngine, factory: Any, tmp_path: Path) -> None:
    await add_target(owner, f"{HOST}/d.sh")
    gate = await open_gate("http://127.0.0.1:1")
    svc, _ = service(tmp_path, factory, gate, Clock())
    assert await svc.rechecker.run() == 0
    assert await rows(owner, "SELECT 1 FROM takedown_checks") == []


async def test_redirect_to_private_stops_the_target(
    owner: AsyncEngine, factory: Any, tmp_path: Path
) -> None:
    tid, _ = await add_target(owner, f"{HOST}/e.sh")
    proxy = FakeProxy(
        lambda u, h: Reply(302, headers={"Location": "http://10.0.0.5/x"})  # gitleaks:allow
    )  # gitleaks:allow
    async with proxy.running():
        gate = await open_gate(proxy.url)
        svc, _ = service(tmp_path, factory, gate, Clock())
        await svc.rechecker.run()
    t = (await rows(owner, "SELECT http_eligible FROM takedown_targets WHERE id = :t", t=tid))[0]
    assert t.http_eligible is False
    assert [r.outcome for r in await rows(owner, "SELECT outcome FROM takedown_checks")] == [
        "refused"
    ]


async def test_the_daily_quota_is_a_hard_cap(
    owner: AsyncEngine, factory: Any, tmp_path: Path
) -> None:
    for i in range(3):
        await add_target(owner, f"{HOST}/q{i}.sh")
    proxy = FakeProxy(lambda u, h: Reply(body=BODY))
    async with proxy.running():
        gate = await open_gate(proxy.url)
        svc, _ = service(tmp_path, factory, gate, Clock(), takedown_http_daily_quota=2)
        await svc.rechecker.run()
    assert len(proxy.seen) == 2
    assert len(await rows(owner, "SELECT 1 FROM takedown_checks")) == 2


async def test_disabled_flag_means_no_request(
    owner: AsyncEngine, factory: Any, tmp_path: Path
) -> None:
    await add_target(owner, f"{HOST}/f.sh")
    proxy = FakeProxy(lambda u, h: Reply(body=BODY))
    async with proxy.running():
        gate = await open_gate(proxy.url)
        svc, _ = service(tmp_path, factory, gate, Clock(), takedown_enabled=False)
        await svc.step()
    assert all("f.sh" not in u for u, _ in proxy.seen)
    assert await rows(owner, "SELECT 1 FROM takedown_checks") == []

"""The abuse.ch submission worker against a real database. The abuse.ch endpoints are a fake
transport: no test opens a connection, and every test counts the requests that were attempted."""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from suckerpot_db import create_engine, create_session_factory
from suckerpot_db.secretbox import Credential, SecretBox
from suckerpot_reporting import SelfTermRow, load_self_terms

from ingest.abusech.client import AbusechClient
from ingest.abusech.worker import KEY_AAD, AbusechSubmitWorker
from ingest.enrichment.intel import IntelResult
from ingest.features import FeatureSettings

from ..db_fixtures import _role_url
from ..helpers import fake_gate

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]
Factory = async_sessionmaker[AsyncSession]
SELF = "198.51.100.77"
KEY = "abusech-test-key-" + "z" * 20
BOX = SecretBox(bytes(range(32, 72)))
NOW = datetime.now(UTC).replace(microsecond=0)
SHA = "c" * 64
URL = "http://files.example.net/bins/mirai.arm7"
ENABLED = FeatureSettings(abusech_submit_enabled=True)


class Terms:
    def __init__(self, *, with_self: bool = True) -> None:
        rows = [SelfTermRow(kind="address", value=SELF, source="manual")] if with_self else []
        self.terms = load_self_terms(rows, {})

    async def get(self) -> Any:
        return self.terms


class Intel:
    def __init__(self, known: bool = False) -> None:
        self.known = known
        self.calls = 0

    def enabled(self, provider: str) -> bool:
        return True

    def quota(self, provider: str) -> int:
        return 1000

    async def urlhaus(self, kind: str, value: str) -> IntelResult:
        self.calls += 1
        return IntelResult("urlhaus", self.known, reference="https://urlhaus.abuse.ch/url/1/")

    async def threatfox(self, kind: str, value: str) -> IntelResult:
        self.calls += 1
        return IntelResult("threatfox", self.known)


class World:
    def __init__(self, owner: AsyncEngine, api: AsyncEngine, factory: Factory) -> None:
        self.owner, self.api, self.factory = owner, api, factory
        self.requests: list[httpx.Request] = []
        self.answer: dict[str, Any] = {"query_status": "ok"}

    def client(self, *, open_: bool = True) -> AbusechClient:
        def handler(req: httpx.Request) -> httpx.Response:
            self.requests.append(req)
            return httpx.Response(200, json=self.answer)

        return AbusechClient(
            fake_gate(open_=open_), httpx.AsyncClient(transport=httpx.MockTransport(handler))
        )

    def worker(
        self,
        *,
        intel: Intel | None = None,
        open_: bool = True,
        terms: Terms | None = None,
        settings: FeatureSettings = ENABLED,
    ) -> AbusechSubmitWorker:
        return AbusechSubmitWorker(
            settings,
            self.factory,
            terms or Terms(),
            fake_gate(open_=open_),
            BOX,
            intel=intel or Intel(),
            client=self.client(open_=open_),
            malpedia={"mirai": "elf.mirai"},
        )

    async def settings(self, mode: str, **kw: Any) -> None:
        ct, nonce = BOX.encrypt(KEY_AAD, Credential(key=KEY))
        async with self.owner.begin() as conn:
            await conn.execute(text("DELETE FROM abusech_submission"))
            await conn.execute(
                text(
                    "INSERT INTO abusech_submission (id, mode, threatfox_enabled, anonymous, "
                    "auto_hold_minutes, daily_cap, key_ciphertext, key_nonce, key_last4) VALUES "
                    "(1, :m, :tf, :an, :h, :cap, :c, :n, :l4)"
                ),
                {
                    "m": mode, "tf": kw.get("threatfox", False), "an": kw.get("anonymous", True),
                    "h": kw.get("hold", 10), "cap": kw.get("cap", 20), "c": ct, "n": nonce,
                    "l4": KEY[-4:],
                },
            )  # fmt: skip

    async def sample(self, url: str = URL, *, kind: str = "elf", family: str = "mirai") -> int:
        async with self.owner.begin() as conn:
            fid = int(
                await conn.scalar(
                    text(
                        "INSERT INTO fetch_targets (url, scheme, host, status, first_seen, "
                        "last_sha256) VALUES (:u, 'http', 'files.example.net', 'fetched', :n, :s) "
                        "ON CONFLICT (url) DO UPDATE SET status = 'fetched' RETURNING id"
                    ),
                    {"u": url, "n": NOW, "s": SHA},
                )
                or 0
            )
            await conn.execute(
                text(
                    "INSERT INTO samples (sha256, sha1, md5, size, kind, arch, endian, family, "
                    "first_seen, last_seen) VALUES (:s, 'x', 'y', 10, :k, 'arm', 'little', :f, "
                    ":n, :n) ON CONFLICT (sha256) DO UPDATE SET kind = :k, family = :f"
                ),
                {"s": SHA, "k": kind, "f": family, "n": NOW},
            )
            await conn.execute(
                text(
                    "INSERT INTO sample_sources (sha256, target_id, first_fetched, last_fetched) "
                    "VALUES (:s, :f, :n, :n) ON CONFLICT DO NOTHING"
                ),
                {"s": SHA, "f": fid, "n": NOW},
            )
        return fid

    async def rows(self) -> list[Any]:
        async with self.owner.connect() as conn:
            return list(
                (await conn.execute(text("SELECT * FROM abusech_submissions ORDER BY id"))).all()
            )

    async def approve(self, sid: int) -> None:
        """What the API does: candidate to pending, as the API role."""
        async with self.api.begin() as conn:
            await conn.execute(
                text(
                    "UPDATE abusech_submissions SET status = 'pending', approved_by = 'admin' "
                    "WHERE id = :i"
                ),
                {"i": sid},
            )


@pytest.fixture
async def world(engine: AsyncEngine, factory: Factory) -> AsyncIterator[World]:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE takedown_target_links, abusech_submissions, abusech_submission, "
                "sample_links, sample_sources, samples, fetch_targets CASCADE"
            )
        )
    api = create_engine(_role_url("API"), pool_size=2)
    yield World(engine, api, factory)
    await api.dispose()


async def test_the_server_flag_off_means_nothing_at_all(world: World) -> None:
    await world.settings("auto")
    await world.sample()
    worker = world.worker(settings=FeatureSettings(abusech_submit_enabled=False))
    assert worker.client is not None  # the injected fake; the real one is never even built
    await worker.run()  # a disabled worker returns at once
    await worker.run_once()
    assert await world.rows() == []
    assert world.requests == []
    worker2 = AbusechSubmitWorker(FeatureSettings(), world.factory, Terms(), fake_gate(), BOX)
    assert worker2.client is None


async def test_mode_off_computes_no_candidates_and_cancels_pending(world: World) -> None:
    await world.settings("off")
    await world.sample()
    worker = world.worker()
    await worker.run_once()
    assert await world.rows() == [] and world.requests == []


async def test_review_mode_lists_a_candidate_after_the_lookup_and_sends_nothing(
    world: World,
) -> None:
    await world.settings("review")
    await world.sample()
    intel = Intel(known=False)
    worker = world.worker(intel=intel)
    await worker.run_once()
    (row,) = await world.rows()
    assert (row.status, row.lookup, row.platform, row.value) == (
        "candidate",
        "unknown",
        "urlhaus",
        URL,
    )
    assert row.tags == ["mirai", "elf", "arm"]
    assert intel.calls == 1 and world.requests == []  # review: the admin clicks Submit


async def test_a_known_url_is_skipped_with_zero_submit_calls(world: World) -> None:
    await world.settings("auto")
    await world.sample()
    worker = world.worker(intel=Intel(known=True))
    await worker.run_once()
    (row,) = await world.rows()
    assert row.status == "skipped_known" and row.lookup == "known"
    assert row.reference == "https://urlhaus.abuse.ch/url/1/"
    assert world.requests == []


async def test_review_submit_sends_once_with_the_anonymous_flag(world: World) -> None:
    await world.settings("review", anonymous=True)
    await world.sample()
    worker = world.worker()
    await worker.run_once()
    (row,) = await world.rows()
    await world.approve(row.id)
    await worker.run_once()
    (row,) = await world.rows()
    assert row.status == "submitted" and row.result_code == "inserted"
    assert row.submitted_at is not None and row.started_at is not None
    (req,) = world.requests
    body = json.loads(req.content)
    assert body["anonymous"] == "1" and body["submission"][0]["url"] == URL
    assert req.headers["auth-key"] == KEY and KEY.encode() not in req.content
    await worker.run_once()
    assert len(world.requests) == 1  # a final row is never picked again


async def test_anonymous_off_is_honoured(world: World) -> None:
    await world.settings("review", anonymous=False)
    await world.sample()
    worker = world.worker()
    await worker.run_once()
    await world.approve((await world.rows())[0].id)
    await worker.run_once()
    assert json.loads(world.requests[0].content)["anonymous"] == "0"


async def test_a_url_with_the_monitored_address_is_guard_failed_and_never_sent(
    world: World,
) -> None:
    await world.settings("auto")
    await world.sample(f"http://files.example.net/x.sh?t={SELF}")
    worker = world.worker()
    await worker.run_once()
    (row,) = await world.rows()
    assert row.status == "guard_failed" and row.result_code.startswith("guard_failed:")
    assert world.requests == []


async def test_without_a_known_own_address_nothing_is_recorded_or_sent(world: World) -> None:
    await world.settings("auto")
    await world.sample()
    worker = world.worker(terms=Terms(with_self=False))
    await worker.run_once()
    assert await world.rows() == [] and world.requests == []  # fails closed, retried later


async def test_auto_mode_schedules_after_the_hold_and_respects_the_daily_cap(
    world: World,
) -> None:
    await world.settings("auto", hold=10, cap=1)
    await world.sample(URL)
    await world.sample("http://files.example.net/bins/mirai.mips")
    worker = world.worker()
    await worker.run_once()
    rows = await world.rows()
    assert [r.status for r in rows] == ["pending", "pending"] and all(r.auto for r in rows)
    assert world.requests == []  # held for ten minutes
    async with world.owner.begin() as conn:
        await conn.execute(
            text("UPDATE abusech_submissions SET scheduled_at = now() - interval '1 min'")
        )
    await worker.run_once()
    statuses = sorted(r.status for r in await world.rows())
    assert statuses == ["pending", "submitted"] and len(world.requests) == 1  # cap of 1 a day


async def test_a_claim_that_never_finished_is_failed_and_never_resent(world: World) -> None:
    await world.settings("review")
    async with world.owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO abusech_submissions (platform, ioc_type, value, threat, lookup) "
                "VALUES ('urlhaus', 'url', :u, 'malware_download', 'unknown')"
            ),
            {"u": URL},
        )
    await world.approve((await world.rows())[0].id)
    async with world.owner.begin() as conn:  # ingest died right after committing 'submitting'
        await conn.execute(
            text(
                "UPDATE abusech_submissions SET status = 'submitting', "
                "started_at = now() - interval '10 minutes'"
            )
        )
    worker = world.worker()
    await worker.run_once()
    (row,) = await world.rows()
    assert (row.status, row.result_code) == ("failed", "unknown_outcome")
    await worker.run_once()
    assert world.requests == []


async def test_a_closed_gate_keeps_the_row_pending_and_sends_nothing(world: World) -> None:
    await world.settings("review")
    await world.sample()
    ok = world.worker()
    await ok.run_once()
    await world.approve((await world.rows())[0].id)
    closed = world.worker(open_=False)
    await closed.run_once()
    (row,) = await world.rows()
    assert row.status == "pending" and row.started_at is None
    assert world.requests == []


async def test_an_error_answer_is_final_and_not_retried(world: World) -> None:
    await world.settings("review")
    await world.sample()
    world.answer = {"query_status": "invalid_url"}
    worker = world.worker()
    await worker.run_once()
    await world.approve((await world.rows())[0].id)
    await worker.run_once()
    (row,) = await world.rows()
    assert (row.status, row.result_code) == ("rejected", "invalid")
    await worker.run_once()
    assert len(world.requests) == 1


async def test_demo_and_html_pages_are_not_candidates(world: World) -> None:
    await world.settings("review")
    await world.sample(kind="text")
    worker = world.worker()
    await worker.run_once()
    assert await world.rows() == []


async def test_the_key_never_reaches_a_row(world: World) -> None:
    await world.settings("review")
    await world.sample()
    worker = world.worker()
    await worker.run_once()
    await world.approve((await world.rows())[0].id)
    await worker.run_once()
    dump = json.dumps([dict(r._mapping) for r in await world.rows()], default=str)
    assert KEY not in dump
    status = json.dumps(await worker.status(), default=str)
    assert KEY not in status


async def test_threatfox_needs_its_switch_and_a_malpedia_family(world: World) -> None:
    await world.settings("review", threatfox=False)
    async with world.owner.begin() as conn:
        await world.sample()
        await conn.execute(
            text(
                "INSERT INTO sample_links (sha256, kind, value, port, source, confidence) "
                "VALUES (:s, 'c2_ip', '203.0.113.9', 4444, 'strings', 'high')"
            ),
            {"s": SHA},
        )
    worker = world.worker()
    await worker.run_once()
    assert {r.platform for r in await world.rows()} == {"urlhaus"}

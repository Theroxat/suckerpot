"""Threat-intel worker: request shape, answer parsing, bounds, quotas, caching, no key leaks."""

import logging
import os
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from ingest.enrichment import EnrichmentSettings
from ingest.enrichment import intel as intel_mod
from ingest.enrichment.credentials import CredentialSync, changed_providers
from ingest.enrichment.intel import (
    ALLOWED_HOSTS,
    MAX_BODY,
    IntelWorker,
    clean,
    clean_tags,
    eligible,
    parse_when,
)
from ingest.enrichment.reputation import ProviderError

AB_KEY = "placeholder-abusech-" + "0" * 12
VT_KEY = "placeholder-virustotal-" + "0" * 12
SHA = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
SETTINGS = EnrichmentSettings.from_env({"ABUSECH_AUTH_KEY": AB_KEY, "VIRUSTOTAL_API_KEY": VT_KEY})


@pytest.fixture(autouse=True)
def no_rate_gap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(intel_mod, "MIN_GAP_S", {})


class Remote:
    """A fake intel backend that records every request it receives."""

    def __init__(self, handler: Any = None) -> None:
        self.requests: list[httpx.Request] = []
        self.handler = handler or (
            lambda req: httpx.Response(200, json={"query_status": "no_results"})
        )

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.handler(request)

    def worker(self, settings: EnrichmentSettings = SETTINGS, factory: Any = None) -> IntelWorker:
        client = httpx.AsyncClient(transport=httpx.MockTransport(self), follow_redirects=False)
        return IntelWorker(factory or MagicMock(), settings, client)


# ---- helpers ----------------------------------------------------------------------------------------


def test_clean_text_is_printable_and_bounded() -> None:
    assert clean("Mirai <script>alert(1)</script>\x00\n", 64) == "Mirai scriptalert(1)/script"
    assert clean("x" * 500, 10) == "x" * 10
    assert clean(None, 10) is None and clean(5, 10) is None and clean("<>", 10) is None
    assert clean_tags(["Mirai", "mirai", "<b>", "x" * 99, 7, None]) == ("mirai", "b", "x" * 32)
    assert len(clean_tags([f"t{i}" for i in range(50)])) == 8


def test_parse_when() -> None:
    assert parse_when("2026-10-20 12:30:00 UTC") == datetime(2026, 10, 20, 12, 30, tzinfo=UTC)
    assert parse_when(1_760_000_000) == datetime.fromtimestamp(1_760_000_000, UTC)
    assert parse_when("garbage") is None and parse_when(10**30) is None and parse_when(True) is None


def test_only_public_values_are_eligible() -> None:
    assert eligible("domain", "files.badhost.ru")
    assert eligible("ip", "8.8.4.4")
    assert eligible("url", "http://files.badhost.ru/a.sh")
    assert eligible("hash", SHA)
    for kind, value in [
        ("ip", "203.0.113.9"),
        ("domain", "files.example.net"),
        ("url", "http://203.0.113.9/a"),
        ("hash", "xyz"),
        ("domain", "intranet"),
    ]:
        assert not eligible(kind, value), value


def test_api_hosts_are_a_fixed_allow_list() -> None:
    assert ALLOWED_HOSTS == {"urlhaus-api.abuse.ch", "threatfox-api.abuse.ch", "www.virustotal.com"}


def test_key_change_detection_covers_the_new_providers() -> None:
    other = EnrichmentSettings.from_env({"ABUSECH_AUTH_KEY": "x" * 20})
    assert changed_providers(SETTINGS, other) == {"abusech", "virustotal"}


def test_settings_repr_hides_the_new_keys() -> None:
    assert AB_KEY not in repr(SETTINGS) and VT_KEY not in repr(SETTINGS)


# ---- URLhaus ---------------------------------------------------------------------------------------


async def test_urlhaus_url_lookup_sends_only_the_value_and_the_key() -> None:
    def answer(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "query_status": "ok",
                "threat": "malware_download",
                "date_added": "2026-10-20 12:00:00 UTC",
                "urlhaus_reference": "https://urlhaus.abuse.ch/url/123/",
                "tags": ["elf", "Mirai"],
                "payloads": [{"signature": "Mirai"}],
            },
        )

    remote = Remote(answer)
    res = await remote.worker().urlhaus("url", "http://files.badhost.ru/a.sh")
    assert res.known and res.family == "Mirai" and res.threat_type == "malware_download"
    assert res.tags == ("elf", "mirai")
    assert res.reference == "https://urlhaus.abuse.ch/url/123/"
    assert res.first_seen_ext == datetime(2026, 10, 20, 12, tzinfo=UTC)
    (req,) = remote.requests
    assert req.url.host == "urlhaus-api.abuse.ch" and req.method == "POST"
    assert req.headers["Auth-Key"] == AB_KEY
    assert req.content == b"url=http%3A%2F%2Ffiles.badhost.ru%2Fa.sh"


async def test_urlhaus_host_and_payload_queries() -> None:
    def answer(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "query_status": "ok",
                "firstseen": "2026-10-01 00:00:00 UTC",
                "urlhaus_reference": "https://evil.example/phish",  # not an abuse.ch link
                "urls": [{"tags": ["Mirai", "elf"]}, {"tags": None}],
                "signature": "Gafgyt",
                "file_type": "elf",
            },
        )

    remote = Remote(answer)
    worker = remote.worker()
    host = await worker.urlhaus("domain", "files.badhost.ru")
    assert host.known and host.tags == ("mirai", "elf") and host.reference is None
    payload = await worker.urlhaus("hash", SHA)
    assert payload.family == "Gafgyt"
    assert [r.content for r in remote.requests] == [
        b"host=files.badhost.ru",
        f"sha256_hash={SHA}".encode(),
    ]
    await worker.urlhaus("hash", "ab" * 16)
    assert remote.requests[-1].content == b"md5_hash=" + b"ab" * 16


async def test_urlhaus_not_found_is_a_negative_answer() -> None:
    res = await Remote().worker().urlhaus("domain", "files.badhost.ru")
    assert not res.known and res.family is None


# ---- ThreatFox ---------------------------------------------------------------------------------------


async def test_threatfox_matches_only_the_exact_host() -> None:
    def answer(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "query_status": "ok",
                "data": [
                    {"id": "9", "ioc": "8.8.4.40:80", "malware_printable": "Other"},
                    {
                        "id": "1234",
                        "ioc": "8.8.4.4:4444",
                        "threat_type": "botnet_cc",
                        "malware_printable": "Cobalt Strike",
                        "first_seen_utc": "2026-10-02 03:04:05",
                        "tags": ["c2"],
                        "reference": "https://evil.example/steal",
                    },
                ],
            },
        )

    remote = Remote(answer)
    res = await remote.worker().threatfox("ip", "8.8.4.4")
    assert res.known and res.family == "Cobalt Strike" and res.threat_type == "botnet_cc"
    assert (
        res.reference == "https://threatfox.abuse.ch/ioc/1234/"
    )  # built here, not taken from the answer
    (req,) = remote.requests
    assert req.headers["Auth-Key"] == AB_KEY
    assert req.read() == b'{"query":"search_ioc","search_term":"8.8.4.4","exact_match":false}'
    miss = (
        await Remote(
            lambda r: httpx.Response(
                200, json={"query_status": "ok", "data": [{"id": "1", "ioc": "8.8.4.41:1"}]}
            )
        )
        .worker()
        .threatfox("ip", "8.8.4.4")
    )
    assert not miss.known


async def test_threatfox_hash_and_no_result() -> None:
    remote = Remote(lambda r: httpx.Response(200, json={"query_status": "no_result", "data": "x"}))
    res = await remote.worker().threatfox("hash", SHA)
    assert not res.known
    assert remote.requests[0].read() == f'{{"query":"search_hash","hash":"{SHA}"}}'.encode()


# ---- VirusTotal -----------------------------------------------------------------------------------------


async def test_virustotal_hash_lookup() -> None:
    def answer(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 41, "suspicious": 1},
                        "popular_threat_classification": {
                            "suggested_threat_label": "trojan.mirai/gafgyt",
                            "popular_threat_category": [{"value": "trojan"}],
                        },
                        "first_submission_date": 1_760_000_000,
                        "tags": ["elf", "upx"],
                    }
                }
            },
        )

    remote = Remote(answer)
    res = await remote.worker().virustotal(SHA)
    assert res.known and res.family == "trojan.mirai/gafgyt" and res.threat_type == "trojan"
    assert res.reference == f"https://www.virustotal.com/gui/file/{SHA}"
    (req,) = remote.requests
    assert req.method == "GET" and str(req.url) == f"https://www.virustotal.com/api/v3/files/{SHA}"
    assert req.headers["x-apikey"] == VT_KEY
    assert req.content == b""


async def test_virustotal_unknown_hash_and_bad_input() -> None:
    worker = Remote(
        lambda r: httpx.Response(404, json={"error": {"code": "NotFoundError"}})
    ).worker()
    assert not (await worker.virustotal(SHA)).known
    for bad in ("../../x", SHA + "/..", "G" * 64, ""):
        with pytest.raises(ProviderError):
            await worker.virustotal(bad)


# ---- hard limits --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "kind"),
    [(401, "auth"), (403, "auth"), (429, "rate_limited"), (500, "error"), (302, "error")],
)
async def test_error_statuses_never_follow_redirects(status: int, kind: str) -> None:
    remote = Remote(lambda r: httpx.Response(status, headers={"Location": "http://203.0.113.9/x"}))
    with pytest.raises(ProviderError) as exc:
        await remote.worker().urlhaus("domain", "files.badhost.ru")
    assert exc.value.kind == kind
    assert len(remote.requests) == 1  # the redirect target was never requested


async def test_oversize_and_garbage_bodies_are_errors() -> None:
    big = Remote(lambda r: httpx.Response(200, content=b"x" * (MAX_BODY + 1)))
    with pytest.raises(ProviderError):
        await big.worker().urlhaus("domain", "files.badhost.ru")
    junk = Remote(lambda r: httpx.Response(200, content=b"<html>"))
    with pytest.raises(ProviderError):
        await junk.worker().threatfox("ip", "8.8.4.4")
    odd = Remote(lambda r: httpx.Response(200, json=["not", "a", "dict"]))
    with pytest.raises(ProviderError):
        await odd.worker().urlhaus("domain", "files.badhost.ru")


async def test_unauthorised_query_status_is_an_auth_error() -> None:
    remote = Remote(lambda r: httpx.Response(200, json={"query_status": "unauthorized"}))
    with pytest.raises(ProviderError) as exc:
        await remote.worker().urlhaus("domain", "files.badhost.ru")
    assert exc.value.kind == "auth"


async def test_a_request_to_an_unlisted_host_is_refused() -> None:
    remote = Remote()
    with pytest.raises(ProviderError):
        await remote.worker()._request("abusech", "GET", "https://evil.example/x", headers={})
    assert remote.requests == []


async def test_errors_and_logs_do_not_contain_keys(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    remote = Remote(lambda r: httpx.Response(401))
    with pytest.raises(ProviderError) as exc:
        await remote.worker().urlhaus("domain", "files.badhost.ru")
    assert AB_KEY not in str(exc.value) and AB_KEY not in repr(exc.value)
    assert AB_KEY not in caplog.text and VT_KEY not in caplog.text


# ---- key test -----------------------------------------------------------------------------------------------


@pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set")
@pytest.mark.integration
class TestWithDatabase:
    async def seed(self, engine: AsyncEngine) -> None:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO indicators (type, value, role, first_seen, last_seen, sightings) "
                    "VALUES ('domain', 'files.badhost.ru', 'download_host', now(), now(), 9), "
                    "('url', 'http://files.badhost.ru/a.sh', 'download_host', now(), now(), 5), "
                    "('domain', 'files.example.net', 'download_host', now(), now(), 4), "
                    "('hash', :sha, 'hash', now(), now(), 3)"
                ),
                {"sha": SHA},
            )

    async def used(self, engine: AsyncEngine, provider: str) -> int:
        async with engine.connect() as conn:
            return int(
                await conn.scalar(
                    text("SELECT COALESCE(sum(used), 0) FROM enrichment_quota WHERE provider = :p"),
                    {"p": provider},
                )
                or 0
            )

    async def test_cycle_stores_answers_spends_quota_and_caches_for_24h(
        self, engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await self.seed(engine)

        def answer(req: httpx.Request) -> httpx.Response:
            if req.url.host == "www.virustotal.com":
                return httpx.Response(404)
            return httpx.Response(200, json={"query_status": "no_results"})

        remote = Remote(answer)
        worker = remote.worker(factory=factory)
        made = await worker.run_once()
        # 3 eligible indicators x 2 abuse.ch sources + 1 VirusTotal; the example.net one is skipped.
        assert made == 7 and len(remote.requests) == 7
        assert {r.url.host for r in remote.requests} == ALLOWED_HOSTS
        sent = b"".join(r.read() for r in remote.requests)
        assert b"example.net" not in sent
        assert (
            await self.used(engine, "abusech") == 6 and await self.used(engine, "virustotal") == 1
        )
        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    text(
                        "SELECT i.value, n.source, n.known, n.tags FROM indicator_intel n "
                        "JOIN indicators i ON i.id = n.indicator_id ORDER BY 1, 2"
                    )
                )
            ).all()
        # 3 eligible x (urlhaus + threatfox), 1 VirusTotal, 2 "not-checked" markers
        assert len(rows) == 9
        skipped = [r for r in rows if r.value == "files.example.net"]
        assert {r.source for r in skipped} == {"urlhaus", "threatfox"}
        assert all(r.tags == ["not-checked"] and not r.known for r in skipped)
        # A second cycle within 24 h makes no request at all.
        before = len(remote.requests)
        assert await worker.run_once() == 0
        assert len(remote.requests) == before
        # ...but an answer older than 24 h is refreshed.
        async with engine.begin() as conn:
            await conn.execute(
                text("UPDATE indicator_intel SET checked_at = now() - interval '25 hours'")
            )
        assert await worker.run_once() == 7

    async def test_daily_quota_is_a_hard_cap(
        self, engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await self.seed(engine)
        capped = EnrichmentSettings.from_env(
            {"ABUSECH_AUTH_KEY": AB_KEY, "ABUSECH_DAILY_QUOTA": "3", "VIRUSTOTAL_API_KEY": VT_KEY}
        )
        remote = Remote()
        worker = remote.worker(capped, factory)
        await worker.run_once()
        abuse_calls = [r for r in remote.requests if r.url.host != "www.virustotal.com"]
        assert len(abuse_calls) == 3 and await self.used(engine, "abusech") == 3
        assert await worker.run_once() == 0  # paused until the quota resets

    async def test_no_key_means_no_request(
        self, engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await self.seed(engine)
        remote = Remote()
        worker = remote.worker(EnrichmentSettings.from_env({}), factory)
        assert await worker.run_once() == 0 and remote.requests == []

    async def test_virustotal_only_receives_hashes(
        self, engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await self.seed(engine)
        remote = Remote(lambda r: httpx.Response(404))
        worker = remote.worker(EnrichmentSettings.from_env({"VIRUSTOTAL_API_KEY": VT_KEY}), factory)
        assert await worker.run_once() == 1
        (req,) = remote.requests
        assert req.url.path.endswith(SHA)

    async def test_rejected_key_disables_the_provider_and_a_new_key_clears_it(
        self, engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await self.seed(engine)
        remote = Remote(lambda r: httpx.Response(401))
        worker = remote.worker(factory=factory)
        await worker.run_once()
        assert worker.state.disabled == {"abusech": "auth", "virustotal": "auth"}
        n = len(remote.requests)
        assert n == 2 and await worker.run_once() == 0
        status = await worker.status()
        assert status["abusech"]["disabled"] == "auth"
        assert AB_KEY not in repr(status) and VT_KEY not in repr(status)
        worker.apply_settings(SETTINGS, {"abusech"})
        assert "abusech" not in worker.state.disabled and "virustotal" in worker.state.disabled

    async def test_rate_limit_pauses_the_provider(
        self, engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await self.seed(engine)
        remote = Remote(lambda r: httpx.Response(429))
        worker = remote.worker(factory=factory)
        await worker.run_once()
        assert (await worker.status())["abusech"]["paused"] is True
        assert (await worker.status())["abusech"]["last_error"] == "rate_limited"
        assert len(remote.requests) == 2  # one per provider, then paused

    async def test_key_test_spends_one_unit_and_reports(
        self, engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        remote = Remote()
        worker = remote.worker(factory=factory)
        res = await worker.run_key_test("abusech")
        assert res["ok"] and res["error"] is None
        assert await self.used(engine, "abusech") == 1
        assert remote.requests[0].content == b"host=example.com"
        bad = Remote(lambda r: httpx.Response(403))
        res = await bad.worker(factory=factory).run_key_test("virustotal")
        assert not res["ok"] and res["error"] == "auth"
        none = (
            await Remote().worker(EnrichmentSettings.from_env({}), factory).run_key_test("abusech")
        )
        assert none["error"] == "no_key"

    async def test_credentials_from_settings_reach_the_worker(
        self, engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
    ) -> None:
        from suckerpot_db.secretbox import Credential, SecretBox

        box = SecretBox(bytes(range(32)))
        ct, nonce = box.encrypt("abusech", Credential("settings-abusech-key-0001"))
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO provider_secrets (provider, ciphertext, nonce, last4, updated_by) "
                    "VALUES ('abusech', :c, :n, '0001', 'admin')"
                ),
                {"c": ct, "n": nonce},
            )
        worker = Remote().worker(EnrichmentSettings.from_env({}), factory)
        sync = CredentialSync(
            factory,
            EnrichmentSettings.from_env({}),
            box,
            on_change=worker.apply_settings,
            client=MagicMock(),
        )
        assert await sync.sync_once() == {"abusech"}
        assert worker.enabled("abusech") and not worker.enabled("virustotal")
        assert sync.info["abusech"].source == "settings"

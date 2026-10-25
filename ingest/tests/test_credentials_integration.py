"""Settings-managed provider keys against a real TimescaleDB: sync, key tests, grants."""

import os
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from suckerpot_db import create_engine
from suckerpot_db.secretbox import Credential, SecretBox

from ingest.enrichment import EnrichmentSettings
from ingest.enrichment.credentials import CredentialSync
from ingest.enrichment.reputation import ReputationWorker

from .db_fixtures import _role_url

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]

BOX = SecretBox(bytes(range(32)))
ENV_VALUE = "envkeyenvkeyenvkey0001"
SET_VALUE = "settingskeysettingskey2"


async def put_row(engine: AsyncEngine, provider: str, key: str) -> None:
    ct, nonce = BOX.encrypt(provider, Credential(key))
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO provider_secrets (provider, ciphertext, nonce, last4, updated_by) "
                "VALUES (:p, :c, :n, :l, 'admin') ON CONFLICT (provider) DO UPDATE "
                "SET ciphertext = :c, nonce = :n, last4 = :l, updated_at = now()"
            ),
            {"p": provider, "c": ct, "n": nonce, "l": key[-4:]},
        )


async def test_sync_hot_swaps_and_falls_back_to_env(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    changes: list[tuple[str, set[str]]] = []
    base = EnrichmentSettings.from_env({"ABUSEIPDB_API_KEY": ENV_VALUE})
    s = CredentialSync(
        factory,
        base,
        BOX,
        on_change=lambda eff, ch: changes.append((eff.abuseipdb_api_key, ch)),
        client=MagicMock(),
    )
    assert await s.sync_once() == set()
    await put_row(engine, "abuseipdb", SET_VALUE)
    assert await s.sync_once() == {"abuseipdb"}
    assert s.current.abuseipdb_api_key == SET_VALUE and s.info["abuseipdb"].source == "settings"
    assert await s.sync_once() == set()  # stable
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM provider_secrets"))
    assert await s.sync_once() == {"abuseipdb"}
    assert changes == [(SET_VALUE, {"abuseipdb"}), (ENV_VALUE, {"abuseipdb"})]
    assert s.info["abuseipdb"].source == "env"


async def test_key_test_requests_are_answered_once(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    calls: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        return httpx.Response(200, json={"data": {"abuseConfidenceScore": 3, "totalReports": 0}})

    base = EnrichmentSettings.from_env({"ABUSEIPDB_API_KEY": ENV_VALUE})
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    worker = ReputationWorker(factory, base, client)
    s = CredentialSync(factory, base, BOX, on_change=worker.apply_settings, client=MagicMock())

    async def run_test(provider: str) -> None:
        await worker.run_key_test(provider)

    s.run_test = run_test
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO provider_test_requests (provider, requested_by) "
                "VALUES ('abuseipdb', 'admin')"
            )
        )
    await s.sync_once()
    await s.sync_once()  # already handled: no second call, no second quota unit
    assert len(calls) == 1
    result: dict[str, Any] = worker.test_result["abuseipdb"]
    assert result["ok"] is True and result["error"] is None and result["checked_at"]
    async with engine.connect() as conn:
        used = await conn.scalar(
            text("SELECT used FROM enrichment_quota WHERE provider = 'abuseipdb'")
        )
    assert used == 1
    async with engine.begin() as conn:  # a new click is answered again
        await conn.execute(
            text("UPDATE provider_test_requests SET requested_at = now() + interval '1 second'")
        )
    await s.sync_once()
    assert len(calls) == 2


async def test_ingest_role_reads_but_never_writes_secrets(
    engine: AsyncEngine, factory: async_sessionmaker[AsyncSession]
) -> None:
    await put_row(engine, "greynoise", SET_VALUE)
    stmts = (
        "DELETE FROM provider_secrets",
        "UPDATE provider_secrets SET last4 = 'xxxx'",
        "INSERT INTO provider_secrets (provider, ciphertext, nonce, last4, updated_by) "
        "VALUES ('abuseipdb', '\\x00', '\\x000000000000000000000000', 'abcd', 'x')",
    )
    async with factory() as s:
        assert await s.scalar(text("SELECT count(*) FROM provider_secrets")) == 1
    for stmt in stmts:
        async with factory() as s:
            with pytest.raises(DBAPIError):
                await s.execute(text(stmt))
    api = create_engine(_role_url("API"), pool_size=1)
    try:
        async with api.begin() as conn:  # the API role manages the keys
            await conn.execute(text("DELETE FROM provider_secrets"))
    finally:
        await api.dispose()

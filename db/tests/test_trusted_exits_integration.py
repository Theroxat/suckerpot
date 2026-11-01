"""M23 schema: the trusted exit table, its cap of 8 rows and exactly the grants of each role."""

import os
import subprocess
import sys
from collections.abc import AsyncIterator, Mapping
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from suckerpot_db import database_url_from_env
from suckerpot_db.roles import apply_roles

pytestmark = pytest.mark.integration

DB_DIR = Path(os.environ.get("DB_DIR", Path(__file__).resolve().parents[1]))
ENV: dict[str, str] = {
    **os.environ,
    "POSTGRES_INGEST_USER": os.environ.get("POSTGRES_INGEST_USER", "suckerpot_ingest"),
    "POSTGRES_INGEST_PASSWORD": os.environ.get("POSTGRES_INGEST_PASSWORD", "ingest-test-password"),
    "POSTGRES_API_USER": os.environ.get("POSTGRES_API_USER", "suckerpot_api"),
    "POSTGRES_API_PASSWORD": os.environ.get("POSTGRES_API_PASSWORD", "api-test-password"),
    "POSTGRES_COLLECTOR_PASSWORD": "collector-test-password",
    "POSTGRES_ANALYZER_PASSWORD": "analyzer-test-password",
}
INSERT = "INSERT INTO egress_trusted_exits (cidr, created_by) VALUES (:c, 'tester')"


def _alembic(*args: str) -> None:
    subprocess.run(  # noqa: S603
        [sys.executable, "-m", "alembic", *args], cwd=DB_DIR, env=ENV, check=True, timeout=180
    )


async def _roles(env: Mapping[str, str]) -> None:
    engine = create_async_engine(database_url_from_env(env))
    try:
        async with engine.begin() as conn:
            await conn.run_sync(lambda c: apply_roles(c, env))
    finally:
        await engine.dispose()


def _as(user: str, password: str) -> AsyncEngine:
    return create_async_engine(
        database_url_from_env({**ENV, "POSTGRES_USER": user, "POSTGRES_PASSWORD": password})
    )


@pytest.fixture
async def owner() -> AsyncIterator[AsyncEngine]:
    _alembic("upgrade", "head")
    await _roles(ENV)
    await _roles(ENV)  # idempotent
    engine = create_async_engine(database_url_from_env(ENV))
    async with engine.begin() as conn:
        await conn.execute(text("TRUNCATE egress_trusted_exits"))
    yield engine
    await engine.dispose()


async def _can(engine: AsyncEngine, sql: str, params: dict[str, object] | None = None) -> bool:
    try:
        async with engine.begin() as conn:
            await conn.execute(text(sql), params or {})
    except DBAPIError as exc:
        assert getattr(exc.orig, "sqlstate", None) == "42501", exc  # insufficient_privilege
        return False
    return True


async def _sqlstate(engine: AsyncEngine, sql: str, params: dict[str, object]) -> str | None:
    try:
        async with engine.begin() as conn:
            await conn.execute(text(sql), params)
    except DBAPIError as exc:
        return getattr(exc.orig, "sqlstate", None)
    return None


async def test_down_and_up_again(owner: AsyncEngine) -> None:
    async def exists() -> bool:
        async with owner.connect() as conn:
            return bool(
                await conn.scalar(text("SELECT to_regclass('egress_trusted_exits') IS NOT NULL"))
            )

    assert await exists()
    _alembic("downgrade", "0019")
    assert not await exists()
    _alembic("upgrade", "head")
    assert await exists()
    await _roles(ENV)


async def test_grants_per_role(owner: AsyncEngine) -> None:
    api = _as(ENV["POSTGRES_API_USER"], ENV["POSTGRES_API_PASSWORD"])
    ingest = _as(ENV["POSTGRES_INGEST_USER"], ENV["POSTGRES_INGEST_PASSWORD"])
    collector = _as("suckerpot_collector", ENV["POSTGRES_COLLECTOR_PASSWORD"])
    analyzer = _as("suckerpot_analyzer", ENV["POSTGRES_ANALYZER_PASSWORD"])
    try:
        assert await _can(api, INSERT, {"c": "198.51.100.0/24"})
        assert await _can(api, "SELECT cidr FROM egress_trusted_exits")
        for reader in (ingest, collector):
            assert await _can(reader, "SELECT cidr FROM egress_trusted_exits")
            assert not await _can(reader, INSERT, {"c": "203.0.113.0/24"})
            assert not await _can(reader, "DELETE FROM egress_trusted_exits")
            assert not await _can(reader, "UPDATE egress_trusted_exits SET created_by = 'x'")
        assert not await _can(api, "UPDATE egress_trusted_exits SET created_by = 'x'")
        assert not await _can(analyzer, "SELECT cidr FROM egress_trusted_exits")
        assert await _can(api, "DELETE FROM egress_trusted_exits")
    finally:
        for engine in (api, ingest, collector, analyzer):
            await engine.dispose()


async def test_unique_and_at_most_eight_rows(owner: AsyncEngine) -> None:
    api = _as(ENV["POSTGRES_API_USER"], ENV["POSTGRES_API_PASSWORD"])
    try:
        for n in range(8):
            assert await _sqlstate(api, INSERT, {"c": f"198.51.{n}.0/24"}) is None
        assert await _sqlstate(api, INSERT, {"c": "203.0.113.0/24"}) == "23514"
        async with owner.begin() as conn:
            await conn.execute(
                text(
                    "DELETE FROM egress_trusted_exits "
                    "WHERE id = (SELECT min(id) FROM egress_trusted_exits)"
                )
            )
        assert await _sqlstate(api, INSERT, {"c": "203.0.113.0/24"}) is None
        # A duplicate is refused (the cap check runs first once the table is full again).
        async with owner.begin() as conn:
            await conn.execute(
                text("DELETE FROM egress_trusted_exits WHERE cidr = '203.0.113.0/24'")
            )
        assert await _sqlstate(api, INSERT, {"c": "198.51.3.0/24"}) == "23505"
    finally:
        await api.dispose()

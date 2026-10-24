"""Shared integration fixtures: a migrated TimescaleDB plus the owner and role connections."""

import asyncio
import os
import subprocess
import sys
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from suckerpot_db import create_engine, create_session_factory, database_url_from_env
from suckerpot_db.diskguard import apply_disk_guard
from suckerpot_db.retention import apply_retention
from suckerpot_db.roles import apply_roles

DB_DIR = Path(os.environ.get("DB_DIR", Path(__file__).resolve().parents[2] / "db"))


# Role names and passwords come from the environment when set (CI), else these defaults.
ROLE_ENV = {
    key: os.environ.get(key, default)
    for key, default in {
        "POSTGRES_INGEST_USER": "suckerpot_ingest",
        "POSTGRES_INGEST_PASSWORD": "ingest pw/with:odd@chars",
        "POSTGRES_API_USER": "suckerpot_api",
        "POSTGRES_API_PASSWORD": "api-test-password",
    }.items()
}


def _role_url(kind: str) -> str:
    return database_url_from_env(
        {
            **os.environ,
            "POSTGRES_USER": ROLE_ENV[f"POSTGRES_{kind}_USER"],
            "POSTGRES_PASSWORD": ROLE_ENV[f"POSTGRES_{kind}_PASSWORD"],
        }
    )


def _migrate(extra_env: dict[str, str] | None = None) -> None:
    """Bring the DB to head and (re)apply the roles, whatever state it was in before."""
    env = {**os.environ, **ROLE_ENV, **(extra_env or {})}
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=DB_DIR,
        env=env,
        check=True,
        timeout=120,
    )

    async def apply() -> None:
        engine = create_async_engine(database_url_from_env(env))
        try:
            async with engine.begin() as conn:
                await conn.run_sync(lambda c: apply_roles(c, env))
        finally:
            await engine.dispose()
        # Same as the migrate entrypoint: retention policies on an autocommit connection.
        engine = create_async_engine(database_url_from_env(env), isolation_level="AUTOCOMMIT")
        try:
            async with engine.connect() as conn:
                await conn.run_sync(lambda c: apply_retention(c, env))
                await conn.run_sync(lambda c: apply_disk_guard(c, env))
        finally:
            await engine.dispose()

    # Own thread: callable from sync fixtures and from running event loops alike.
    with ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(asyncio.run, apply()).result()


@pytest.fixture(scope="session")
def migrated() -> None:
    _migrate()
    _migrate()  # second run proves idempotence


@pytest.fixture
async def engine(migrated: None) -> AsyncIterator[AsyncEngine]:
    """Owner connection (test setup only)."""
    eng = create_engine(pool_size=2)
    async with eng.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE events, sessions, ip_reputation, enrichment_quota, "
                "enrichment_status, sessions_daily, system_status, maintenance_log"
            )
        )
    yield eng
    await eng.dispose()


@pytest.fixture
async def factory(engine: AsyncEngine) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """Writer connections AS the ingest role."""
    eng = create_engine(_role_url("INGEST"), pool_size=2)
    yield create_session_factory(eng)
    await eng.dispose()

"""Migration 0006 goes down and up again, and the grants follow the tables.

Named test_zz_* on purpose: re-running the migrations re-schedules the TimescaleDB maintenance job,
which must not fire while the retention tests drive that job by hand. This file runs last.
"""

import os
import subprocess
import sys

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from .db_fixtures import DB_DIR, ROLE_ENV, _migrate

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("POSTGRES_HOST"), reason="POSTGRES_HOST not set"),
]


def alembic(*args: str) -> None:
    subprocess.run(  # noqa: S603
        [sys.executable, "-m", "alembic", *args],
        cwd=DB_DIR,
        env={**os.environ, **ROLE_ENV},
        check=True,
        timeout=120,
    )


async def has_table(engine: AsyncEngine, name: str) -> bool:
    async with engine.connect() as conn:
        return bool(await conn.scalar(text("SELECT to_regclass(:n) IS NOT NULL"), {"n": name}))


async def priv(engine: AsyncEngine, role: str, table: str, privilege: str) -> bool:
    async with engine.connect() as conn:
        return bool(
            await conn.scalar(
                text("SELECT has_table_privilege(:r, :t, :p)"),
                {"r": role, "t": table, "p": privilege},
            )
        )


async def test_up_down_up_and_grants(engine: AsyncEngine) -> None:
    assert await has_table(engine, "provider_secrets")
    api, ingest = ROLE_ENV["POSTGRES_API_USER"], ROLE_ENV["POSTGRES_INGEST_USER"]
    for p in ("SELECT", "INSERT", "UPDATE", "DELETE"):
        assert await priv(engine, api, "provider_secrets", p)
    assert await priv(engine, ingest, "provider_secrets", "SELECT")
    for p in ("INSERT", "UPDATE", "DELETE", "TRUNCATE"):
        assert not await priv(engine, ingest, "provider_secrets", p)
    assert await priv(engine, ingest, "provider_test_requests", "UPDATE")
    assert not await priv(engine, ingest, "provider_test_requests", "INSERT")

    alembic("downgrade", "0005")
    assert not await has_table(engine, "provider_secrets")
    assert not await has_table(engine, "provider_test_requests")
    assert await has_table(engine, "enrichment_status")  # earlier tables untouched

    _migrate()  # upgrade head + roles again
    assert await has_table(engine, "provider_secrets")
    assert await priv(engine, api, "provider_secrets", "DELETE")

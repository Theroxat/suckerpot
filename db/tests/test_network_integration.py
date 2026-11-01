"""M29 schema against a real TimescaleDB: roles are confined, the membership trigger holds (N7)."""

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
# ruff: noqa: S608, ASYNC221  (test SQL is built from constants; alembic runs once)

DB_DIR = Path(os.environ.get("DB_DIR", Path(__file__).resolve().parents[1]))
ENV: dict[str, str] = {
    **os.environ,
    "POSTGRES_INGEST_USER": os.environ.get("POSTGRES_INGEST_USER", "suckerpot_ingest"),
    "POSTGRES_INGEST_PASSWORD": os.environ.get("POSTGRES_INGEST_PASSWORD", "ingest-test-password"),
    "POSTGRES_API_USER": os.environ.get("POSTGRES_API_USER", "suckerpot_api"),
    "POSTGRES_API_PASSWORD": os.environ.get("POSTGRES_API_PASSWORD", "api-test-password"),
}
RESET = (
    "UPDATE network_membership SET desired = 'off', state = 'off', pseudonym = NULL, "
    "privkey_enc = NULL, privkey_nonce = NULL, pubkey = NULL, node_id = NULL",
    "DELETE FROM network_submissions",
    "DELETE FROM network_targets",
    "DELETE FROM network_summary",
)
TARGET = (
    "INSERT INTO network_targets (hub_id, kind, value, state, nodes, first_day, last_day) "
    "VALUES ('t_000000000002', 'ip', '198.51.100.2', 'confirmed', 0, current_date, current_date)"
)


def _as(user: str, password: str) -> AsyncEngine:
    return create_async_engine(
        database_url_from_env({**ENV, "POSTGRES_USER": user, "POSTGRES_PASSWORD": password})
    )


async def _run(
    engine: AsyncEngine, sql: str, params: Mapping[str, object] | None = None
) -> int | None:
    """Row count, or None when refused (privilege or trigger)."""
    try:
        async with engine.begin() as conn:
            return (await conn.execute(text(sql), params or {})).rowcount
    except DBAPIError:
        return None


@pytest.fixture
async def rig() -> AsyncIterator[tuple[AsyncEngine, AsyncEngine, AsyncEngine]]:
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=DB_DIR,
        env=ENV,
        check=True,
        timeout=180,
    )
    owner = create_async_engine(database_url_from_env(ENV))
    async with owner.begin() as conn:
        await conn.run_sync(lambda c: apply_roles(c, ENV))
        for sql in RESET:
            await conn.execute(text(sql))
    api = _as(ENV["POSTGRES_API_USER"], ENV["POSTGRES_API_PASSWORD"])
    ingest = _as(ENV["POSTGRES_INGEST_USER"], ENV["POSTGRES_INGEST_PASSWORD"])
    yield owner, api, ingest
    await owner.dispose()
    await api.dispose()
    await ingest.dispose()


async def test_the_membership_row_is_seeded_once(rig: tuple[AsyncEngine, ...]) -> None:
    owner, _api, _ingest = rig
    async with owner.connect() as conn:
        assert await conn.scalar(text("SELECT count(*) FROM network_membership")) == 1
    assert await _run(owner, "INSERT INTO network_membership (id) VALUES (2)") is None


async def test_the_api_cannot_read_the_private_key(rig: tuple[AsyncEngine, ...]) -> None:
    owner, api, ingest = rig
    await _run(
        owner, "UPDATE network_membership SET privkey_enc = '\\x01', privkey_nonce = '\\x02'"
    )
    assert await _run(api, "SELECT privkey_enc FROM network_membership") is None
    assert await _run(api, "SELECT privkey_nonce FROM network_membership") is None
    assert await _run(api, "SELECT * FROM network_membership") is None
    assert (
        await _run(api, "SELECT desired, state, fingerprint, pubkey FROM network_membership") == 1
    )
    assert await _run(ingest, "SELECT privkey_enc FROM network_membership") == 1


async def test_the_api_writes_only_the_wishes(rig: tuple[AsyncEngine, ...]) -> None:
    _owner, api, _ingest = rig
    assert await _run(api, "UPDATE network_membership SET state = 'member'") is None
    assert await _run(api, "UPDATE network_membership SET node_id = gen_random_uuid()") is None
    assert await _run(api, "UPDATE network_membership SET privkey_enc = '\\x00'") is None
    assert await _run(api, TARGET) is None
    assert await _run(api, "DELETE FROM network_submissions") is None
    assert await _run(api, "DELETE FROM network_membership") is None


async def test_the_api_can_only_walk_off_member_leave(rig: tuple[AsyncEngine, ...]) -> None:
    owner, api, _ingest = rig
    assert await _run(api, "UPDATE network_membership SET desired = 'leave'") is None
    assert await _run(api, "UPDATE network_membership SET desired = 'member'") == 1
    assert await _run(api, "UPDATE network_membership SET desired = 'off'") is None
    assert await _run(api, "UPDATE network_membership SET desired = 'leave'") == 1
    assert await _run(api, "UPDATE network_membership SET desired = 'member'") is None
    assert await _run(api, "UPDATE network_membership SET pseudonym = 'fox'") is None  # leaving
    assert await _run(owner, "UPDATE network_membership SET desired = 'off'") == 1


async def test_ingest_owns_the_other_tables(rig: tuple[AsyncEngine, ...]) -> None:
    _owner, api, ingest = rig
    assert await _run(ingest, TARGET) == 1
    assert await _run(api, "SELECT hub_id FROM network_targets") == 1
    assert await _run(ingest, "DELETE FROM network_targets") == 1
    assert await _run(ingest, "INSERT INTO network_membership (id) VALUES (2)") is None


async def test_the_prune_job_nulls_old_payloads_and_drops_old_rows(
    rig: tuple[AsyncEngine, ...],
) -> None:
    owner, _api, _ingest = rig
    async with owner.begin() as conn:
        for age in (1, 10, 100):
            await conn.execute(
                text(
                    "INSERT INTO network_submissions (day, batch_id, status, payload) VALUES "
                    f"((now() AT TIME ZONE 'UTC')::date - {age}, 'b{age}', 'sent', '{{}}')"
                )
            )
        await conn.execute(text("CALL suckerpot_network_prune(0, '{}'::jsonb)"))
        rows = (
            await conn.execute(
                text("SELECT batch_id, payload IS NULL FROM network_submissions ORDER BY batch_id")
            )
        ).all()
    assert [tuple(r) for r in rows] == [("b1", False), ("b10", True)]

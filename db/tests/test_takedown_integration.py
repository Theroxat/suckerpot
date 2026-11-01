"""M27 schema: grants per role, the target and submission triggers, RLS, prune, down/up."""

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
KEY = "a" * 64
NEW_TARGET = (
    "INSERT INTO takedown_targets (kind, role, value, target_key, provider_key, reported_at, "
    "track_until) VALUES ('url', 'payload_url', :v, :k, 'as64500', now() - interval '3 days', "
    "now() + interval '27 days') RETURNING id"
)
NEW_SUB = (
    "INSERT INTO abusech_submissions (platform, ioc_type, value, threat, demo, lookup) "
    "VALUES ('urlhaus', 'url', :v, 'malware_download', :d, 'unknown') RETURNING id"
)


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


async def _state(engine: AsyncEngine, sql: str, params: dict[str, object] | None = None) -> str:
    """'ok' or the SQLSTATE the statement failed with."""
    try:
        async with engine.begin() as conn:
            await conn.execute(text(sql), params or {})
    except DBAPIError as exc:
        return str(getattr(exc.orig, "sqlstate", "?"))
    return "ok"


@pytest.fixture
async def owner() -> AsyncIterator[AsyncEngine]:
    _alembic("upgrade", "head")
    await _roles(ENV)
    engine = create_async_engine(database_url_from_env(ENV))
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE takedown_target_links, takedown_checks, takedown_targets, "
                "abusech_submissions, abusech_submission, outcome_rollup_monthly CASCADE"
            )
        )
    yield engine
    await engine.dispose()


@pytest.fixture
async def roles() -> AsyncIterator[dict[str, AsyncEngine]]:
    out = {
        "api": _as(ENV["POSTGRES_API_USER"], ENV["POSTGRES_API_PASSWORD"]),
        "ingest": _as(ENV["POSTGRES_INGEST_USER"], ENV["POSTGRES_INGEST_PASSWORD"]),
        "collector": _as("suckerpot_collector", ENV["POSTGRES_COLLECTOR_PASSWORD"]),
    }
    yield out
    for engine in out.values():
        await engine.dispose()


async def _new_target(engine: AsyncEngine, value: str = "http://files.example.net/a.sh") -> int:
    async with engine.begin() as conn:
        return int(await conn.scalar(text(NEW_TARGET), {"v": value, "k": KEY}) or 0)


async def test_down_and_up_again(owner: AsyncEngine) -> None:
    async def exists() -> bool:
        async with owner.connect() as conn:
            return bool(
                await conn.scalar(text("SELECT to_regclass('takedown_targets') IS NOT NULL"))
            )

    assert await exists()
    _alembic("downgrade", "0022")
    assert not await exists()
    _alembic("upgrade", "head")
    assert await exists()
    await _roles(ENV)


async def test_collector_cannot_change_the_state(
    owner: AsyncEngine, roles: dict[str, AsyncEngine]
) -> None:
    tid = await _new_target(roles["ingest"])
    collector = roles["collector"]
    assert await _state(collector, "SELECT state FROM takedown_targets") == "ok"
    ok = "UPDATE takedown_targets SET http_step = 2, http_last_at = now() WHERE id = :i"
    assert await _state(collector, ok, {"i": tid}) == "ok"
    for column in ("state = 'down'", "first_down_at = now()", "tracking = false"):
        sql = f"UPDATE takedown_targets SET {column} WHERE id = :i"  # noqa: S608
        assert await _state(collector, sql, {"i": tid}) == "42501", column
    insert_check = (
        "INSERT INTO takedown_checks (target_id, method, outcome) VALUES (:i, 'http', 'same')"
    )
    assert await _state(collector, insert_check, {"i": tid}) == "ok"
    assert await _state(collector, "DELETE FROM takedown_checks") == "42501"
    assert await _state(collector, "SELECT * FROM abusech_submissions") == "42501"


async def test_api_only_stops_or_rechecks(
    owner: AsyncEngine, roles: dict[str, AsyncEngine]
) -> None:
    tid = await _new_target(roles["ingest"])
    api = roles["api"]
    stop = "UPDATE takedown_targets SET tracking = false, stopped_at = now() WHERE id = :i"
    assert await _state(api, stop, {"i": tid}) == "ok"
    assert (
        await _state(api, "UPDATE takedown_targets SET state = 'up' WHERE id = :i", {"i": tid})
        == "42501"
    )
    assert await _state(api, "DELETE FROM takedown_targets") == "42501"
    assert await _state(api, NEW_TARGET, {"v": "http://x.example.net/", "k": KEY}) == "42501"


async def test_target_identity_and_reported_at_guard(
    owner: AsyncEngine, roles: dict[str, AsyncEngine]
) -> None:
    ingest = roles["ingest"]
    tid = await _new_target(ingest)
    earlier = (
        "UPDATE takedown_targets SET reported_at = reported_at - interval '1 day' WHERE id = :i"
    )
    later = "UPDATE takedown_targets SET reported_at = reported_at + interval '1 day' WHERE id = :i"
    assert await _state(ingest, earlier, {"i": tid}) == "ok"
    assert await _state(ingest, later, {"i": tid}) == "23514"
    # Identity columns have no UPDATE grant at all; the owner hits the trigger.
    async with owner.begin() as conn:
        with pytest.raises(DBAPIError):
            await conn.execute(
                text("UPDATE takedown_targets SET value = 'x' WHERE id = :i"), {"i": tid}
            )


async def test_ingest_cannot_write_the_collector_columns(
    owner: AsyncEngine, roles: dict[str, AsyncEngine]
) -> None:
    tid = await _new_target(roles["ingest"])
    for column in ("http_step = 1", "http_next_at = now()", "last_sha256 = NULL"):
        sql = f"UPDATE takedown_targets SET {column} WHERE id = :i"  # noqa: S608
        assert await _state(roles["ingest"], sql, {"i": tid}) == "42501", column
    assert (
        await _state(
            roles["ingest"], "UPDATE takedown_targets SET state = 'up' WHERE id = :i", {"i": tid}
        )
        == "ok"
    )


async def test_the_api_cannot_read_the_auth_key(
    owner: AsyncEngine, roles: dict[str, AsyncEngine]
) -> None:
    api, ingest = roles["api"], roles["ingest"]
    put = (
        "INSERT INTO abusech_submission (id, key_ciphertext, key_nonce, key_last4) "
        "VALUES (1, :c, :n, 'abcd')"
    )
    async with api.begin() as conn:
        await conn.execute(text(put), {"c": b"x" * 32, "n": b"n" * 12})
    assert await _state(api, "SELECT key_ciphertext FROM abusech_submission") == "42501"
    assert await _state(api, "SELECT key_nonce FROM abusech_submission") == "42501"
    assert await _state(api, "SELECT mode, key_set, key_last4 FROM abusech_submission") == "ok"
    assert await _state(ingest, "SELECT key_ciphertext, key_nonce FROM abusech_submission") == "ok"
    assert await _state(ingest, "UPDATE abusech_submission SET mode = 'off'") == "42501"


async def test_auto_mode_needs_a_key(owner: AsyncEngine, roles: dict[str, AsyncEngine]) -> None:
    sql = "INSERT INTO abusech_submission (id, mode) VALUES (1, 'auto')"
    assert await _state(roles["api"], sql) == "23514"  # CHECK violation


async def test_submission_workflow_rules(owner: AsyncEngine, roles: dict[str, AsyncEngine]) -> None:
    api, ingest = roles["api"], roles["ingest"]
    async with ingest.begin() as conn:
        sid = int(
            await conn.scalar(text(NEW_SUB), {"v": "http://files.example.net/x", "d": False}) or 0
        )
        demo = int(
            await conn.scalar(text(NEW_SUB), {"v": "http://demo.example.net/x", "d": True}) or 0
        )
    approve = (
        "UPDATE abusech_submissions SET status = 'pending', approved_by = 'admin' WHERE id = :i"
    )
    # Mode off: the API cannot approve.
    assert await _state(api, approve, {"i": sid}) == "23514"
    async with owner.begin() as conn:
        await conn.execute(text("INSERT INTO abusech_submission (id, mode) VALUES (1, 'review')"))
    assert await _state(api, approve, {"i": sid}) == "ok"
    # A demo row never leaves candidate, whoever asks.
    assert await _state(api, approve, {"i": demo}) == "23514"
    # The API cannot submit, nor write a result.
    assert (
        await _state(
            api, "UPDATE abusech_submissions SET status = 'submitted' WHERE id = :i", {"i": sid}
        )
        == "23514"
    )
    assert (
        await _state(
            api, "UPDATE abusech_submissions SET result_code = 'x' WHERE id = :i", {"i": sid}
        )
        == "42501"
    )
    # Ingest claims, then finishes; a final row is immutable.
    claim = "UPDATE abusech_submissions SET status = 'submitting', started_at = now() WHERE id = :i"
    done = (
        "UPDATE abusech_submissions SET status = 'submitted', result_code = 'inserted', "
        "submitted_at = now(), done_at = now() WHERE id = :i"
    )
    assert await _state(ingest, claim, {"i": sid}) == "ok"
    assert (
        await _state(
            api, "UPDATE abusech_submissions SET status = 'cancelled' WHERE id = :i", {"i": sid}
        )
        == "23514"
    )
    assert await _state(ingest, done, {"i": sid}) == "ok"
    assert await _state(ingest, claim, {"i": sid}) == "23514"
    assert (
        await _state(
            ingest, "UPDATE abusech_submissions SET result_code = 'y' WHERE id = :i", {"i": sid}
        )
        == "23514"
    )


async def test_api_cancels_only_pending(owner: AsyncEngine, roles: dict[str, AsyncEngine]) -> None:
    api, ingest = roles["api"], roles["ingest"]
    async with owner.begin() as conn:
        await conn.execute(text("INSERT INTO abusech_submission (id, mode) VALUES (1, 'review')"))
    async with ingest.begin() as conn:
        sid = int(
            await conn.scalar(text(NEW_SUB), {"v": "http://files.example.net/c", "d": False}) or 0
        )
    cancel = "UPDATE abusech_submissions SET status = 'cancelled' WHERE id = :i"
    assert await _state(api, cancel, {"i": sid}) == "23514"  # still a candidate
    approve = (
        "UPDATE abusech_submissions SET status = 'pending', approved_by = 'admin' WHERE id = :i"
    )
    assert await _state(api, approve, {"i": sid}) == "ok"
    assert await _state(api, cancel, {"i": sid}) == "ok"
    async with owner.connect() as conn:
        done_at = await conn.scalar(
            text("SELECT done_at FROM abusech_submissions WHERE id = :i"), {"i": sid}
        )
    assert done_at is not None  # stamped by the trigger, the API cannot write it


async def test_ingest_only_inserts_candidates(
    owner: AsyncEngine, roles: dict[str, AsyncEngine]
) -> None:
    ingest, api = roles["ingest"], roles["api"]
    bad = (
        "INSERT INTO abusech_submissions (platform, ioc_type, value, threat, status) "
        "VALUES ('urlhaus', 'url', 'http://z.example.net/', 'malware_download', 'submitted')"
    )
    assert await _state(ingest, bad) == "23514"
    assert await _state(api, NEW_SUB, {"v": "http://q.example.net/", "d": False}) == "42501"


async def test_quota_rows_of_takedown_http_belong_to_the_collector(
    owner: AsyncEngine, roles: dict[str, AsyncEngine]
) -> None:
    collector = roles["collector"]
    ins = "INSERT INTO enrichment_quota (provider, day, used) VALUES (:p, current_date, 1)"
    assert await _state(collector, ins, {"p": "takedown_http"}) == "ok"
    assert await _state(collector, ins, {"p": "abuseipdb"}) == "42501"
    async with collector.connect() as conn:
        seen = (await conn.execute(text("SELECT provider FROM enrichment_quota"))).scalars().all()
    assert set(seen) <= {"collector", "takedown_http"}
    status = "INSERT INTO enrichment_status (name, detail) VALUES (:n, '{}')"
    assert await _state(collector, status, {"n": "takedown_http"}) == "ok"


async def test_prune_keeps_the_rollup(owner: AsyncEngine) -> None:
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO outcome_rollup_monthly (month, provider_key, kind, channel, targets) "
                "VALUES ('2020-01-01', 'as64500', 'payload_url', 'mail', 3)"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO takedown_targets (kind, role, value, target_key, provider_key, "
                "reported_at, track_until) VALUES ('url', 'payload_url', "
                "'http://old.example.net/', "
                ":k, 'as64500', now() - interval '900 days', now() - interval '870 days')"
            ),
            {"k": KEY},
        )
        await conn.execute(text("CALL suckerpot_takedown_prune(0, '{}'::jsonb)"))
        targets = await conn.scalar(text("SELECT count(*) FROM takedown_targets"))
        rollup = await conn.scalar(text("SELECT count(*) FROM outcome_rollup_monthly"))
    assert targets == 0
    assert rollup == 1

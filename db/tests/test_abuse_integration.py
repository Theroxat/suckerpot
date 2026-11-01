"""M22 schema: the chain goes down and up, the workflow triggers hold and the roles are confined."""

import os
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from suckerpot_db import database_url_from_env
from suckerpot_db.roles import apply_roles

pytestmark = pytest.mark.integration
# ruff: noqa: S608  (test SQL is built from constants)

DB_DIR = Path(os.environ.get("DB_DIR", Path(__file__).resolve().parents[1]))
TABLES = ("rdap_bootstrap", "abuse_networks", "abuse_lookups", "abuse_recipients",
          "abuse_reports", "abuse_report_subjects", "abuse_report_requests", "report_settings",
          "report_self_terms")  # fmt: skip
ENV: dict[str, str] = {
    **os.environ,
    "POSTGRES_INGEST_USER": os.environ.get("POSTGRES_INGEST_USER", "suckerpot_ingest"),
    "POSTGRES_INGEST_PASSWORD": os.environ.get("POSTGRES_INGEST_PASSWORD", "ingest-test-password"),
    "POSTGRES_API_USER": os.environ.get("POSTGRES_API_USER", "suckerpot_api"),
    "POSTGRES_API_PASSWORD": os.environ.get("POSTGRES_API_PASSWORD", "api-test-password"),
}
NEW_REPORT = (
    "INSERT INTO abuse_reports (public_id, id_seed, recipient_id, kind, demo, window_start, "
    "window_end, evidence, content_sha256, guard_ok, status) VALUES (gen_random_uuid(), "
    "gen_random_uuid(), (SELECT min(id) FROM abuse_recipients), :kind, :demo, now(), now(), "
    "'{}', 'x', true, :status)"
)


def _alembic(*args: str) -> None:
    subprocess.run(  # noqa: S603
        [sys.executable, "-m", "alembic", *args], cwd=DB_DIR, env=ENV, check=True, timeout=180
    )


def _as(user: str, password: str) -> AsyncEngine:
    return create_async_engine(
        database_url_from_env({**ENV, "POSTGRES_USER": user, "POSTGRES_PASSWORD": password})
    )


@pytest.fixture
async def owner() -> AsyncIterator[AsyncEngine]:
    _alembic("upgrade", "head")
    engine = create_async_engine(database_url_from_env(ENV))
    async with engine.begin() as conn:
        await conn.run_sync(lambda c: apply_roles(c, ENV))
        await conn.execute(text("TRUNCATE abuse_recipients, report_self_terms CASCADE"))
        await conn.execute(
            text(
                "INSERT INTO abuse_recipients (mailbox, source) "
                "VALUES ('abuse@example.net', 'rdap')"
            )
        )
    yield engine
    await engine.dispose()


async def _run(
    engine: AsyncEngine, sql: str, params: dict[str, object] | None = None
) -> int | None:
    """Row count of the statement, or None when it was refused (privilege, RLS or trigger)."""
    try:
        async with engine.begin() as conn:
            return (await conn.execute(text(sql), params or {})).rowcount
    except DBAPIError:
        return None


async def _report(owner: AsyncEngine, status: str = "draft", demo: bool = False) -> int:
    async with owner.begin() as conn:
        await conn.execute(text("DELETE FROM abuse_reports"))
        await conn.execute(text(NEW_REPORT), {"kind": "c2", "demo": demo, "status": status})
        return int(await conn.scalar(text("SELECT id FROM abuse_reports")) or 0)


@pytest.fixture
async def roles() -> AsyncIterator[tuple[AsyncEngine, AsyncEngine]]:
    api = _as(ENV["POSTGRES_API_USER"], ENV["POSTGRES_API_PASSWORD"])
    ingest = _as(ENV["POSTGRES_INGEST_USER"], ENV["POSTGRES_INGEST_PASSWORD"])
    yield api, ingest
    await api.dispose()
    await ingest.dispose()


async def test_down_and_up_again(owner: AsyncEngine) -> None:
    async def exists(table: str) -> bool:
        async with owner.connect() as conn:
            return bool(await conn.scalar(text("SELECT to_regclass(:t) IS NOT NULL"), {"t": table}))

    assert all([await exists(t) for t in TABLES])
    _alembic("downgrade", "0018")
    assert not any([await exists(t) for t in TABLES])
    async with owner.connect() as conn:
        assert await conn.scalar(text("SELECT version_num FROM alembic_version")) == "0018"
        assert await conn.scalar(text("SELECT to_regproc('abuse_reports_transition') IS NULL"))
    _alembic("upgrade", "head")
    assert all([await exists(t) for t in TABLES])
    async with owner.connect() as conn:
        assert await conn.scalar(text("SELECT count(*) FROM report_settings")) == 1


async def test_one_open_report_per_recipient_and_kind(owner: AsyncEngine) -> None:
    await _report(owner)
    assert await _run(owner, NEW_REPORT, {"kind": "c2", "demo": False, "status": "draft"}) is None
    assert await _run(owner, NEW_REPORT, {"kind": "payload_host", "demo": False, "status": "draft"})
    assert await _run(owner, "UPDATE abuse_reports SET status = 'discarded' WHERE kind = 'c2'")
    assert await _run(owner, NEW_REPORT, {"kind": "c2", "demo": False, "status": "draft"})


async def test_transitions_and_demo(owner: AsyncEngine) -> None:
    rid = await _report(owner)
    set_status = "UPDATE abuse_reports SET status = :s WHERE id = :i"
    assert await _run(owner, set_status, {"s": "sent", "i": rid}) is None  # draft -> sent
    assert await _run(owner, set_status, {"s": "closed", "i": rid}) is None
    assert await _run(owner, set_status, {"s": "reviewed", "i": rid}) == 1
    assert await _run(owner, set_status, {"s": "sent", "i": rid}) == 1
    assert await _run(owner, set_status, {"s": "reviewed", "i": rid}) is None  # sent is final
    assert await _run(owner, set_status, {"s": "closed", "i": rid}) == 1
    assert await _run(owner, set_status, {"s": "draft", "i": rid}) is None
    # A demo report can never be sent, neither by insert nor by update.
    assert await _run(owner, NEW_REPORT, {"kind": "c2", "demo": True, "status": "sent"}) is None
    rid = await _report(owner, demo=True)
    assert await _run(owner, set_status, {"s": "reviewed", "i": rid}) == 1
    assert await _run(owner, set_status, {"s": "sent", "i": rid}) is None
    # Identity columns and, after the draft state, the content are frozen.
    assert (
        await _run(owner, "UPDATE abuse_reports SET demo = false WHERE id = :i", {"i": rid}) is None
    )
    assert (
        await _run(owner, "UPDATE abuse_reports SET evidence = jsonb_build_object('a', 1)") is None
    )


async def test_touch_bumps_the_revision_with_the_evidence(owner: AsyncEngine) -> None:
    await _report(owner)
    async with owner.begin() as conn:
        await conn.execute(text("UPDATE abuse_reports SET notes = 'n'"))
        rev = await conn.scalar(text("SELECT revision FROM abuse_reports"))
        assert rev == 1
        await conn.execute(text("UPDATE abuse_reports SET evidence = jsonb_build_object('a', 1)"))
        assert await conn.scalar(text("SELECT revision FROM abuse_reports")) == 2
        assert await conn.scalar(text("SELECT updated_at >= created_at FROM abuse_reports"))


async def test_api_and_ingest_are_confined_on_reports(
    owner: AsyncEngine, roles: tuple[AsyncEngine, AsyncEngine]
) -> None:
    api, ingest = roles
    await _report(owner)
    # Ingest rebuilds drafts, but cannot review, send, close or touch the notes.
    assert await _run(
        ingest, "UPDATE abuse_reports SET evidence = jsonb_build_object('a', 2), guard_ok = false"
    )
    assert await _run(ingest, "UPDATE abuse_reports SET status = 'reviewed'") is None
    assert await _run(ingest, "UPDATE abuse_reports SET reviewed_by = 'x'") is None
    assert await _run(ingest, "UPDATE abuse_reports SET notes = 'x'") is None
    assert await _run(ingest, "UPDATE abuse_reports SET sent_at = now()") is None
    assert await _run(ingest, "DELETE FROM abuse_reports") is None
    assert await _run(ingest, "UPDATE abuse_reports SET status = 'superseded'") == 1
    rid = await _report(owner)
    # The API reviews and sends but cannot rewrite evidence or insert reports.
    assert await _run(api, "UPDATE abuse_reports SET evidence = '{}'") is None
    assert await _run(api, "UPDATE abuse_reports SET content_sha256 = 'y'") is None
    assert await _run(api, NEW_REPORT, {"kind": "c2", "demo": False, "status": "draft"}) is None
    assert await _run(
        api, "UPDATE abuse_reports SET status = 'reviewed', reviewed_by = 'a', notes = 'k'"
    )
    # Once reviewed, ingest may not touch the report at all.
    assert await _run(ingest, "UPDATE abuse_reports SET guard_ok = false") is None
    assert await _run(ingest, "UPDATE abuse_reports SET status = 'draft'") is None
    assert await _run(api, "UPDATE abuse_reports SET status = 'sent', sent_by = 'a'") == 1
    assert await _run(api, "UPDATE abuse_reports SET status = 'draft'") is None
    assert rid


async def test_other_tables(owner: AsyncEngine, roles: tuple[AsyncEngine, AsyncEngine]) -> None:
    api, ingest = roles
    for table in TABLES:
        assert await _run(api, f"SELECT count(*) FROM {table}") is not None
        assert await _run(ingest, f"SELECT count(*) FROM {table}") is not None
    net = (
        "INSERT INTO abuse_networks (kind, cidr, source, fetched_at, expires_at) "
        "VALUES ('ip', '198.51.100.0/24', 'rdap', now(), now())"
    )
    assert await _run(api, net) is None
    assert await _run(ingest, net)
    assert await _run(ingest, "DELETE FROM abuse_networks")
    assert await _run(ingest, "UPDATE abuse_recipients SET name = 'N'")
    assert await _run(ingest, "UPDATE abuse_recipients SET muted = true") is None
    assert await _run(api, "UPDATE abuse_recipients SET muted = true, override_mailbox = 'a@b.cc'")
    assert await _run(api, "UPDATE abuse_recipients SET mailbox = 'x@y.zz'") is None
    assert await _run(
        api, "INSERT INTO abuse_recipients (mailbox, source) VALUES ('m@example.org', 'manual')"
    )
    req = "INSERT INTO abuse_report_requests (action, requested_by) VALUES ('lookup_again', 'a')"
    assert await _run(api, req)
    assert await _run(ingest, req) is None
    assert await _run(ingest, "UPDATE abuse_report_requests SET done_at = now(), outcome = 'ok'")
    assert await _run(api, "UPDATE abuse_report_requests SET outcome = 'x'") is None
    assert await _run(api, "UPDATE report_settings SET intro = 'hello', revision = revision + 1")
    assert await _run(ingest, "UPDATE report_settings SET intro = 'x'") is None


async def test_self_terms_row_level_security(
    owner: AsyncEngine, roles: tuple[AsyncEngine, AsyncEngine]
) -> None:
    api, ingest = roles
    ins = "INSERT INTO report_self_terms (kind, value, source) VALUES ('name', :v, :s)"
    sensor = (
        "INSERT INTO report_self_terms (kind, value, source, confirmed) "
        "VALUES ('name', :v, 'sensor', :c)"
    )
    assert await _run(ingest, ins, {"v": "learned-a", "s": "learned"})
    assert await _run(ingest, ins, {"v": "manual-b", "s": "manual"}) is None
    # Ingest never confirms a learned row; a sensor row is trusted and always confirmed.
    assert (
        await _run(
            ingest,
            "INSERT INTO report_self_terms (kind, value, source, confirmed) "
            "VALUES ('name', 'learned-ok', 'learned', true)",
        )
        is None
    )
    assert await _run(ingest, sensor, {"v": "srv-sensor", "c": False}) is None
    assert await _run(ingest, sensor, {"v": "srv-sensor", "c": True})
    assert await _run(api, ins, {"v": "manual-c", "s": "manual"})
    assert await _run(api, ins, {"v": "learned-d", "s": "learned"}) is None
    assert await _run(api, ins, {"v": "sensor-e", "s": "sensor"}) is None
    for eng in (api, ingest):
        async with eng.connect() as conn:
            assert await conn.scalar(text("SELECT count(*) FROM report_self_terms")) == 3
    # Ingest updates only the counters of learned and sensor terms.
    assert await _run(ingest, "UPDATE report_self_terms SET distinct_sources = 3") == 2
    assert await _run(ingest, "UPDATE report_self_terms SET last_seen = now()") == 2
    assert await _run(ingest, "UPDATE report_self_terms SET confirmed = true") is None
    assert await _run(ingest, "UPDATE report_self_terms SET source = 'manual'") is None
    assert await _run(ingest, "DELETE FROM report_self_terms") is None
    assert await _run(api, "UPDATE report_self_terms SET confirmed = true") == 3
    assert await _run(api, "UPDATE report_self_terms SET value = 'zz'") is None
    # The owner deletes manual and learned terms; a sensor's own name stays.
    assert await _run(api, "DELETE FROM report_self_terms") == 2
    async with owner.connect() as conn:
        assert await conn.scalar(text("SELECT source FROM report_self_terms")) == "sensor"


async def test_ingest_reads_payload_tables_but_cannot_write_them(
    owner: AsyncEngine, roles: tuple[AsyncEngine, AsyncEngine]
) -> None:
    _, ingest = roles
    for table in ("fetch_targets", "samples", "sample_links", "sample_sources"):
        assert await _run(ingest, f"SELECT count(*) FROM {table}") is not None
        assert await _run(ingest, f"DELETE FROM {table}") is None
    assert await _run(ingest, "SELECT count(*) FROM fetch_attempts") is None


async def test_a_waiting_recipient_has_no_mailbox_until_the_owner_types_one(
    owner: AsyncEngine, roles: tuple[AsyncEngine, AsyncEngine]
) -> None:
    api, ingest = roles
    new = "INSERT INTO abuse_recipients (mailbox, name, source) VALUES (NULL, :n, 'rdap')"
    assert await _run(ingest, new, {"n": "net one"})
    assert await _run(ingest, new, {"n": "net two"})  # several waiting rows are allowed
    net = (
        "INSERT INTO abuse_networks (kind, cidr, source, fetched_at, expires_at, recipient_id) "
        "VALUES ('ip', '198.51.100.0/24', 'rdap', now(), now(), "
        "(SELECT min(id) FROM abuse_recipients WHERE mailbox IS NULL))"
    )
    assert await _run(ingest, net)
    assert await _run(
        api,
        "UPDATE abuse_recipients SET override_mailbox = 'abuse@example.org' WHERE mailbox IS NULL",
    )

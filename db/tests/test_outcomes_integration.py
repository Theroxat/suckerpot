"""M26 schema: reply token, send-request Message-ID, replies, outcomes and the prune procedure."""

import os
import subprocess
import sys
from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from suckerpot_db import database_url_from_env
from suckerpot_db.roles import apply_roles

pytestmark = pytest.mark.integration
# ruff: noqa: E501


DB_DIR = Path(os.environ.get("DB_DIR", Path(__file__).resolve().parents[1]))
ENV: dict[str, str] = {
    **os.environ,
    "POSTGRES_INGEST_USER": os.environ.get("POSTGRES_INGEST_USER", "suckerpot_ingest"),
    "POSTGRES_INGEST_PASSWORD": os.environ.get("POSTGRES_INGEST_PASSWORD", "ingest-test-password"),
    "POSTGRES_API_USER": os.environ.get("POSTGRES_API_USER", "suckerpot_api"),
    "POSTGRES_API_PASSWORD": os.environ.get("POSTGRES_API_PASSWORD", "api-test-password"),
}
NEW_REPORT = (
    "INSERT INTO abuse_reports (public_id, id_seed, recipient_id, kind, demo, window_start, "
    "window_end, evidence, content_sha256, guard_ok, status{extra}) VALUES (gen_random_uuid(), "
    "gen_random_uuid(), (SELECT min(id) FROM abuse_recipients), :kind, false, now(), now(), "
    "'{{}}', 'x', true, :status{vals})"
)
JAN_2026 = datetime(2026, 1, 1, tzinfo=UTC)  # asyncpg wants a datetime, not a string
JAN_2020 = datetime(2020, 1, 1, tzinfo=UTC)
REPLY = (
    "INSERT INTO abuse_replies (source, received_at, match_method, classification, size_bytes, "
    "report_id, excerpt) VALUES ('paste', :at, :m, 'human_reply', 10, :r, 'hello')"
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


@pytest.fixture
async def roles() -> AsyncIterator[tuple[AsyncEngine, AsyncEngine]]:
    api = _as(ENV["POSTGRES_API_USER"], ENV["POSTGRES_API_PASSWORD"])
    ingest = _as(ENV["POSTGRES_INGEST_USER"], ENV["POSTGRES_INGEST_PASSWORD"])
    yield api, ingest
    await api.dispose()
    await ingest.dispose()


async def _run(
    engine: AsyncEngine, sql: str, params: Mapping[str, object] | None = None
) -> int | None:
    """Row count of the statement, or None when it was refused (privilege or trigger)."""
    try:
        async with engine.begin() as conn:
            return (await conn.execute(text(sql), params or {})).rowcount
    except DBAPIError:
        return None


async def _sent_report(owner: AsyncEngine, kind: str = "c2") -> int:
    async with owner.begin() as conn:
        await conn.execute(text("DELETE FROM abuse_reports WHERE kind = :k"), {"k": kind})
        await conn.execute(
            text(NEW_REPORT.format(extra="", vals="")), {"kind": kind, "status": "reviewed"}
        )
        rid = int(
            await conn.scalar(text("SELECT id FROM abuse_reports WHERE kind = :k"), {"k": kind})
            or 0
        )
        await conn.execute(
            text(
                "UPDATE abuse_reports SET status = 'sent', sent_at = now() - interval '3 days', "
                "sent_by = 'x', sent_via = 'manual' WHERE id = :i"
            ),
            {"i": rid},
        )
    return rid


async def _draft(owner: AsyncEngine, kind: str = "payload_host") -> int:
    async with owner.begin() as conn:
        await conn.execute(text("DELETE FROM abuse_reports WHERE kind = :k"), {"k": kind})
        await conn.execute(
            text(NEW_REPORT.format(extra="", vals="")), {"kind": kind, "status": "draft"}
        )
        return int(
            await conn.scalar(text("SELECT id FROM abuse_reports WHERE kind = :k"), {"k": kind})
            or 0
        )


async def test_existing_and_new_reports_get_distinct_immutable_tokens(owner: AsyncEngine) -> None:
    async with owner.begin() as conn:
        await conn.execute(text("DELETE FROM abuse_reports"))
        for kind in ("c2", "payload_host", "attack_source"):
            await conn.execute(
                text(NEW_REPORT.format(extra="", vals="")), {"kind": kind, "status": "draft"}
            )
    _alembic("downgrade", "0025")
    _alembic("upgrade", "head")
    async with owner.connect() as conn:
        tokens = [r[0] for r in await conn.execute(text("SELECT reply_token FROM abuse_reports"))]
    assert len(tokens) == 3 and len(set(tokens)) == 3
    assert all(len(t) == 12 and set(t) <= set("0123456789abcdef") for t in tokens)
    assert await _run(owner, "UPDATE abuse_reports SET reply_token = 'aaaaaaaaaaaa'") is None


async def test_the_message_id_is_written_once_by_ingest(
    owner: AsyncEngine, roles: tuple[AsyncEngine, AsyncEngine]
) -> None:
    api, ingest = roles
    rid = await _draft(owner)
    ask = "INSERT INTO abuse_send_requests (report_id, kind, requested_by{c}) VALUES (:r, 'send', 'a'{v})"
    assert (
        await _run(api, ask.format(c=", message_id", v=", '<x@example.org>'"), {"r": rid}) is None
    )
    assert await _run(api, ask.format(c="", v=""), {"r": rid}) == 1
    assert await _run(api, "UPDATE abuse_send_requests SET message_id = '<a@example.org>'") is None
    claim = (
        "UPDATE abuse_send_requests SET status = 'sending', started_at = now(), "
        "message_id = :m WHERE report_id = :r"
    )
    assert await _run(ingest, claim, {"m": "x" * 256, "r": rid}) is None  # 255 at most
    assert await _run(ingest, claim, {"m": "<a@example.org>", "r": rid}) == 1
    # Immutable afterwards.
    assert (
        await _run(ingest, "UPDATE abuse_send_requests SET message_id = '<b@example.org>'") is None
    )


async def test_no_outcome_for_a_draft_and_no_date_before_the_send(
    owner: AsyncEngine, roles: tuple[AsyncEngine, AsyncEngine]
) -> None:
    api, ingest = roles
    draft = await _draft(owner)
    new_auto = "INSERT INTO abuse_report_outcomes (report_id) VALUES (:r)"
    assert await _run(ingest, new_auto, {"r": draft}) is None
    new_manual = (
        "INSERT INTO abuse_report_outcomes (report_id, manual_outcome, manual_at, manual_by) "
        "VALUES (:r, 'resolved', {at}, 'admin')"
    )
    assert await _run(api, new_manual.format(at="now()"), {"r": draft}) is None
    sent = await _sent_report(owner)
    assert await _run(api, new_manual.format(at="now() - interval '10 days'"), {"r": sent}) is None
    assert await _run(api, new_manual.format(at="now()"), {"r": sent}) == 1


async def test_outcome_columns_are_split_between_roles(
    owner: AsyncEngine, roles: tuple[AsyncEngine, AsyncEngine]
) -> None:
    api, ingest = roles
    sent = await _sent_report(owner)
    assert (
        await _run(ingest, "INSERT INTO abuse_report_outcomes (report_id) VALUES (:r)", {"r": sent})
        == 1
    )
    set_auto = "UPDATE abuse_report_outcomes SET auto_outcome = 'resolved', needs_review = true"
    set_manual = "UPDATE abuse_report_outcomes SET manual_outcome = 'rejected', manual_by = 'a'"
    assert await _run(ingest, set_auto) == 1
    assert await _run(ingest, set_manual) is None  # ingest cannot write manual_*
    assert await _run(api, set_manual) == 1
    assert await _run(api, set_auto) is None  # the API cannot write auto_*
    assert await _run(api, "UPDATE abuse_report_outcomes SET note = 'n'") == 1
    assert await _run(api, "DELETE FROM abuse_report_outcomes") is None
    assert await _run(ingest, "DELETE FROM abuse_report_outcomes") is None


async def test_the_api_cannot_read_the_mailbox_password_or_pasted_bytes(
    owner: AsyncEngine, roles: tuple[AsyncEngine, AsyncEngine]
) -> None:
    api, ingest = roles
    put = (
        "INSERT INTO report_imap (host, port, security, username, password_ciphertext, "
        "password_nonce) VALUES ('imap.example.org', 993, 'ssl', 'u', '\\x01', '\\x02')"
    )
    assert await _run(api, put) == 1
    assert await _run(api, "SELECT password_ciphertext FROM report_imap") is None
    assert await _run(api, "SELECT password_nonce FROM report_imap") is None
    assert await _run(api, "SELECT password_set, host FROM report_imap") == 1
    assert await _run(ingest, "SELECT password_ciphertext FROM report_imap") == 1
    assert await _run(ingest, "UPDATE report_imap SET enabled = true") is None
    assert (
        await _run(
            api,
            "UPDATE report_imap SET processed_action = 'move', move_folder = 'INBOX'",
        )
        is None
    )  # the move folder must differ from the folder
    assert (
        await _run(api, "INSERT INTO abuse_reply_imports (raw, requested_by) VALUES ('\\x41', 'a')")
        == 1
    )
    assert await _run(api, "SELECT raw FROM abuse_reply_imports") is None
    assert await _run(api, "SELECT id, status FROM abuse_reply_imports") == 1
    assert (
        await _run(
            ingest, "UPDATE abuse_reply_imports SET raw = '', status = 'done', done_at = now()"
        )
        == 1
    )


async def test_reply_columns_per_role(
    owner: AsyncEngine, roles: tuple[AsyncEngine, AsyncEngine]
) -> None:
    api, ingest = roles
    sent = await _sent_report(owner)
    assert await _run(ingest, REPLY, {"at": JAN_2026, "m": "token", "r": sent}) == 1
    assert await _run(api, REPLY, {"at": JAN_2026, "m": "none", "r": sent}) is None
    assert (
        await _run(api, "UPDATE abuse_replies SET classification = 'resolved', reviewed_by = 'a'")
        == 1
    )
    assert await _run(api, "UPDATE abuse_replies SET excerpt = 'x'") is None
    assert await _run(api, "UPDATE abuse_replies SET from_address = 'a@example.org'") is None
    assert await _run(ingest, "UPDATE abuse_replies SET classification = 'resolved'") is None
    assert await _run(ingest, "UPDATE abuse_replies SET verified = true") == 1
    assert await _run(api, "DELETE FROM abuse_replies") is None
    # Exactly one dedupe key per message.
    dup = "INSERT INTO abuse_replies (source, received_at, match_method, classification, size_bytes, message_id_sha256) VALUES ('imap', now(), 'none', 'unknown', 1, repeat('a', 64))"
    assert await _run(ingest, dup) == 1
    assert await _run(ingest, dup) is None
    # Trusting a domain is the API's, five at most.
    five = "UPDATE abuse_recipients SET reply_domains = ARRAY['a.example.org','b.example.org','c.example.org','d.example.org','e.example.org']"
    assert await _run(api, five) == 1
    assert (
        await _run(
            api, "UPDATE abuse_recipients SET reply_domains = reply_domains || 'f.example.org'"
        )
        is None
    )
    assert await _run(ingest, "UPDATE abuse_recipients SET reply_domains = '{}'") is None


async def test_prune_keeps_sent_requests_and_clears_excerpts(owner: AsyncEngine) -> None:
    sent = await _sent_report(owner)
    async with owner.begin() as conn:
        await conn.execute(text("DELETE FROM abuse_replies"))
        await conn.execute(text("DELETE FROM abuse_send_requests"))
        # The guard trigger only lets a request start pending; old finished rows need it off.
        await conn.execute(text("ALTER TABLE abuse_send_requests DISABLE TRIGGER USER"))
        await conn.execute(
            text(
                "INSERT INTO abuse_send_requests (report_id, kind, requested_by, status, "
                "requested_at, started_at, done_at) VALUES (:r, 'send', 'a', 'sent', "
                "now() - interval '40 days', now() - interval '40 days', now() - interval '40 days')"
            ),
            {"r": sent},
        )
        await conn.execute(
            text(
                "INSERT INTO abuse_send_requests (kind, requested_by, status, requested_at, "
                "started_at, done_at) VALUES ('test', 'a', 'failed', now() - interval '40 days', "
                "now() - interval '40 days', now() - interval '40 days')"
            )
        )
        await conn.execute(text("ALTER TABLE abuse_send_requests ENABLE TRIGGER USER"))
        await conn.execute(text(REPLY), {"at": JAN_2020, "m": "token", "r": sent})
        await conn.execute(
            text(
                "INSERT INTO abuse_replies (source, received_at, match_method, classification, "
                "size_bytes) VALUES ('paste', now() - interval '200 days', 'none', 'unknown', 1)"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO abuse_replies (source, received_at, match_method, classification, "
                "size_bytes, excerpt) VALUES ('paste', now(), 'none', 'unknown', 1, 'fresh')"
            )
        )
        await conn.execute(text("CALL suckerpot_abuse_prune(0, '{\"excerpt_days\": 180}'::jsonb)"))
    async with owner.connect() as conn:
        kinds = [r[0] for r in await conn.execute(text("SELECT kind FROM abuse_send_requests"))]
        assert kinds == ["send"]  # the sent 'send' row stays, the old test row goes
        row = (
            await conn.execute(
                text("SELECT excerpt, excerpt_purged_at FROM abuse_replies WHERE report_id = :r"),
                {"r": sent},
            )
        ).one()
        assert row.excerpt is None and row.excerpt_purged_at is not None
        # The old unmatched reply is gone, the fresh one (kept, unmatched) stays with its excerpt.
        left = [
            r[0] for r in await conn.execute(text("SELECT excerpt FROM abuse_replies ORDER BY id"))
        ]
        assert left == [None, "fresh"]

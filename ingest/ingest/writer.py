"""Batched writer: events insert + sessions upsert in one transaction."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

from sqlalchemy import func, insert
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_common import Event
from suckerpot_db.models import EventRow, SessionRow

from ingest.aggregate import SessionDelta, compute_session_deltas

log = logging.getLogger(__name__)


def strip_nul(value: Any) -> Any:
    """PostgreSQL jsonb rejects U+0000: remove it from every string (keys and values)."""
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, dict):
        return {strip_nul(k): strip_nul(v) for k, v in value.items()}
    if isinstance(value, list):
        return [strip_nul(v) for v in value]
    return value


def event_to_row(ev: Event) -> dict[str, Any]:
    return {
        "ts": ev.ts,
        "sensor": str(ev.sensor),
        "session_id": ev.session_id,
        "type": str(ev.type),
        "src_ip": str(ev.src_ip),
        "src_port": ev.src_port,
        "dst_port": ev.dst_port,
        "data": strip_nul(ev.data),
    }


def delta_to_row(d: SessionDelta) -> dict[str, Any]:
    return {
        "session_id": d.session_id,
        "sensor": d.sensor,
        "src_ip": d.src_ip,
        "src_port": d.src_port,
        "dst_port": d.dst_port,
        "started_at": d.started_at,
        "ended_at": d.ended_at,
        "last_event_at": d.last_event_at,
        "event_count": d.event_count,
        "login_attempts": d.login_attempts,
        "login_success": d.login_success,
        "commands": d.commands,
        "downloads": d.downloads,
        "http_requests": d.http_requests,
    }


async def write_batch(factory: async_sessionmaker[AsyncSession], events: Sequence[Event]) -> None:
    """Insert events and upsert sessions atomically. Raises on failure (nothing is committed)."""
    if not events:
        return
    deltas = compute_session_deltas(events)
    async with factory() as session, session.begin():
        await session.execute(insert(EventRow), [event_to_row(e) for e in events])
        stmt = pg_insert(SessionRow)
        ex = stmt.excluded
        t = SessionRow.__table__
        stmt = stmt.on_conflict_do_update(
            index_elements=[t.c.session_id],
            set_={
                "event_count": t.c.event_count + ex.event_count,
                "login_attempts": t.c.login_attempts + ex.login_attempts,
                "login_success": t.c.login_success | ex.login_success,
                "commands": t.c.commands + ex.commands,
                "downloads": t.c.downloads + ex.downloads,
                "http_requests": t.c.http_requests + ex.http_requests,
                "started_at": func.least(t.c.started_at, ex.started_at),
                "last_event_at": func.greatest(t.c.last_event_at, ex.last_event_at),
                # greatest() ignores NULLs in PostgreSQL.
                "ended_at": func.greatest(t.c.ended_at, ex.ended_at),
            },
        )
        await session.execute(stmt, [delta_to_row(d) for d in deltas])

"""The blocklist as exports see it: scored entries minus allowed ones, plus manual blocks.

Ingest rewrites ``blocklist_entries`` every 15 minutes and applies the overrides then; this
module applies them again at read time so that an administrator's decision takes effect at once.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import and_, exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.blocklist_values import normalize_value
from suckerpot_db.models import BlocklistEntryRow as E
from suckerpot_db.models import BlocklistOverrideRow as O

MAX_ROWS = 50_000


def _live_override(action: str) -> Any:
    now = datetime.now(UTC)
    return and_(O.action == action, or_(O.expires_at.is_(None), O.expires_at > now))


async def effective_rows(
    db: AsyncSession,
    kinds: Sequence[str],
    *,
    min_score: int,
    include_benign: bool,
    include_demo: bool,
    limit: int = MAX_ROWS,
) -> list[dict[str, Any]]:
    """Entries that pass the filters, best first; manual blocks added, allowed ones left out."""
    allowed = exists().where(O.kind == E.kind, O.value == E.value, _live_override("allow"))
    stmt = (
        select(E)
        .where(E.kind.in_(list(kinds)), E.score >= min_score, ~allowed)
        .order_by(E.score.desc(), E.last_seen.desc(), E.kind, E.value)
        .limit(limit)
    )
    if not include_benign:
        stmt = stmt.where(E.benign.is_(False))
    if not include_demo:
        stmt = stmt.where(E.demo.is_(False))
    rows: list[dict[str, Any]] = [
        {
            "kind": e.kind,
            "value": e.value,
            "score": e.score,
            "reasons": list(e.reasons),
            "first_seen": e.first_seen,
            "last_seen": e.last_seen,
            "sessions": e.sessions,
            "sources": e.sources,
            "benign": e.benign,
        }
        for e in (await db.execute(stmt)).scalars()
    ]
    have = {(r["kind"], r["value"]) for r in rows}
    blocks = (
        await db.execute(
            select(O).where(O.kind.in_(list(kinds)), _live_override("block")).limit(1000)
        )
    ).scalars()
    for o in blocks:
        value = normalize_value(o.kind, o.value)
        if value is None or (o.kind, value) in have:
            continue
        rows.append(
            {
                "kind": o.kind,
                "value": value,
                "score": 100,
                "reasons": ["manual-block"],
                "first_seen": o.created_at,
                "last_seen": o.created_at,
                "sessions": 0,
                "sources": 0,
                "benign": False,
            }
        )
    rows.sort(key=lambda r: (-int(r["score"]), -r["last_seen"].timestamp(), r["kind"], r["value"]))
    return rows[:limit]


async def version(db: AsyncSession) -> str:
    """A short tag that changes whenever the lists could have changed (for ETag)."""
    computed, count = (
        await db.execute(select(func.max(E.computed_at), func.count()).select_from(E))
    ).one()
    changed = (await db.execute(select(func.max(O.created_at), func.count()).select_from(O))).one()
    raw = f"{computed}|{count}|{changed[0]}|{changed[1]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

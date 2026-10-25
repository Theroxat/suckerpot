"""``GET /audit``: the audit log for administrators, newest first, paginated."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from suckerpot_db import AuditLogRow

from api.authz import require_admin
from api.cursor import InvalidCursorError, decode_cursor, encode_cursor
from api.deps import DbSession

DEFAULT_LIMIT = 50
MAX_LIMIT = 200

router = APIRouter(tags=["audit"])


class AuditEntry(BaseModel):
    id: int
    ts: datetime
    actor: str
    action: str
    target: str | None
    ip: str | None
    details: dict[str, Any]


class AuditPage(BaseModel):
    items: list[AuditEntry]
    next_cursor: str | None


@router.get("/audit", response_model=AuditPage, dependencies=[Depends(require_admin)])
async def list_audit(
    db: DbSession,
    actor: Annotated[str | None, Query(max_length=128)] = None,
    action: Annotated[str | None, Query(max_length=64)] = None,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> AuditPage:
    """Newest first. ``actor`` matches the name exactly (any case); ``action`` is a prefix
    such as ``user.`` or the full name such as ``user.create``."""
    stmt = select(AuditLogRow).order_by(AuditLogRow.id.desc()).limit(limit + 1)
    if actor:
        stmt = stmt.where(func.lower(AuditLogRow.actor) == actor.strip().lower())
    if action:
        like = action.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        stmt = stmt.where(
            or_(AuditLogRow.action == action, AuditLogRow.action.like(like + "%", escape="\\"))
        )
    if cursor:
        try:
            (last_id,) = decode_cursor(cursor)
            if not isinstance(last_id, int):
                raise ValueError
        except (InvalidCursorError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="invalid cursor") from exc
        stmt = stmt.where(AuditLogRow.id < last_id)
    rows = list((await db.execute(stmt)).scalars())
    page, more = rows[:limit], len(rows) > limit
    return AuditPage(
        items=[
            AuditEntry(
                id=r.id,
                ts=r.ts,
                actor=r.actor,
                action=r.action,
                target=r.target,
                ip=r.ip,
                details=r.details,
            )
            for r in page
        ],
        next_cursor=encode_cursor([page[-1].id]) if more and page else None,
    )

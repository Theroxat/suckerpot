"""The audit log: who did what to whom.

Append-only for the API role; the routes that read it are in ``api.audit_routes``.

An entry never holds a secret: no password, hash, cookie or token, only names, roles and flags.
``details`` is bounded (the database refuses more than 2 KiB; ``record`` trims first).
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db import AuditLogRow

MAX_DETAILS_BYTES = 1500
MAX_TEXT = 120


def _clip(value: str | None, limit: int = MAX_TEXT) -> str | None:
    return None if value is None else value[:limit]


async def record(
    db: AsyncSession,
    *,
    actor: str,
    action: str,
    target: str | None = None,
    ip: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Add an entry to the caller's transaction (the caller commits)."""
    safe = details or {}
    if len(json.dumps(safe, default=str)) > MAX_DETAILS_BYTES:
        safe = {"truncated": True}
    db.add(
        AuditLogRow(
            actor=_clip(actor) or "unknown",
            action=action[:64],
            target=_clip(target),
            ip=_clip(ip, 64),
            details=json.loads(json.dumps(safe, default=str)),
        )
    )

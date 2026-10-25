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
    actor_id: int | str | None = None,
    target_id: int | None = None,
) -> None:
    """Add an entry to the caller's transaction (the caller commits).

    Names can be reused after a deletion, so the numeric ids go into ``details``: ``actor_id``
    is a user id, ``"owner"`` for the owner account, or ``"system"``; ``target_id`` is a user id.
    """
    safe = dict(details or {})
    if actor_id is not None:
        safe["actor_id"] = actor_id
    if target_id is not None:
        safe["target_id"] = target_id
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


def actor_id_of(principal: Any) -> int | str | None:
    """The audit ``actor_id`` of a ``Principal``: its user id, or ``"owner"``."""
    if principal is None:
        return None
    return "owner" if principal.is_owner else principal.user_id

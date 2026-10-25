"""Database access for dashboard accounts: lookups, login bookkeeping and lockout.

Everything here takes an open ``AsyncSession`` and leaves the commit to the caller, so an action
and its audit entry share one transaction. Passwords never pass through this module: it only
handles argon2 hashes.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db import UserRow

LOCK_AFTER_FAILURES = 10
LOCK_DURATION = timedelta(minutes=15)
ROLES = ("admin", "viewer")


async def get_by_id(db: AsyncSession, user_id: int) -> UserRow | None:
    return await db.get(UserRow, user_id)


async def find_by_username(db: AsyncSession, username: str) -> UserRow | None:
    """Case-insensitive lookup (the unique index is on ``lower(username)``)."""
    stmt = select(UserRow).where(func.lower(UserRow.username) == username.strip().lower())
    return (await db.execute(stmt)).scalar_one_or_none()


def is_locked(row: UserRow, now: datetime | None = None) -> bool:
    return row.locked_until is not None and row.locked_until > (now or datetime.now(UTC))


async def register_failure(db: AsyncSession, user_id: int) -> bool:
    """Count a wrong password. True when this failure locked the account.

    One statement, so concurrent attempts cannot both miss the threshold. A locked account is
    left alone (no counting, no extension). The counter restarts when the lock is set, so a
    returning user gets a fresh set of tries once the lock has expired.
    """
    row = (
        await db.execute(
            text(
                "UPDATE users SET "
                "failed_logins = "
                "CASE WHEN failed_logins + 1 >= :n THEN 0 ELSE failed_logins + 1 END, "
                "locked_until = CASE WHEN failed_logins + 1 >= :n "
                "THEN now() + make_interval(secs => :secs) ELSE locked_until END "
                "WHERE id = :id AND (locked_until IS NULL OR locked_until <= now()) "
                "RETURNING (locked_until IS NOT NULL AND locked_until > now()) AS locked"
            ),
            {"n": LOCK_AFTER_FAILURES, "secs": LOCK_DURATION.total_seconds(), "id": user_id},
        )
    ).first()
    return bool(row and row.locked)


async def register_success(db: AsyncSession, user_id: int) -> None:
    await db.execute(
        text(
            "UPDATE users SET failed_logins = 0, locked_until = NULL, "
            "prev_login_at = last_login_at, last_login_at = now() WHERE id = :id"
        ),
        {"id": user_id},
    )

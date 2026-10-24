"""Disk guard: a hard ceiling on the database size, whatever the sensors send.

Two layers share the ceiling ``DB_MAX_SIZE_GB`` (default 10):

* a TimescaleDB job (``suckerpot_disk_guard``, every 5 minutes) that, above 90% of the ceiling,
  drops the oldest raw ``events`` chunks until the database is below 80%;
* the ingest service, which above 95% keeps only small payloads (see ``ingest.diskguard``).

``DB_MAX_SIZE_MB`` is a test-only override with the same meaning, in megabytes.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

from sqlalchemy import text
from sqlalchemy.engine import Connection

DEFAULT_MAX_GB = 10.0
MIN_MAX_GB = 1.0
MAX_MAX_GB = 100_000.0
GUARD_PROC = "suckerpot_disk_guard"
GUARD_INTERVAL = "5 minutes"
# Chunks newer than this are never dropped: the aggregate refresh windows still cover them, and
# refreshing a dropped range would erase the aggregates.
PROTECTED_DAYS = 4


class DiskGuardError(RuntimeError):
    """Invalid disk guard configuration (safe to print)."""


def _number(raw: str, name: str, low: float, high: float) -> float:
    try:
        value = float(raw)
    except ValueError:
        raise DiskGuardError(f"{name} must be a number") from None
    if not low <= value <= high:
        raise DiskGuardError(f"{name} must be between {low:g} and {high:g}")
    return value


def max_db_bytes(env: Mapping[str, str] | None = None) -> int:
    """The database size ceiling in bytes (``DB_MAX_SIZE_MB`` wins when set, for tests)."""
    e = os.environ if env is None else env
    mb = (e.get("DB_MAX_SIZE_MB") or "").strip()
    if mb:
        return int(_number(mb, "DB_MAX_SIZE_MB", 1, MAX_MAX_GB * 1024) * 1024 * 1024)
    gb = (e.get("DB_MAX_SIZE_GB") or "").strip()
    value = _number(gb, "DB_MAX_SIZE_GB", MIN_MAX_GB, MAX_MAX_GB) if gb else DEFAULT_MAX_GB
    return int(value * 1024**3)


def apply_disk_guard(conn: Connection, env: Mapping[str, str] | None = None) -> int:
    """(Re)create the guard job with the configured ceiling. Idempotent. Returns the ceiling."""
    limit = max_db_bytes(env)
    conn.execute(
        text("SELECT delete_job(job_id) FROM timescaledb_information.jobs WHERE proc_name = :p"),
        {"p": GUARD_PROC},
    )
    conn.execute(
        text(
            f"SELECT add_job('{GUARD_PROC}', INTERVAL '{GUARD_INTERVAL}', "
            "config => jsonb_build_object('max_bytes', CAST(:b AS bigint)))"
        ),
        {"b": limit},
    )
    return limit

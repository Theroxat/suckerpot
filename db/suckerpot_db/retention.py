"""Data retention: raw events expire, aggregates stay, disk usage stays bounded.

Policies (all TimescaleDB background jobs, applied idempotently with ``RETENTION_DAYS``):

* events older than ``RETENTION_DAYS`` are dropped (whole chunks, no row-by-row delete);
* events chunks older than 7 days are compressed (segmented by sensor, ordered by time);
* the continuous aggregates are refreshed hourly over a short recent window only, so buckets
  whose raw rows were dropped are never recomputed and the aggregates are kept forever;
* a maintenance job rolls old sessions up into ``sessions_daily``, then deletes them, and
  prunes the enrichment caches.

Called from migration 0004 (policies only, inside its transaction) and from the migrate
entrypoint after every upgrade (policies, then a bounded aggregate backfill on an autocommit
connection, because a refresh cannot run inside a transaction block).
"""

from __future__ import annotations

import os
from collections.abc import Mapping

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError

DEFAULT_RETENTION_DAYS = 90
MIN_RETENTION_DAYS = 7
MAX_RETENTION_DAYS = 3650
COMPRESS_AFTER_DAYS = 7
DEFAULT_INDICATOR_MAX_ROWS = 500_000
REFRESH_WINDOW_DAYS = 3
MAINTENANCE_PROC = "suckerpot_maintenance"
INDICATOR_PRUNE_PROC = "suckerpot_indicator_prune"  # created by migration 0009
AUDIT_PRUNE_PROC = "suckerpot_audit_prune"  # created by migration 0010
AUDIT_RETENTION_DAYS = 365

# Name of each continuous aggregate with its bucket width.
AGGREGATES: dict[str, str] = {
    "events_hourly": "1 hour",
    "events_daily_tags": "1 day",
    "events_daily_country": "1 day",
    "events_daily_ip": "1 day",
}


class RetentionError(RuntimeError):
    """Raised with a sanitized message (never contains a secret)."""


def retention_days(env: Mapping[str, str] | None = None) -> int:
    """Parse ``RETENTION_DAYS`` (default 90, range 7 to 3650)."""
    e = os.environ if env is None else env
    raw = (e.get("RETENTION_DAYS") or "").strip()
    if not raw:
        return DEFAULT_RETENTION_DAYS
    try:
        days = int(raw)
    except ValueError:
        raise RetentionError("RETENTION_DAYS must be an integer number of days") from None
    if not MIN_RETENTION_DAYS <= days <= MAX_RETENTION_DAYS:
        raise RetentionError(
            f"RETENTION_DAYS must be between {MIN_RETENTION_DAYS} and {MAX_RETENTION_DAYS}"
        )
    return days


def indicator_max_rows(env: Mapping[str, str] | None = None) -> int:
    """Parse ``INDICATORS_MAX_ROWS`` (default 500000, range 1000 to 50 million)."""
    e = os.environ if env is None else env
    raw = (e.get("INDICATORS_MAX_ROWS") or "").strip()
    if not raw:
        return DEFAULT_INDICATOR_MAX_ROWS
    try:
        rows = int(raw)
    except ValueError:
        raise RetentionError("INDICATORS_MAX_ROWS must be an integer") from None
    if not 1000 <= rows <= 50_000_000:
        raise RetentionError("INDICATORS_MAX_ROWS must be between 1000 and 50000000")
    return rows


def apply_policies(conn: Connection, days: int, indicator_rows: int | None = None) -> None:
    """(Re)create every background job with the configured retention. Idempotent."""
    # The compression window is fixed; retention is validated to be at least as long.
    conn.execute(
        text("SELECT remove_retention_policy('events', if_exists => true)"),
    )
    conn.execute(
        text("SELECT add_retention_policy('events', drop_after => make_interval(days => :d))"),
        {"d": days},
    )
    conn.execute(text("SELECT remove_compression_policy('events', if_exists => true)"))
    conn.execute(
        text(
            "SELECT add_compression_policy('events', compress_after => make_interval(days => :d))"
        ),
        {"d": COMPRESS_AFTER_DAYS},
    )
    for view in AGGREGATES:
        conn.execute(
            text(f"SELECT remove_continuous_aggregate_policy('{view}', if_exists => true)")
        )
        conn.execute(
            text(
                f"SELECT add_continuous_aggregate_policy('{view}', "
                "start_offset => make_interval(days => :w), "
                "end_offset => INTERVAL '1 hour', "
                "schedule_interval => INTERVAL '1 hour')"
            ),
            {"w": REFRESH_WINDOW_DAYS},
        )
    conn.execute(
        text("SELECT delete_job(job_id) FROM timescaledb_information.jobs WHERE proc_name = :p"),
        {"p": MAINTENANCE_PROC},
    )
    conn.execute(
        text(
            f"SELECT add_job('{MAINTENANCE_PROC}', INTERVAL '1 hour', "
            "config => jsonb_build_object('retention_days', CAST(:d AS integer)))"
        ),
        {"d": days},
    )
    # Indicators expire with the raw events. The procedure only exists from migration 0009 on.
    conn.execute(
        text("SELECT delete_job(job_id) FROM timescaledb_information.jobs WHERE proc_name = :p"),
        {"p": INDICATOR_PRUNE_PROC},
    )
    exists = conn.execute(
        text("SELECT to_regprocedure(:p) IS NOT NULL"),
        {"p": f"{INDICATOR_PRUNE_PROC}(integer, jsonb)"},
    ).scalar()
    if exists:
        conn.execute(
            text(
                f"SELECT add_job('{INDICATOR_PRUNE_PROC}', INTERVAL '1 hour', "
                "config => jsonb_build_object('retention_days', CAST(:d AS integer), "
                "'max_rows', CAST(:r AS bigint)))"
            ),
            {"d": days, "r": indicator_rows or DEFAULT_INDICATOR_MAX_ROWS},
        )
    # The audit log is kept for a year, whatever RETENTION_DAYS says. The procedure only exists
    # from migration 0010 on.
    conn.execute(
        text("SELECT delete_job(job_id) FROM timescaledb_information.jobs WHERE proc_name = :p"),
        {"p": AUDIT_PRUNE_PROC},
    )
    audit_exists = conn.execute(
        text("SELECT to_regprocedure(:p) IS NOT NULL"),
        {"p": f"{AUDIT_PRUNE_PROC}(integer, jsonb)"},
    ).scalar()
    if audit_exists:
        conn.execute(
            text(
                f"SELECT add_job('{AUDIT_PRUNE_PROC}', INTERVAL '1 day', "
                "config => jsonb_build_object('retention_days', CAST(:d AS integer)))"
            ),
            {"d": AUDIT_RETENTION_DAYS},
        )


def backfill(conn: Connection, days: int) -> None:
    """Materialise the aggregates for the retention window (needs an autocommit connection).

    The window starts at the retention cutoff, but never before the oldest raw event: chunks
    are dropped oldest first, and refreshing a region whose raw rows are gone would erase the
    aggregates that were kept on purpose (also after RETENTION_DAYS was raised). Only regions
    with pending invalidations are recomputed, so repeated calls are cheap.
    """
    oldest = conn.execute(text("SELECT date_trunc('day', min(ts), 'UTC') FROM events")).scalar()
    if oldest is None:
        return
    for view in AGGREGATES:
        conn.execute(
            text(
                f"CALL refresh_continuous_aggregate('{view}', "
                "greatest(CAST(:oldest AS timestamptz), "
                "date_trunc('day', now() - make_interval(days => :d), 'UTC')), "
                "date_trunc('day', now(), 'UTC') + INTERVAL '1 day')"
            ),
            {"d": days, "oldest": oldest},
        )


def apply_retention(conn: Connection, env: Mapping[str, str] | None = None) -> int:
    """Apply policies and backfill for ``RETENTION_DAYS``. ``conn`` must be autocommit."""
    days = retention_days(env)
    try:
        apply_policies(conn, days, indicator_max_rows(env))
        backfill(conn, days)
    except DBAPIError as exc:
        code = getattr(exc.orig, "sqlstate", None)
        raise RetentionError(f"applying retention policies failed (SQLSTATE {code})") from None
    return days

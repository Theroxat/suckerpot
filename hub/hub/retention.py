"""Retention (design M29 invariant H3). The hub keeps as little as the protocol allows.

* per-node observations: ``HUB_OBS_RETENTION_DAYS`` (14), day granularity;
* batch markers: 14 days; nonces and challenges: until they expire (10 minutes);
* contributor links: when the target is resolved or after 30 days;
* takedown votes: 30 days; weekly statistics: 8 weeks;
* nodes with no request for 30 days are deleted with everything linked to them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings

RESOLVED_STATES = ("taken_down", "expired", "disputed")
RESOLVED_GRACE = timedelta(days=2)  # lets the daily reputation job read the links first
EXPIRED_TARGET_DAYS = 180
CANDIDATE_DAYS = 14
RECIPIENT_LOG_DAYS = 90
REPORT_DAYS = 365


@dataclass
class RetentionResult:
    deleted: dict[str, int] = field(default_factory=dict)


async def _delete(
    session: AsyncSession, name: str, sql: str, params: dict[str, object], out: RetentionResult
) -> None:
    result = await session.execute(text(sql), params)
    out.deleted[name] = int(getattr(result, "rowcount", 0) or 0)


async def run_retention(
    session: AsyncSession, s: Settings, now: datetime, today: date
) -> RetentionResult:
    out = RetentionResult()
    obs_cutoff = today - timedelta(days=s.obs_retention_days)
    await _delete(
        session, "observations", "DELETE FROM observations WHERE day < :c", {"c": obs_cutoff}, out
    )
    await _delete(
        session,
        "batches",
        "DELETE FROM batches WHERE day < :c",
        {"c": today - timedelta(days=14)},
        out,
    )
    await _delete(session, "nonces", "DELETE FROM nonces WHERE expires_at < :n", {"n": now}, out)
    await _delete(
        session, "challenges", "DELETE FROM enrol_challenges WHERE expires_at < :n", {"n": now}, out
    )
    await _delete(
        session,
        "contributors",
        """
        DELETE FROM target_contributors tc USING targets t
        WHERE t.id = tc.target_id
          AND ((t.state = ANY(:resolved) AND t.updated_at < :grace)
               OR coalesce(t.confirmed_day, t.first_day) < :old)
        """,
        {
            "resolved": list(RESOLVED_STATES),
            "grace": now - RESOLVED_GRACE,
            "old": today - timedelta(days=s.contributor_retention_days),
        },
        out,
    )
    await _delete(
        session,
        "votes",
        "DELETE FROM takedown_votes WHERE day < :c",
        {"c": today - timedelta(days=s.vote_retention_days)},
        out,
    )
    await _delete(
        session,
        "candidates",
        "DELETE FROM targets WHERE state = 'candidate' AND coalesce(last_day, first_day) < :c",
        {"c": today - timedelta(days=CANDIDATE_DAYS)},
        out,
    )
    await _delete(
        session,
        "old_targets",
        "DELETE FROM targets WHERE state = 'expired' AND updated_at < :c",
        {"c": now - timedelta(days=EXPIRED_TARGET_DAYS)},
        out,
    )
    await _delete(
        session,
        "recipient_log",
        "DELETE FROM recipient_log WHERE day < :c",
        {"c": today - timedelta(days=RECIPIENT_LOG_DAYS)},
        out,
    )
    await _delete(
        session,
        "reports",
        "DELETE FROM reports WHERE state IN ('sent', 'failed', 'cancelled') AND created_day < :c",
        {"c": today - timedelta(days=REPORT_DAYS)},
        out,
    )
    await _delete(
        session,
        "inactive_nodes",
        "DELETE FROM nodes WHERE last_active_day < :c",
        {"c": today - timedelta(days=s.inactive_node_days)},
        out,
    )
    await session.commit()
    return out

"""M16: scoring of recorded indicators into ``blocklist_entries``.

Every cycle reads the last ``BLOCKLIST_WINDOW_DAYS`` of sessions and indicators, scores them
(``blocklist.scoring``), applies the overrides an administrator set, and rewrites the table.
Entries that no longer qualify are deleted. Everything runs inside the database: nothing is
resolved, fetched or contacted, and addresses that must never be listed (private, loopback,
reserved) and shared hosting names are dropped before they reach the table.

Row budgets: at most ``BLOCKLIST_MAX_ROWS`` entries, and the candidate queries are capped so one
cycle cannot grow with the table sizes. Each cycle runs in one transaction with a 30 s statement
timeout.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db.blocklist_values import is_shared_host, normalize_value
from suckerpot_db.models import BlocklistEntryRow

from ingest.blocklist.scoring import (
    MIN_LISTED_SCORE,
    IndicatorFacts,
    IpFacts,
    score_indicator,
    score_ip,
)
from ingest.features import FeatureSettings, FeatureWorker

log = logging.getLogger(__name__)

IP_CANDIDATES = 100_000
INDICATOR_CANDIDATES = 50_000
CHUNK = 2_000
WRITE_CHUNK = 1_000
STATEMENT_TIMEOUT = "30s"


@dataclass(slots=True)
class Candidate:
    kind: str
    value: str
    score: int
    reasons: list[str]
    first_seen: datetime
    last_seen: datetime
    sessions: int = 0
    sources: int = 0
    campaign_ids: list[int] = field(default_factory=list)
    benign: bool = False
    demo: bool = False


def _chunks(items: Sequence[str], size: int) -> list[Sequence[str]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


async def _ip_candidates(db: AsyncSession, cutoff: datetime) -> list[Candidate]:
    rows = (
        (
            await db.execute(
                text(
                    """
                    SELECT host(src_ip) AS ip, count(*) AS sessions,
                           count(DISTINCT sensor) AS sensors,
                           min(started_at) AS first_seen, max(last_event_at) AS last_seen,
                           coalesce(sum(login_attempts), 0) AS login_attempts,
                           bool_or(login_success) AS login_success,
                           coalesce(sum(commands), 0) AS commands,
                           coalesce(sum(downloads), 0) AS downloads,
                           max(abuse_score) AS max_abuse,
                           coalesce(bool_or(known_scanner), false) AS known_scanner,
                           bool_and(benign) AS benign,
                           coalesce(array_agg(DISTINCT campaign_id)
                                    FILTER (WHERE campaign_id IS NOT NULL), '{}') AS campaigns
                    FROM sessions
                    WHERE started_at >= :cutoff
                    GROUP BY src_ip
                    ORDER BY max(last_event_at) DESC
                    LIMIT :n
                    """
                ),
                {"cutoff": cutoff, "n": IP_CANDIDATES},
            )
        )
        .mappings()
        .all()
    )
    ips = [str(r["ip"]) for r in rows]
    tags: dict[str, frozenset[str]] = {}
    demo: dict[str, bool] = {}
    for chunk in _chunks(ips, CHUNK):
        for r in (
            (
                await db.execute(
                    text(
                        """
                        SELECT host(src_ip) AS ip, array_agg(DISTINCT t) AS tags
                        FROM sessions s CROSS JOIN LATERAL unnest(s.tags) AS t
                        WHERE s.started_at >= :cutoff
                          AND s.src_ip = ANY(CAST(CAST(:ips AS text[]) AS inet[]))
                        GROUP BY s.src_ip
                        """
                    ),
                    {"cutoff": cutoff, "ips": list(chunk)},
                )
            )
            .mappings()
            .all()
        ):
            tags[str(r["ip"])] = frozenset(r["tags"])
        for r in (
            (
                await db.execute(
                    text(
                        """
                        SELECT host(src_ip) AS ip,
                               bool_and(coalesce(data ->> 'demo', 'false') = 'true') AS demo
                        FROM events
                        WHERE type = 'connect' AND ts >= :cutoff
                          AND src_ip = ANY(CAST(CAST(:ips AS text[]) AS inet[]))
                        GROUP BY src_ip
                        """
                    ),
                    {"cutoff": cutoff, "ips": list(chunk)},
                )
            )
            .mappings()
            .all()
        ):
            demo[str(r["ip"])] = bool(r["demo"])
    out: list[Candidate] = []
    for r in rows:
        value = normalize_value("ip", str(r["ip"]))
        if value is None:
            continue
        campaigns = [int(c) for c in r["campaigns"]][:64]
        scored = score_ip(
            IpFacts(
                sessions=int(r["sessions"]),
                sensors=int(r["sensors"]),
                login_attempts=int(r["login_attempts"]),
                login_success=bool(r["login_success"]),
                commands=int(r["commands"]),
                downloads=int(r["downloads"]),
                max_abuse=None if r["max_abuse"] is None else int(r["max_abuse"]),
                known_scanner=bool(r["known_scanner"]),
                in_campaign=bool(campaigns),
                tags=tags.get(str(r["ip"]), frozenset()),
            )
        )
        out.append(
            Candidate(
                "ip",
                value,
                scored.score,
                scored.reasons,
                r["first_seen"],
                r["last_seen"],
                int(r["sessions"]),
                int(r["sessions"]),
                campaigns,
                bool(r["benign"]),
                demo.get(str(r["ip"]), False),
            )
        )
    return out


async def _indicator_candidates(db: AsyncSession, cutoff: datetime) -> list[Candidate]:
    rows = (
        (
            await db.execute(
                text(
                    """
                    SELECT i.type, i.value, i.role, i.first_seen, i.last_seen, i.sightings,
                           i.trusted, i.demo,
                           count(DISTINCT l.session_id) AS sessions,
                           count(DISTINCT network(set_masklen(l.src_ip,
                               CASE WHEN family(l.src_ip) = 4 THEN 24 ELSE 48 END))) AS sources,
                           EXISTS (SELECT 1 FROM indicator_intel k
                                   WHERE k.indicator_id = i.id AND k.known) AS known,
                           (SELECT max(k.family) FROM indicator_intel k
                            WHERE k.indicator_id = i.id AND k.known) AS family,
                           coalesce((SELECT array_agg(DISTINCT s.campaign_id)
                                     FROM indicator_sessions l2
                                     JOIN sessions s ON s.session_id = l2.session_id
                                     WHERE l2.indicator_id = i.id
                                       AND s.campaign_id IS NOT NULL), '{}') AS campaigns
                    FROM indicators i
                    LEFT JOIN indicator_sessions l ON l.indicator_id = i.id
                    WHERE i.last_seen >= :cutoff AND i.type IN ('url', 'domain', 'ip', 'hash')
                    GROUP BY i.id
                    ORDER BY i.last_seen DESC
                    LIMIT :n
                    """
                ),
                {"cutoff": cutoff, "n": INDICATOR_CANDIDATES},
            )
        )
        .mappings()
        .all()
    )
    out: list[Candidate] = []
    for r in rows:
        kind = str(r["type"])
        value = normalize_value(kind, str(r["value"]))
        if value is None:
            continue
        campaigns = [int(c) for c in r["campaigns"]][:64]
        scored = score_indicator(
            IndicatorFacts(
                kind=kind,
                role=str(r["role"]),
                sessions=int(r["sessions"]),
                sources=int(r["sources"]),
                sightings=int(r["sightings"]),
                trusted=bool(r["trusted"]),
                known=bool(r["known"]),
                family=r["family"],
                in_campaign=bool(campaigns),
            )
        )
        out.append(
            Candidate(
                kind,
                value,
                scored.score,
                scored.reasons,
                r["first_seen"],
                r["last_seen"],
                int(r["sessions"]),
                int(r["sources"]),
                campaigns,
                False,
                bool(r["demo"]),
            )
        )
    return out


async def _overrides(db: AsyncSession, now: datetime) -> list[dict[str, Any]]:
    rows = (
        (
            await db.execute(
                text(
                    "SELECT kind, value, action, created_at FROM blocklist_overrides "
                    "WHERE expires_at IS NULL OR expires_at > :now"
                ),
                {"now": now},
            )
        )
        .mappings()
        .all()
    )
    return [dict(r) for r in rows]


def apply_overrides(
    candidates: list[Candidate], overrides: Sequence[dict[str, Any]]
) -> list[Candidate]:
    """Drop what an admin allowed; add or raise what an admin blocked (score 100)."""
    by_key = {(c.kind, c.value): c for c in candidates}
    for o in overrides:
        value = normalize_value(str(o["kind"]), str(o["value"]))
        if value is None:
            continue
        key = (str(o["kind"]), value)
        if o["action"] == "allow":
            by_key.pop(key, None)
        elif o["action"] == "block":
            existing = by_key.get(key)
            if existing is not None:
                existing.score = 100
                existing.benign = False
                if "manual-block" not in existing.reasons:
                    existing.reasons = ["manual-block", *existing.reasons][:16]
            else:
                created: datetime = o["created_at"]
                by_key[key] = Candidate(key[0], key[1], 100, ["manual-block"], created, created)
    return list(by_key.values())


def select_top(candidates: list[Candidate], limit: int) -> list[Candidate]:
    listed = [
        c
        for c in candidates
        if c.score >= MIN_LISTED_SCORE
        and not (c.kind == "domain" and is_shared_host(c.value))
        and len(c.value) <= 512
    ]
    listed.sort(key=lambda c: (-c.score, -c.last_seen.timestamp(), c.kind, c.value))
    return listed[:limit]


async def write_entries(db: AsyncSession, entries: Sequence[Candidate], cycle: datetime) -> int:
    for start in range(0, len(entries), WRITE_CHUNK):
        rows = [
            {
                "kind": c.kind,
                "value": c.value,
                "score": c.score,
                "reasons": c.reasons[:16],
                "first_seen": c.first_seen,
                "last_seen": c.last_seen,
                "sessions": c.sessions,
                "sources": c.sources,
                "campaign_ids": c.campaign_ids[:64],
                "benign": c.benign,
                "demo": c.demo,
                "computed_at": cycle,
            }
            for c in entries[start : start + WRITE_CHUNK]
        ]
        stmt = pg_insert(BlocklistEntryRow)
        ex = stmt.excluded
        await db.execute(
            stmt.on_conflict_do_update(
                index_elements=["kind", "value"],
                set_={
                    "score": ex.score,
                    "reasons": ex.reasons,
                    "first_seen": ex.first_seen,
                    "last_seen": ex.last_seen,
                    "sessions": ex.sessions,
                    "sources": ex.sources,
                    "campaign_ids": ex.campaign_ids,
                    "benign": ex.benign,
                    "demo": ex.demo,
                    "computed_at": ex.computed_at,
                },
            ),
            rows,
        )
    result = await db.execute(
        text("DELETE FROM blocklist_entries WHERE computed_at < :cycle"), {"cycle": cycle}
    )
    return int(getattr(result, "rowcount", 0) or 0)


class BlocklistWorker(FeatureWorker):
    name = "blocklist"
    interval_s = 900.0

    def __init__(
        self,
        settings: FeatureSettings,
        factory: async_sessionmaker[AsyncSession] | None = None,
    ) -> None:
        super().__init__(settings, enabled=settings.blocklist_enabled)
        self.factory = factory
        self.entries = 0
        self.removed = 0
        self.last_run_at: datetime | None = None

    async def run_once(self) -> None:
        if self.factory is None:
            return
        now = datetime.now(UTC)
        cutoff = now - timedelta(days=self.settings.blocklist_window_days)
        async with self.factory() as db, db.begin():
            await db.execute(text(f"SET LOCAL statement_timeout = '{STATEMENT_TIMEOUT}'"))
            candidates = await _ip_candidates(db, cutoff)
            candidates += await _indicator_candidates(db, cutoff)
            candidates = apply_overrides(candidates, await _overrides(db, now))
            top = select_top(candidates, self.settings.blocklist_max_rows)
            self.removed = await write_entries(db, top, now)
            self.entries = len(top)
        self.last_run_at = now

    async def status(self) -> dict[str, Any]:
        base = await super().status()
        if not self.enabled:
            return base
        base[self.name].update(
            {
                "entries": self.entries,
                "removed_last_run": self.removed,
                "last_run_at": self.last_run_at.isoformat() if self.last_run_at else None,
            }
        )
        return base

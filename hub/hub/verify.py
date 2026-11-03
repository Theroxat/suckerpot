"""Link verification (design M32 section 7): tasks for nodes with the ``verifier`` role.

Two parts share this module.

* The API side (``routes/verify.py`` and the reveal branch of ``routes/targets.py``) lists the
  links a node can reveal, stores a revealed link in ``verify_tasks`` after the cheap checks
  (scheme, public host, never-list, length), leases tasks to verifiers and stores attestations.
* The worker side (``run``, hourly after consensus) creates tasks from links that at least
  ``HUB_VERIFY_MIN_REPORTERS`` eligible nodes reported, validates revealed links against the feed
  exclusions and the caps, schedules them (review queue or a random delay), returns expired leases
  to the queue, expires stale tasks and keeps the daily counters.

Invariants: off unless ``HUB_VERIFY_MODE`` is ``review`` or ``auto`` (H8); a task holds no node id
except the live lease, and a clear link is deleted with its task (H9, see ``retention``). A
verifier's attestation is never a sighting: the reporter count comes from observations only.
"""

from __future__ import annotations

import ipaddress
import random
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Final
from urllib.parse import urlsplit

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_netproto.models import MAX_VERIFY_REVEALS, MAX_VERIFY_TASKS

from . import abusech, consensus
from .config import Settings
from .feeds.filter import NEVER as EXCL_NEVER
from .malware import SQL_MALWARE_LIKE, is_malware_like, sql_params
from .never import Never

ROLE: Final = "verifier"
MAX_URL: Final = 1024
PER_CYCLE: Final = 500
ADMIT_PER_CYCLE: Final = 200
STALE_DAYS: Final = 3

# Refusal codes (constants, never free text).
R_LENGTH: Final = "length"
R_SCHEME: Final = "scheme"
R_PRIVATE: Final = "private"
R_HOST: Final = "host"
R_CREDENTIALS: Final = "credentials"
R_NEVER: Final = "never_list"
R_SHARED: Final = "shared_host"
R_EXCLUDED: Final = "excluded"
R_HOST_CAP: Final = "host_cap"
R_DAILY_CAP: Final = "daily_cap"
R_OPERATOR: Final = "operator"

OPEN_STATES: Final = ("waiting_reveal", "pending_review", "queued")
# Outcomes after which another attempt (by another verifier or later) is worthwhile.
RETRY_OUTCOMES: Final = frozenset({"unreachable", "http_error", "timeout", "skipped"})

_REFUSAL_MAP: Final = {
    "length": R_LENGTH,
    "scheme": R_SCHEME,
    "private": R_PRIVATE,
    "host": R_HOST,
    "local_name": R_HOST,
    "numeric_host": R_HOST,
}


def new_task_id() -> str:
    return "v_" + secrets.token_hex(6)


def site_of(url: str) -> str:
    """Lower-cased host of a canonical URL (no port, no brackets, no trailing dot)."""
    return (urlsplit(url).hostname or "").lower().rstrip(".")


def basic_refusal(url: str, never: Never, *, allow_documentation: bool) -> str | None:
    """Checks that need no feed tables: length, scheme, public host, no credentials, never-list.

    Documentation ranges and every non-global address are refused unless the test overlay
    ``HUB_ALLOW_DOCUMENTATION`` is set.
    """
    why = abusech.url_refusal(url, allow_documentation=allow_documentation)
    if why is not None:
        return _REFUSAL_MAP.get(why, R_HOST)
    parts = urlsplit(url)
    if parts.username is not None or parts.password is not None:
        return R_CREDENTIALS
    if never.has_url(url):
        return R_NEVER
    return None


def utc_stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


# ------------------------------------------------------------------ API side


async def is_verifier(session: AsyncSession, node_id: uuid.UUID) -> bool:
    row = await session.execute(
        text("SELECT 1 FROM node_roles WHERE node_id = :n AND role = :r"),
        {"n": node_id, "r": ROLE},
    )
    return row.first() is not None


async def reveal_refs(
    session: AsyncSession, s: Settings, node_id: uuid.UUID, today: date
) -> list[str]:
    """Blinded links THIS node reported recently that wait for their clear value."""
    if not s.verify_enabled:
        return []
    rows = await session.execute(
        text(
            """
            SELECT DISTINCT t.url_b FROM verify_tasks t
            JOIN observations o ON o.kind = 'url' AND o.value = t.url_b
              AND o.node_id = :n AND o.day >= :since
            WHERE t.url IS NULL AND t.state IN ('waiting_reveal', 'attested')
            ORDER BY t.url_b LIMIT :lim
            """
        ),
        {
            "n": node_id,
            "since": today - timedelta(days=s.verify_url_max_age_days),
            "lim": MAX_VERIFY_REVEALS,
        },
    )
    return [r[0] for r in rows]


async def accept_reveal(
    session: AsyncSession,
    s: Settings,
    node_id: uuid.UUID,
    value_b: str,
    canonical: str,
    today: date,
    never: Never,
) -> bool:
    """Store the clear link of a task the caller reported. True when the task took it.

    A link that fails the cheap checks refuses the task (the value itself is not stored). The
    exclusions and the caps are applied by the worker (``admit``), which has the feed tables.
    """
    if not s.verify_enabled:
        return False
    row = (
        await session.execute(
            text(
                """
                SELECT t.state FROM verify_tasks t
                WHERE t.url_b = :b AND t.url IS NULL AND t.state IN ('waiting_reveal', 'attested')
                  AND EXISTS (SELECT 1 FROM observations o WHERE o.kind = 'url'
                              AND o.value = t.url_b AND o.node_id = :n AND o.day >= :since)
                """
            ),
            {
                "b": value_b,
                "n": node_id,
                "since": today - timedelta(days=s.verify_url_max_age_days),
            },
        )
    ).first()
    if row is None:
        return False
    why = basic_refusal(canonical, never, allow_documentation=s.allow_documentation)
    if why is not None:
        if row[0] == "waiting_reveal":
            await session.execute(
                text(
                    "UPDATE verify_tasks SET state = 'refused', refusal = :r, ended_day = :d "
                    "WHERE url_b = :b AND state = 'waiting_reveal' AND url IS NULL"
                ),
                {"r": why, "d": today, "b": value_b},
            )
        return False
    result = await session.execute(
        text(
            "UPDATE verify_tasks SET url = :u, site = :h, revealed_day = :d "
            "WHERE url_b = :b AND url IS NULL AND state IN ('waiting_reveal', 'attested')"
        ),
        {"u": canonical, "h": site_of(canonical), "d": today, "b": value_b},
    )
    return bool(getattr(result, "rowcount", 0))


@dataclass(frozen=True)
class Leased:
    id: str
    url: str
    lease_until: datetime


async def lease_tasks(
    session: AsyncSession, s: Settings, node_id: uuid.UUID, now: datetime, limit: int
) -> list[Leased]:
    """Hand out up to ``limit`` tasks: this node's live leases first, then queued ones."""
    if not s.verify_enabled:
        return []
    limit = min(limit, MAX_VERIFY_TASKS)
    until = now + timedelta(hours=s.verify_lease_hours)
    own = (
        await session.execute(
            text(
                "SELECT id, url, lease_until FROM verify_tasks WHERE state = 'leased' "
                "AND lease_node = :n AND lease_until > :now AND url IS NOT NULL "
                "ORDER BY id LIMIT :lim"
            ),
            {"n": node_id, "now": now, "lim": limit},
        )
    ).all()
    out = [Leased(r[0], r[1], r[2]) for r in own]
    if len(out) < limit:
        fresh = (
            await session.execute(
                text(
                    """
                    WITH picked AS (
                      SELECT t.id FROM verify_tasks t
                      WHERE t.state = 'queued' AND t.url IS NOT NULL
                        AND (t.release_at IS NULL OR t.release_at <= :now)
                        AND NOT EXISTS (SELECT 1 FROM verify_attestations a
                                        WHERE a.task_id = t.id AND a.node_id = :n)
                      ORDER BY t.release_at NULLS FIRST, t.id
                      LIMIT :lim FOR UPDATE SKIP LOCKED)
                    UPDATE verify_tasks v SET state = 'leased', lease_node = :n,
                      lease_until = :until
                    FROM picked WHERE v.id = picked.id
                    RETURNING v.id, v.url, v.lease_until
                    """
                ),
                {"n": node_id, "now": now, "lim": limit - len(out), "until": until},
            )
        ).all()
        out += [Leased(r[0], r[1], r[2]) for r in fresh]
    return out


@dataclass
class ResultItem:
    id: str
    outcome: str
    sha256: str | None = None
    size: int | None = None
    file_type: str | None = None
    family: str | None = None


async def record_result(
    session: AsyncSession, s: Settings, node_id: uuid.UUID, item: ResultItem, now: datetime
) -> bool:
    """Store one verifier answer. False when the task is not leased to this node."""
    task = (
        await session.execute(
            text("SELECT state, lease_node, attempts FROM verify_tasks WHERE id = :i FOR UPDATE"),
            {"i": item.id},
        )
    ).first()
    if task is None or task[0] != "leased" or task[1] != node_id:
        return False
    today = now.date()
    like = item.outcome == "fetched" and is_malware_like(
        [item.family] if item.family else None, item.file_type
    )
    stored = await session.execute(
        text(
            "INSERT INTO verify_attestations (task_id, node_id, day, outcome, sha256, size, "
            "file_type, family, malware_like) VALUES (:t, :n, :d, :o, :h, :z, :f, :fam, :m) "
            "ON CONFLICT DO NOTHING"
        ),
        {
            "t": item.id,
            "n": node_id,
            "d": today,
            "o": item.outcome,
            "h": item.sha256,
            "z": item.size,
            "f": item.file_type,
            "fam": item.family,
            "m": like,
        },
    )
    if not getattr(stored, "rowcount", 0):
        return False
    attempts = int(task[2]) + (1 if item.outcome in RETRY_OUTCOMES else 0)
    if item.outcome == "fetched":
        state, ended = "attested", today
    elif item.outcome in RETRY_OUTCOMES and attempts < s.verify_max_attempts:
        state, ended = "queued", None
    else:
        state, ended = "failed", today
    await session.execute(
        text(
            "UPDATE verify_tasks SET state = :s, attempts = :a, ended_day = :e, release_at = :r, "
            "lease_node = NULL, lease_until = NULL WHERE id = :i"
        ),
        {
            "s": state,
            "a": attempts,
            "e": ended,
            "r": now if state == "queued" else None,
            "i": item.id,
        },
    )
    return True


# ---------------------------------------------------------------- worker side


@dataclass
class VerifyResult:
    created: int = 0
    refreshed: int = 0
    self_attested: int = 0
    leases_returned: int = 0
    leases_failed: int = 0
    expired: int = 0
    admitted: int = 0
    refused: dict[str, int] = field(default_factory=dict)
    waiting: int = 0

    def refuse(self, code: str) -> None:
        self.refused[code] = self.refused.get(code, 0) + 1


async def _end_leases(session: AsyncSession, s: Settings, now: datetime, out: VerifyResult) -> None:
    """Step 4: an expired lease returns the task to the queue, or fails it after the last try."""
    failed = await session.execute(
        text(
            "UPDATE verify_tasks SET state = 'failed', attempts = attempts + 1, ended_day = :d, "
            "lease_node = NULL, lease_until = NULL "
            "WHERE state = 'leased' AND lease_until <= :now AND attempts + 1 >= :max"
        ),
        {"d": now.date(), "now": now, "max": s.verify_max_attempts},
    )
    out.leases_failed = int(getattr(failed, "rowcount", 0) or 0)
    back = await session.execute(
        text(
            "UPDATE verify_tasks SET state = 'queued', attempts = attempts + 1, release_at = :now, "
            "lease_node = NULL, lease_until = NULL WHERE state = 'leased' AND lease_until <= :now"
        ),
        {"now": now},
    )
    out.leases_returned = int(getattr(back, "rowcount", 0) or 0)


async def _create(session: AsyncSession, s: Settings, today: date, out: VerifyResult) -> None:
    """Step 2: tasks (and fresh counts) for links ``verify_min_reporters`` eligible nodes saw."""
    eligible = await consensus.eligible_nodes(session, s, today)
    if not eligible:
        return
    rows = (
        await session.execute(
            text(
                """
                SELECT o.value AS b, array_agg(DISTINCT o.node_id) AS nodes, max(o.day) AS last_day
                FROM observations o
                WHERE o.kind = 'url' AND o.day >= :since AND o.node_id = ANY(:eligible)
                  AND o.value ~ '^[0-9a-f]{64}$'
                  AND NOT EXISTS (
                    SELECT 1 FROM targets tg JOIN abusech_submissions a
                      ON a.kind = 'urlhaus' AND a.indicator = tg.value
                    WHERE tg.kind = 'url' AND tg.value_b = o.value)
                GROUP BY o.value HAVING count(DISTINCT o.node_id) >= :minr
                ORDER BY max(o.day) DESC, o.value LIMIT :lim
                """
            ),
            {
                "since": today - timedelta(days=s.verify_url_max_age_days),
                "eligible": list(eligible),
                "minr": max(2, s.verify_min_reporters),
                "lim": PER_CYCLE,
            },
        )
    ).all()
    known = {
        r[0]: r[1]
        for r in await session.execute(
            text("SELECT url_b, state FROM verify_tasks WHERE url_b = ANY(:b)"),
            {"b": [r.b for r in rows]},
        )
    }
    for r in rows:
        cohorts = len({eligible[n].cohort for n in r.nodes if n in eligible})
        params = {
            "b": r.b,
            "n": len(r.nodes),
            "c": cohorts,
            "d": r.last_day,
            "today": today,
            "id": new_task_id(),
        }
        if r.b not in known:
            await session.execute(
                text(
                    "INSERT INTO verify_tasks (id, url_b, state, reporters, reporter_cohorts, "
                    "last_report_day, created_day) VALUES (:id, :b, 'waiting_reveal', :n, :c, "
                    ":d, :today) ON CONFLICT (url_b) DO NOTHING"
                ),
                params,
            )
            out.created += 1
        elif known[r.b] in OPEN_STATES:
            await session.execute(
                text(
                    "UPDATE verify_tasks SET reporters = :n, reporter_cohorts = :c, "
                    "last_report_day = greatest(last_report_day, :d) WHERE url_b = :b"
                ),
                params,
            )
            out.refreshed += 1


async def _self_attest(session: AsyncSession, today: date, since: date, out: VerifyResult) -> None:
    """Step 6: a verifier's own batch row (fetched, malware-like) is its attestation."""
    rows = (
        await session.execute(
            text(
                f"""
                SELECT DISTINCT ON (t.id) t.id, o.node_id, o.file_type,
                       (SELECT f FROM unnest(o.families) AS f
                        WHERE f = ANY(CAST(:mal_families AS text[])) ORDER BY f LIMIT 1) AS family
                FROM verify_tasks t
                JOIN observations o ON o.kind = 'url' AND o.value = t.url_b AND o.fetched
                  AND o.day >= :since
                JOIN node_roles r ON r.node_id = o.node_id AND r.role = 'verifier'
                WHERE t.state IN ('waiting_reveal', 'pending_review', 'queued')
                  AND {SQL_MALWARE_LIKE}
                ORDER BY t.id, o.day DESC
                """  # noqa: S608 - module constants only
            ),
            {"since": since, **sql_params()},
        )
    ).all()
    for r in rows:
        stored = await session.execute(
            text(
                "INSERT INTO verify_attestations (task_id, node_id, day, outcome, file_type, "
                "family, malware_like) VALUES (:t, :n, :d, 'fetched', :f, :fam, true) "
                "ON CONFLICT DO NOTHING"
            ),
            {"t": r.id, "n": r.node_id, "d": today, "f": r.file_type, "fam": r.family},
        )
        if getattr(stored, "rowcount", 0):
            await session.execute(
                text(
                    "UPDATE verify_tasks SET state = 'attested', ended_day = :d, "
                    "lease_node = NULL, lease_until = NULL WHERE id = :i"
                ),
                {"d": today, "i": r.id},
            )
            out.self_attested += 1


async def _expire(session: AsyncSession, today: date, out: VerifyResult) -> None:
    """Step 5: links that nobody reported for three days are rarely alive."""
    res = await session.execute(
        text(
            "UPDATE verify_tasks SET state = 'expired', ended_day = :d "
            "WHERE state IN ('waiting_reveal', 'pending_review', 'queued') "
            "AND last_report_day < :c"
        ),
        {"d": today, "c": today - timedelta(days=STALE_DAYS)},
    )
    out.expired = int(getattr(res, "rowcount", 0) or 0)


async def _admit(
    session: AsyncSession,
    s: Settings,
    now: datetime,
    today: date,
    never: Never,
    rng: random.Random,
    out: VerifyResult,
) -> None:
    """Step 3: validate revealed links against the exclusions and the caps, then schedule."""
    pending = (
        await session.execute(
            text(
                "SELECT id, url, site FROM verify_tasks WHERE state = 'waiting_reveal' "
                "AND url IS NOT NULL ORDER BY revealed_day, id LIMIT :n FOR UPDATE"
            ),
            {"n": ADMIT_PER_CYCLE},
        )
    ).all()
    if not pending:
        return
    excl, stale = await abusech.load_excl(session, s, today)
    admitted_today = int(
        (
            await session.execute(
                text(
                    "SELECT count(*) FROM verify_tasks WHERE revealed_day = :d AND url IS NOT NULL "
                    "AND state NOT IN ('waiting_reveal', 'refused')"
                ),
                {"d": today},
            )
        ).scalar_one()
    )
    for t in pending:
        why = basic_refusal(t.url, never, allow_documentation=s.allow_documentation)
        if why is None:
            reason = abusech.excluded_reason(excl, abusech.URLHAUS, t.url)
            if reason is not None:
                why = R_SHARED if reason == EXCL_NEVER else R_EXCLUDED
            elif stale and _is_ip_literal(t.site):
                out.waiting += 1  # CDN and Tor ranges cannot be trusted: wait, do not refuse
                continue
        if why is None:
            on_site = int(
                (
                    await session.execute(
                        text(
                            "SELECT count(*) FROM verify_tasks WHERE site = :h AND "
                            "revealed_day = :d AND state NOT IN ('waiting_reveal', 'refused')"
                        ),
                        {"h": t.site, "d": today},
                    )
                ).scalar_one()
            )
            if on_site >= s.verify_host_daily_cap:
                why = R_HOST_CAP
            elif admitted_today >= s.verify_daily_cap:
                why = R_DAILY_CAP
        if why is not None:
            await session.execute(
                text(
                    "UPDATE verify_tasks SET state = 'refused', refusal = :r, ended_day = :d "
                    "WHERE id = :i"
                ),
                {"r": why, "d": today, "i": t.id},
            )
            out.refuse(why)
            continue
        if s.verify_mode == "auto":
            delay = rng.uniform(s.verify_delay_min_h, s.verify_delay_max_h)
            state, release = "queued", now + timedelta(hours=delay)
        else:
            state, release = "pending_review", None
        await session.execute(
            text(
                "UPDATE verify_tasks SET state = :s, release_at = :r, revealed_day = :d "
                "WHERE id = :i"
            ),
            {"s": state, "r": release, "d": today, "i": t.id},
        )
        admitted_today += 1
        out.admitted += 1


def _is_ip_literal(host: str | None) -> bool:
    try:
        ipaddress.ip_address((host or "").strip("[]"))
    except ValueError:
        return False
    return True


async def _daily(session: AsyncSession, today: date) -> None:
    """Step 7: recount today's counters from the tables (idempotent)."""
    await session.execute(
        text(
            """
            INSERT INTO verify_daily (day, created, revealed, refused, queued, attested,
                                      malware_like, expired)
            SELECT :d,
              (SELECT count(*) FROM verify_tasks WHERE created_day = :d),
              (SELECT count(*) FROM verify_tasks WHERE revealed_day = :d AND url IS NOT NULL),
              (SELECT count(*) FROM verify_tasks WHERE ended_day = :d AND state = 'refused'),
              (SELECT count(*) FROM verify_tasks WHERE revealed_day = :d AND url IS NOT NULL
                 AND state NOT IN ('waiting_reveal', 'refused', 'expired')),
              (SELECT count(*) FROM verify_attestations WHERE day = :d),
              (SELECT count(*) FROM verify_attestations WHERE day = :d AND malware_like),
              (SELECT count(*) FROM verify_tasks WHERE ended_day = :d AND state = 'expired')
            ON CONFLICT (day) DO UPDATE SET created = EXCLUDED.created,
              revealed = EXCLUDED.revealed, refused = EXCLUDED.refused, queued = EXCLUDED.queued,
              attested = EXCLUDED.attested, malware_like = EXCLUDED.malware_like,
              expired = EXCLUDED.expired
            """
        ),
        {"d": today},
    )


async def run(
    session: AsyncSession,
    s: Settings,
    now: datetime,
    *,
    never: Never,
    rng: random.Random | None = None,
) -> VerifyResult:
    """One worker pass. Does nothing at all while ``HUB_VERIFY_MODE`` is ``off``."""
    out = VerifyResult()
    if not s.verify_enabled:
        return out
    today = now.date()
    rng = rng or random.SystemRandom()
    await _end_leases(session, s, now, out)
    await _create(session, s, today, out)
    await _self_attest(session, today, today - timedelta(days=s.verify_url_max_age_days), out)
    await _expire(session, today, out)
    await _admit(session, s, now, today, never, rng, out)
    await _daily(session, today)
    await session.commit()
    return out

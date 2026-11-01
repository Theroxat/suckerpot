"""Consensus (design M29 section 8.1 and 8.2) and takedown voting (section 7.2).

A value becomes a published target only when enough independent, aged, well-behaved nodes
saw it. The rules are in ``evaluate`` (pure, covered by tests); ``run_consensus`` feeds them from
the database and stores the outcome. Single-node values never get a row: only values seen by at
least two eligible nodes are kept as candidates (never published).
"""

from __future__ import annotations

import logging
import secrets
import uuid
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import date, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings
from .never import Never, split_host_port
from .support import first_day_supported, k_supported, last_day_supported

log = logging.getLogger("hub.consensus")

CANDIDATE_MIN_NODES = 2
TARGET_TTL_DAYS = 30  # a confirmed target nobody saw for this long is expired
CONTRIBUTOR_DAYS = 30
TAKEDOWN_DOWN_NODES = 2
TAKEDOWN_DOWN_DAYS = 3
TAKEDOWN_RETURN_DAYS = 14
RE_REPORT_DAYS = 30
BLINDED = frozenset({"url", "domain", "c2_domain"})
# Kinds that need twice the nodes unless an external source knows them. Only an address can be
# looked up; a blinded value never can, so it always needs twice the nodes.
DOUBLE_KINDS = frozenset({"ip", "c2_ip", "url", "domain", "c2_domain"})
LOOKUP_KINDS = frozenset({"ip", "c2_ip"})
C2_KINDS = frozenset({"c2_ip", "c2_domain"})
MIN_FETCHED_NODES = 2

Corroborate = Callable[[str], Awaitable[bool]]


@dataclass(frozen=True)
class EligibleNode:
    id: uuid.UUID
    reputation: float
    cohort: date  # Monday of the ISO week of enrolment
    country: str | None


@dataclass
class Group:
    kind: str
    value: str
    nodes: set[uuid.UUID] = field(default_factory=set)
    days: set[date] = field(default_factory=set)
    services: set[str] = field(default_factory=set)
    activity: set[str] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)
    families: set[str] = field(default_factory=set)
    days_by_node: dict[uuid.UUID, set[date]] = field(default_factory=dict)
    fetched_nodes: set[uuid.UUID] = field(default_factory=set)
    via: set[str] = field(default_factory=set)
    seen: dict[str, dict[str, set[object]]] = field(
        default_factory=lambda: {"services": {}, "activity": {}, "tags": {}, "families": {}}
    )


@dataclass(frozen=True)
class Verdict:
    confirmed: bool
    reason: str
    weight: float
    countries: int


def cohort_of(enrolled: date) -> date:
    return enrolled - timedelta(days=enrolled.weekday())


async def eligible_nodes(
    session: AsyncSession, s: Settings, today: date
) -> dict[uuid.UUID, EligibleNode]:
    """Nodes whose observations count (section 8.1)."""
    rows = await session.execute(
        text(
            """
            SELECT n.id, n.reputation, n.enrolled_day, n.country FROM nodes n
            WHERE n.standing = 'active'
              AND n.enrolled_day <= :oldest
              AND n.reputation >= CAST(:min_rep AS real)
              AND (SELECT count(*) FROM batches b
                   WHERE b.node_id = n.id AND b.items > 0
                     AND b.day >= :since AND b.day < :today) >= :min_days
            """
        ),
        {
            "oldest": today - timedelta(days=s.node_min_age_days),
            "min_rep": s.min_reputation,
            "since": today - timedelta(days=14),
            "today": today,
            "min_days": s.node_min_active_days,
        },
    )
    return {
        r.id: EligibleNode(r.id, float(r.reputation), cohort_of(r.enrolled_day), r.country)
        for r in rows
    }


def evaluate(
    group: Group,
    eligible: dict[uuid.UUID, EligibleNode],
    s: Settings,
    *,
    never: Never,
    corroborated: bool | None,
    via_ok: bool = True,
) -> Verdict:
    """Apply the confirmation rules to one group. ``corroborated`` is None when not looked up.

    Returns ``reason == "need_corroboration"`` when the only missing piece is the external
    lookup of an address: the caller looks it up and calls again.
    """
    nodes = [eligible[n] for n in group.nodes if n in eligible]
    count = len(nodes)
    weight = sum(min(n.reputation, 1.0) for n in nodes)
    countries = len({n.country for n in nodes if n.country})
    if never.matches(group.kind, group.value):
        return Verdict(False, "never_list", weight, countries)
    if count < s.min_nodes:
        return Verdict(False, "too_few_nodes", weight, countries)
    if weight < s.min_weight:
        return Verdict(False, "too_little_weight", weight, countries)
    if len(group.days) < 2 and count < 2 * s.min_nodes:
        return Verdict(False, "single_day", weight, countries)
    shares = Counter(n.cohort for n in nodes)
    if max(shares.values()) / count > s.cohort_max_share:
        return Verdict(False, "cohort", weight, countries)
    if group.kind in DOUBLE_KINDS and count < 2 * s.min_nodes:
        if group.kind not in LOOKUP_KINDS:
            return Verdict(False, "uncorroborated", weight, countries)
        if corroborated is None:
            return Verdict(False, "need_corroboration", weight, countries)
        if not corroborated:
            return Verdict(False, "uncorroborated", weight, countries)
    if group.kind in C2_KINDS and not via_ok:
        return Verdict(False, "no_dropper", weight, countries)
    return Verdict(True, "confirmed", weight, countries)


async def load_groups(
    session: AsyncSession, s: Settings, today: date, eligible: dict[uuid.UUID, EligibleNode]
) -> dict[tuple[str, str], Group]:
    """Observations of the window, from eligible nodes, for values seen by at least two of them."""
    if not eligible:
        return {}
    since = today - timedelta(days=s.window_days)
    rows = await session.execute(
        text(
            """
            SELECT o.kind, o.value, o.node_id, o.day, o.services, o.activity, o.tags, o.families,
                   o.fetched, o.via
            FROM observations o
            JOIN (SELECT kind, value FROM observations
                  WHERE day >= :since AND day < :today AND node_id = ANY(:nodes)
                  GROUP BY kind, value HAVING count(DISTINCT node_id) >= :least) k
              ON k.kind = o.kind AND k.value = o.value
            WHERE o.day >= :since AND o.day < :today AND o.node_id = ANY(:nodes)
            """
        ),
        {
            "since": since,
            "today": today,
            "nodes": list(eligible),
            "least": CANDIDATE_MIN_NODES,
        },
    )
    groups: dict[tuple[str, str], Group] = {}
    for r in rows:
        g = groups.setdefault((r.kind, r.value), Group(r.kind, r.value))
        g.nodes.add(r.node_id)
        g.days.add(r.day)
        g.services.update(r.services or ())
        g.activity.update(r.activity or ())
        g.tags.update(r.tags or ())
        g.families.update(r.families or ())
        g.days_by_node.setdefault(r.node_id, set()).add(r.day)
        if r.fetched:
            g.fetched_nodes.add(r.node_id)
        if r.via:
            g.via.add(r.via)
        for name in ("services", "activity", "tags", "families"):
            for v in getattr(r, name) or ():
                g.seen[name].setdefault(v, set()).add(r.node_id)
    return groups


_UPSERT = text(
    """
    INSERT INTO targets (id, kind, value, value_b, state, node_count, weight, country_count,
                         first_day, last_day, services, activity, tags, families,
                         confirmed_day, updated_at)
    VALUES (:id, :kind, :value, :value_b, :state, :nodes, :weight, :countries,
            :first_day, :last_day, :services, :activity, :tags, :families, :confirmed_day, now())
    ON CONFLICT (kind, (coalesce(value_b, value))) DO UPDATE SET
      state = CASE WHEN targets.state IN ('candidate', 'expired') AND EXCLUDED.state = 'confirmed'
                   THEN 'confirmed' ELSE targets.state END,
      confirmed_day = CASE WHEN targets.state IN ('candidate', 'expired')
                                AND EXCLUDED.state = 'confirmed'
                           THEN EXCLUDED.confirmed_day ELSE targets.confirmed_day END,
      node_count = CASE WHEN targets.state IN ('candidate', 'expired')
                        THEN EXCLUDED.node_count ELSE targets.node_count END,
      country_count = CASE WHEN targets.state IN ('candidate', 'expired')
                           THEN EXCLUDED.country_count ELSE targets.country_count END,
      weight = EXCLUDED.weight,
      first_day = CASE WHEN targets.state = 'candidate' THEN EXCLUDED.first_day
                       WHEN EXCLUDED.state <> 'confirmed' THEN targets.first_day
                       ELSE LEAST(targets.first_day, EXCLUDED.first_day) END,
      last_day = CASE WHEN targets.state = 'candidate' THEN EXCLUDED.last_day
                      WHEN EXCLUDED.state <> 'confirmed' THEN targets.last_day
                      ELSE GREATEST(targets.last_day, EXCLUDED.last_day) END,
      services = CASE WHEN targets.state = 'candidate' THEN EXCLUDED.services
                 WHEN EXCLUDED.state <> 'confirmed' THEN targets.services
                 ELSE ARRAY(SELECT DISTINCT unnest(targets.services || EXCLUDED.services) ORDER BY 1) END,
      activity = CASE WHEN targets.state = 'candidate' THEN EXCLUDED.activity
                 WHEN EXCLUDED.state <> 'confirmed' THEN targets.activity
                 ELSE ARRAY(SELECT DISTINCT unnest(targets.activity || EXCLUDED.activity) ORDER BY 1) END,
      tags = CASE WHEN targets.state = 'candidate' THEN EXCLUDED.tags
                 WHEN EXCLUDED.state <> 'confirmed' THEN targets.tags
                 ELSE ARRAY(SELECT DISTINCT unnest(targets.tags || EXCLUDED.tags) ORDER BY 1) END,
      families = CASE WHEN targets.state = 'candidate' THEN EXCLUDED.families
                 WHEN EXCLUDED.state <> 'confirmed' THEN targets.families
                 ELSE ARRAY(SELECT DISTINCT unnest(targets.families || EXCLUDED.families) ORDER BY 1) END,
      updated_at = now()
    """
)

_LINK = text(
    """
    INSERT INTO target_contributors (target_id, node_id)
    SELECT t.id, x.node_id
    FROM unnest(CAST(:kinds AS text[]), CAST(:keys AS text[]), CAST(:nodes AS uuid[]))
         AS x(kind, key, node_id)
    JOIN targets t ON t.kind = x.kind AND coalesce(t.value_b, t.value) = x.key
    WHERE t.state IN ('candidate', 'confirmed', 'reported')
      AND coalesce(t.confirmed_day, t.first_day) >= :cutoff
    ON CONFLICT DO NOTHING
    """
)


@dataclass
class ConsensusResult:
    groups: int = 0
    confirmed: int = 0
    candidates: int = 0
    reasons: Counter[str] = field(default_factory=Counter)


async def run_consensus(
    session: AsyncSession,
    s: Settings,
    today: date,
    *,
    never: Never,
    corroborate: Corroborate | None = None,
    eligible: dict[uuid.UUID, EligibleNode] | None = None,
) -> ConsensusResult:
    eligible = eligible if eligible is not None else await eligible_nodes(session, s, today)
    groups = await load_groups(session, s, today, eligible)
    result = ConsensusResult(groups=len(groups))
    upserts: list[dict[str, object]] = []
    link_kinds: list[str] = []
    link_keys: list[str] = []
    link_nodes: list[uuid.UUID] = []
    droppers: set[str] = set()  # sha256 values confirmed in this run and fetched by 2+ nodes
    ordered = sorted(groups.items(), key=lambda kv: kv[0][0] != "sha256")
    for (kind, value), group in ordered:
        via_ok = bool(group.via & droppers)
        verdict = evaluate(group, eligible, s, never=never, corroborated=None, via_ok=via_ok)
        if verdict.reason == "need_corroboration":
            host = split_host_port(value)[0] if kind == "c2_ip" else value
            ok = await corroborate(host) if corroborate is not None else False
            verdict = evaluate(group, eligible, s, never=never, corroborated=ok, via_ok=via_ok)
        if (
            kind == "sha256"
            and verdict.confirmed
            and len(group.fetched_nodes & eligible.keys()) >= MIN_FETCHED_NODES
        ):
            droppers.add(value)
        result.reasons[verdict.reason] += 1
        if verdict.reason == "never_list":
            continue
        state = "confirmed" if verdict.confirmed else "candidate"
        result.confirmed += verdict.confirmed
        result.candidates += not verdict.confirmed
        blinded = kind in BLINDED
        # Published fields use only what k eligible nodes support (see hub.support). A group
        # below k is a candidate and is never published, so it keeps the raw values.
        k = s.min_nodes
        days = sorted(group.days)
        first = first_day_supported(group.days_by_node, k) or days[0]
        last = last_day_supported(group.days_by_node, k) or days[-1]
        if verdict.confirmed:
            fields = {n: sorted(k_supported(group.seen[n], k)) for n in group.seen}
        else:
            fields = {n: sorted(group.seen[n]) for n in group.seen}
        upserts.append(
            {
                "id": "t_" + secrets.token_hex(6),
                "kind": kind,
                "value": None if blinded else value,
                "value_b": value if blinded else None,
                "state": state,
                "nodes": len(group.nodes & eligible.keys()),
                "weight": verdict.weight,
                "countries": verdict.countries,
                "first_day": first,
                "last_day": last,
                **fields,
                "confirmed_day": today if verdict.confirmed else None,
            }
        )
        for node_id in group.nodes & eligible.keys():
            link_kinds.append(kind)
            link_keys.append(value)
            link_nodes.append(node_id)
    if upserts:
        await session.execute(_UPSERT, upserts)
    cutoff = today - timedelta(days=CONTRIBUTOR_DAYS)
    for i in range(0, len(link_nodes), 5000):
        await session.execute(
            _LINK,
            {
                "kinds": link_kinds[i : i + 5000],
                "keys": link_keys[i : i + 5000],
                "nodes": link_nodes[i : i + 5000],
                "cutoff": cutoff,
            },
        )
    await session.commit()
    return result


async def expire_stale(session: AsyncSession, today: date) -> int:
    """Targets nobody has seen for TARGET_TTL_DAYS expire; stale candidates are dropped."""
    old = today - timedelta(days=TARGET_TTL_DAYS)
    expired = await session.execute(
        text(
            "UPDATE targets SET state = 'expired', updated_at = now() "
            "WHERE state IN ('confirmed', 'reported') AND last_day < :old"
        ),
        {"old": old},
    )
    await session.execute(
        text("DELETE FROM targets WHERE state = 'candidate' AND last_day < :cutoff"),
        {"cutoff": today - timedelta(days=14)},
    )
    await session.commit()
    return int(getattr(expired, "rowcount", 0) or 0)


async def recheck_never_list(
    session: AsyncSession, never: Never, s: Settings, today: date
) -> list[str]:
    """Disputes confirmed or reported targets whose clear value is now on the never-list."""
    from .reputation import dispute

    rows = await session.execute(
        text(
            "SELECT id, kind, value FROM targets "
            "WHERE state IN ('confirmed', 'reported') AND value IS NOT NULL"
        )
    )
    hits = [r.id for r in rows if never.matches(r.kind, r.value)]
    for target_id in hits:
        await dispute(session, target_id, s)
    return hits


async def update_takedowns(
    session: AsyncSession, s: Settings, today: date, eligible: dict[uuid.UUID, EligibleNode]
) -> tuple[int, int]:
    """Move reported targets to taken_down (section 7.2) and back. Returns (down, back)."""
    ids = list(eligible)
    down = back = 0
    reported = (
        await session.execute(text("SELECT id, reported_day FROM targets WHERE state = 'reported'"))
    ).all()
    for target in reported:
        votes = (
            await session.execute(
                text(
                    "SELECT node_id, day, state FROM takedown_votes "
                    "WHERE target_id = :t AND day > :rep AND node_id = ANY(:ids)"
                ),
                {"t": target.id, "rep": target.reported_day, "ids": ids},
            )
        ).all()
        downs = [v for v in votes if v.state == "down"]
        down_days = {v.day for v in downs}
        if (
            len({v.node_id for v in downs}) >= TAKEDOWN_DOWN_NODES
            and len(down_days) >= TAKEDOWN_DOWN_DAYS
        ):
            last = max(down_days)
            if not any(v.state == "up" and v.day == last for v in votes):
                await session.execute(
                    text(
                        "UPDATE targets SET state = 'taken_down', taken_down_day = :d, "
                        "updated_at = now() WHERE id = :t AND state = 'reported'"
                    ),
                    {"d": last, "t": target.id},
                )
                down += 1
    taken = (
        await session.execute(
            text("SELECT id, taken_down_day, reported_day FROM targets WHERE state = 'taken_down'")
        )
    ).all()
    for target in taken:
        if target.taken_down_day is None:
            continue
        limit = target.taken_down_day + timedelta(days=TAKEDOWN_RETURN_DAYS)
        came_back = (
            await session.execute(
                text(
                    "SELECT 1 FROM takedown_votes WHERE target_id = :t AND state = 'up' "
                    "AND day > :d AND day <= :limit AND node_id = ANY(:ids) LIMIT 1"
                ),
                {"t": target.id, "d": target.taken_down_day, "limit": limit, "ids": ids},
            )
        ).first()
        if came_back is None:
            continue
        old_report = target.reported_day is not None and target.reported_day <= today - timedelta(
            days=RE_REPORT_DAYS
        )
        await session.execute(
            text(
                "UPDATE targets SET state = :state, taken_down_day = NULL, "
                "reported_day = CASE WHEN :again THEN NULL ELSE reported_day END, "
                "report_id = CASE WHEN :again THEN NULL ELSE report_id END, "
                "updated_at = now() WHERE id = :t"
            ),
            {
                "state": "confirmed" if old_report else "reported",
                "again": old_report,
                "t": target.id,
            },
        )
        back += 1
    await session.commit()
    return down, back

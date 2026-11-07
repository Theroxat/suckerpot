"""Public network observatory (design M34): ``network.json`` on the feed site.

Three parts:

* ``freeze_days``: once a day is final (no batch for it can arrive any more), its network-wide
  aggregates are computed ONCE from ``observations`` into ``observatory_daily``, and never again.
  A node that joins, leaves or sends late therefore cannot move a number that was already
  published, so two versions of the file cannot be subtracted to isolate one node.
* ``load``: reads what the document needs (frozen days, outcome counts, node counts).
* ``render``: a pure function that applies every anonymity rule (tests drive it directly).

``publish`` writes the file atomically next to the feed files. It does not depend on
``HUB_FEED_MODE``: the lists can stay off while the observatory publishes.
"""

from __future__ import annotations

import os
import secrets
import statistics
import uuid
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_netproto import buckets, enums
from suckerpot_netproto.feeds.models import LICENCE
from suckerpot_netproto.feeds.render import dumps_json

from . import consensus
from .config import Settings
from .feeds.publish import FILE_MODE, gz

SCHEMA = "selfhostr-network-stats/1"
FILE = "network.json"

# A batch may be sent up to MAX_BATCH_AGE_DAYS after its day, so a day is final this many days
# after it (the hub refuses older batches). Only final days are frozen and published.
FINAL_LAG_DAYS = buckets.MAX_BATCH_AGE_DAYS + 1
# Outcome counts (confirmations, reports, takedowns) are published with at least 24 h delay:
# the last published day ended at least one full day ago.
OUTCOME_LAG_DAYS = 2
SERIES_DAYS = 90
WINDOW_DAYS = 30
RETENTION_DAYS = 400
# Below this many contributing nodes a figure is coarse: weekly, one significant figure.
MIN_NODES_STANDARD = buckets.MIN_COUNTRIES_SHOWN
# An item (service, tag, family) needs this much support over the window to be named.
ITEM_MIN = 20
# From MIN_NODES_STANDARD nodes up, an item must also have been seen by two nodes on one day.
ITEM_MIN_NODES = 2
TOP_TAGS = 10
TOP_FAMILIES = 10
SHARE_STEP_COARSE = 5
SHARE_STEP_STANDARD = 1

ACTIVITY_FIELDS = ("login", "command", "download", "exploit")
KIND_FIELDS = ("payload_urls", "files", "c2")
SERIES_FIELDS = ("sources", *ACTIVITY_FIELDS, *KIND_FIELDS)
COARSE = "coarse"
STANDARD = "standard"


# --- inputs -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class DayRow:
    """One frozen day: contributing nodes and the distinct counts of ``SERIES_FIELDS``."""

    day: date
    nodes: int
    values: Mapping[str, int]


@dataclass(frozen=True)
class ItemRow:
    """One frozen day of one service, tag or family."""

    day: date
    metric: str  # service | tag | family
    key: str
    total: int
    nodes: int


@dataclass(frozen=True)
class OutcomeDay:
    day: date
    confirmed: int = 0
    reported: int = 0
    taken_down: int = 0


@dataclass
class ObservatoryInput:
    today: date
    min_nodes: int
    members: int = 0
    active_7d: int = 0
    eligible: int = 0
    # Earliest day each candidate node can be eligible (internal: never published per node).
    earliest_eligible: list[date] = field(default_factory=list)
    # Members per country among those who chose to show one (filtered by ``render``).
    country_members: Mapping[str, int] = field(default_factory=dict)
    days: list[DayRow] = field(default_factory=list)
    items: list[ItemRow] = field(default_factory=list)
    outcomes: list[OutcomeDay] = field(default_factory=list)
    reports_sent_30d: int = 0
    abusech_sent_30d: int = 0
    takedown_gaps: list[int] = field(default_factory=list)


# --- rounding and the per-node eligibility estimate (pure) -------------------------------------


def round_figure(n: int, significant: int) -> int:
    """Round half up to ``significant`` figures, never finer than tens (4 -> 0, 5 -> 10)."""
    if n <= 0:
        return 0
    step: int = 10 ** max(1, len(str(n)) - significant)
    return ((n + step // 2) // step) * step


def round_share(part: int, whole: int, step: int) -> int:
    """Percentage of ``whole``, rounded half up to a multiple of ``step``."""
    if whole <= 0 or part <= 0:
        return 0
    return int(part * 100 / whole / step + 0.5) * step


def earliest_eligible(
    today: date,
    enrolled: date,
    batch_days: Iterable[date],
    *,
    min_age_days: int,
    min_active_days: int,
) -> date:
    """First day a node can be eligible if it sends a batch every day from now on.

    Same rule as ``consensus.eligible_nodes``: enrolled at least ``min_age_days`` ago and at least
    ``min_active_days`` days with a batch in the 14 days before the day.
    """
    seen = {d for d in batch_days if today - timedelta(days=14) <= d < today}
    wait_age = max(0, (enrolled + timedelta(days=min_age_days) - today).days)
    for j in range(wait_age + 15):
        day = today + timedelta(days=j)
        if day - timedelta(days=min_age_days) < enrolled:
            continue
        past = sum(1 for d in seen if d >= day - timedelta(days=14))
        if past + min(j, 14) >= min_active_days:
            return day
    return today + timedelta(days=wait_age + 14)


def first_consensus_day(
    today: date, min_nodes: int, eligible: int, earliest: Sequence[date]
) -> date | None:
    """Earliest day the eligible-node count can reach ``min_nodes``, or None when there are not
    enough members yet to get there."""
    if eligible >= min_nodes:
        return today
    ordered = sorted(earliest)
    if len(ordered) < min_nodes:
        return None
    return max(today, ordered[min_nodes - 1])


# --- render (pure) ------------------------------------------------------------------------------


def _week_start(d: date) -> date:
    return d - timedelta(days=d.weekday())


def _entry(
    start: date, days: int, precision: str, values: Mapping[str, int | None]
) -> dict[str, Any]:
    out: dict[str, Any] = {"start": start.isoformat(), "days": days, "precision": precision}
    out.update({f: values.get(f) for f in SERIES_FIELDS})
    return out


def build_series(rows: Sequence[DayRow], first: date, last: date) -> list[dict[str, Any]]:
    """Per-day figures from ``first`` to ``last``, grouped by ISO week.

    A week in which every day had at least ``MIN_NODES_STANDARD`` contributing nodes is published
    day by day with two significant figures. Any other week is ONE coarse entry: the average per
    reporting day, one significant figure (null when no node reported that week). A coarse entry
    always covers a complete ISO week: a partial week at either end is left out (the trailing one
    appears once it is complete). A single node's day off, or its exact daily volume, is never
    visible.
    """
    by_day = {r.day: r for r in rows}
    out: list[dict[str, Any]] = []
    week = _week_start(first)
    while week <= last:
        span = [d for d in (week + timedelta(days=i) for i in range(7)) if first <= d <= last]
        week_rows = [by_day.get(d) for d in span]
        full = [r for r in week_rows if r is not None and r.nodes >= MIN_NODES_STANDARD]
        if len(full) == len(span):
            for r in full:
                out.append(
                    _entry(
                        r.day,
                        1,
                        STANDARD,
                        {f: round_figure(r.values.get(f, 0), 2) for f in SERIES_FIELDS},
                    )
                )
        elif len(span) == 7:
            reporting = [r for r in week_rows if r is not None and r.nodes > 0]
            values: dict[str, int | None] = {}
            for f in SERIES_FIELDS:
                if reporting:
                    mean = sum(r.values.get(f, 0) for r in reporting) / len(reporting)
                    values[f] = round_figure(int(mean + 0.5), 1)
                else:
                    values[f] = None
            out.append(_entry(span[0], len(span), COARSE, values))
        week += timedelta(days=7)
    return out


def _allowed(metric: str, key: str) -> bool:
    if metric == "service":
        return key in enums.SERVICES
    if metric == "tag":
        return enums.is_valid_tag(key)
    if metric == "family":
        return key in enums.FAMILIES_V1
    return False


def build_window(
    rows: Sequence[DayRow], items: Sequence[ItemRow], first: date, last: date
) -> dict[str, Any]:
    """Services, tags and families over the window, as shares of daily distinct counts."""
    reporting = [r for r in rows if first <= r.day <= last and r.nodes > 0]
    coarse = not reporting or any(r.nodes < MIN_NODES_STANDARD for r in reporting)
    step = SHARE_STEP_COARSE if coarse else SHARE_STEP_STANDARD
    days = {r.day for r in reporting}
    totals: dict[tuple[str, str], int] = defaultdict(int)
    peak_nodes: dict[tuple[str, str], int] = defaultdict(int)
    for it in items:
        if it.day not in days or not _allowed(it.metric, it.key):
            continue
        totals[(it.metric, it.key)] += it.total
        peak_nodes[(it.metric, it.key)] = max(peak_nodes[(it.metric, it.key)], it.nodes)
    whole = {
        "service": sum(r.values.get("sources", 0) for r in reporting),
        "tag": sum(r.values.get("sources", 0) for r in reporting),
        "family": sum(r.values.get("files", 0) for r in reporting),
    }

    def listing(metric: str, top: int | None) -> list[dict[str, Any]]:
        picked = []
        for (m, key), total in totals.items():
            if m != metric or total < ITEM_MIN:
                continue
            if not coarse and peak_nodes[(m, key)] < ITEM_MIN_NODES:
                continue
            share = round_share(total, whole[metric], step)
            if share > 0:
                picked.append((total, key, share))
        picked.sort(key=lambda p: (-p[0], p[1]))
        return [{"id": key, "share_pct": share} for _, key, share in picked[:top]]

    return {
        "first_day": first.isoformat(),
        "last_day": last.isoformat(),
        "days": (last - first).days + 1,
        "precision": COARSE if coarse else STANDARD,
        "services": listing("service", None),
        "tags": listing("tag", TOP_TAGS),
        "families": listing("family", TOP_FAMILIES),
    }


def render(inp: ObservatoryInput) -> dict[str, Any]:
    today = inp.today
    # Activity: final days only.
    act_last = today - timedelta(days=FINAL_LAG_DAYS)
    frozen = sorted((r for r in inp.days if r.day <= act_last), key=lambda r: r.day)
    if frozen:
        act_first = max(act_last - timedelta(days=SERIES_DAYS - 1), frozen[0].day)
        series = build_series(frozen, act_first, act_last)
    else:
        series = []
    window = build_window(frozen, inp.items, act_last - timedelta(days=WINDOW_DAYS - 1), act_last)
    # Outcomes: complete days, at least 24 h after their end.
    out_last = today - timedelta(days=OUTCOME_LAG_DAYS)
    out_first = out_last - timedelta(days=SERIES_DAYS - 1)
    by_day = {o.day: o for o in inp.outcomes}
    daily = []
    for i in range(SERIES_DAYS):
        d = out_first + timedelta(days=i)
        o = by_day.get(d, OutcomeDay(d))
        daily.append(
            {
                "day": d.isoformat(),
                "confirmed": o.confirmed,
                "reported": o.reported,
                "taken_down": o.taken_down,
            }
        )
    last30 = daily[-30:]
    first_day = first_consensus_day(today, inp.min_nodes, inp.eligible, inp.earliest_eligible)
    countries = sorted(
        (cc, n) for cc, n in inp.country_members.items() if n >= buckets.MIN_COUNTRIES_SHOWN
    )
    return {
        "schema": SCHEMA,
        "generated_day": today.isoformat(),
        "licence": LICENCE,
        "nodes": {
            "members": inp.members,
            "active_7d": inp.active_7d,
            "eligible": inp.eligible,
            "countries": [{"cc": cc, "members": n} for cc, n in countries],
        },
        "bootstrap": {
            "min_nodes": inp.min_nodes,
            "eligible_nodes": inp.eligible,
            "nodes_missing": max(0, inp.min_nodes - inp.eligible),
            "consensus_possible": inp.eligible >= inp.min_nodes,
            "first_consensus_day": first_day.isoformat() if first_day else None,
            "days_until_first_consensus": (first_day - today).days if first_day else None,
        },
        "outcomes": {
            "first_day": out_first.isoformat(),
            "last_day": out_last.isoformat(),
            "confirmed_30d": sum(d["confirmed"] for d in last30),
            "reported_30d": sum(d["reported"] for d in last30),
            "taken_down_30d": sum(d["taken_down"] for d in last30),
            "reports_sent_30d": inp.reports_sent_30d,
            "abusech_sent_30d": inp.abusech_sent_30d,
            "median_days_to_takedown": round(statistics.median(inp.takedown_gaps))
            if inp.takedown_gaps
            else None,
            "daily": daily,
        },
        "activity": {
            "last_day": act_last.isoformat(),
            "series": series,
            "window": window,
        },
        "rules": {
            "min_nodes_standard": MIN_NODES_STANDARD,
            "min_countries_shown": buckets.MIN_COUNTRIES_SHOWN,
            "activity_lag_days": FINAL_LAG_DAYS,
            "outcome_lag_days": OUTCOME_LAG_DAYS,
            "item_min": ITEM_MIN,
        },
    }


def render_bytes(inp: ObservatoryInput) -> bytes:
    return dumps_json(render(inp)).encode("utf-8")


# --- freeze (database) ---------------------------------------------------------------------------

_ITEM_QUERIES = {
    "activity": "SELECT k AS key, count(DISTINCT value) AS total, count(DISTINCT node_id) AS nodes "
    "FROM observations, unnest(activity) AS k WHERE day = :d AND kind = 'ip' GROUP BY k",
    "service": "SELECT k AS key, count(DISTINCT value) AS total, count(DISTINCT node_id) AS nodes "
    "FROM observations, unnest(services) AS k WHERE day = :d AND kind = 'ip' GROUP BY k",
    "tag": "SELECT k AS key, count(DISTINCT value) AS total, count(DISTINCT node_id) AS nodes "
    "FROM observations, unnest(tags) AS k WHERE day = :d AND kind = 'ip' GROUP BY k",
    "family": "SELECT k AS key, count(DISTINCT value) AS total, count(DISTINCT node_id) AS nodes "
    "FROM observations, unnest(families) AS k WHERE day = :d AND kind = 'sha256' GROUP BY k",
    "kind": "SELECT CASE kind WHEN 'url' THEN 'payload_urls' WHEN 'sha256' THEN 'files' "
    "ELSE 'c2' END AS key, count(DISTINCT kind || '|' || value) AS total, "
    "count(DISTINCT node_id) AS nodes FROM observations WHERE day = :d "
    "AND kind IN ('url', 'sha256', 'c2_ip', 'c2_domain') GROUP BY 1",
}


async def freeze_day(session: AsyncSession, day: date) -> None:
    """Store the aggregates of one final day. A day already stored is left as it is."""
    head = (
        await session.execute(
            text(
                "SELECT count(DISTINCT value) FILTER (WHERE kind = 'ip') AS total, "
                "count(DISTINCT node_id) AS nodes FROM observations WHERE day = :d"
            ),
            {"d": day},
        )
    ).one()
    rows: list[dict[str, Any]] = [
        {"d": day, "m": "total", "k": "", "t": int(head.total), "n": int(head.nodes)}
    ]
    for metric, sql in _ITEM_QUERIES.items():
        for r in await session.execute(text(sql), {"d": day}):
            rows.append(
                {"d": day, "m": metric, "k": str(r.key), "t": int(r.total), "n": int(r.nodes)}
            )
    await session.execute(
        text(
            "INSERT INTO observatory_daily (day, metric, key, total, nodes) "
            "VALUES (:d, :m, :k, :t, :n) ON CONFLICT DO NOTHING"
        ),
        rows,
    )


async def freeze_days(session: AsyncSession, s: Settings, today: date) -> int:
    """Freeze every final day still covered by the observations. Returns the days stored."""
    last = today - timedelta(days=FINAL_LAG_DAYS)
    first = today - timedelta(days=s.obs_retention_days)
    if first > last:
        return 0
    done = {
        r[0]
        for r in await session.execute(
            text(
                "SELECT day FROM observatory_daily WHERE metric = 'total' AND day BETWEEN :a AND :b"
            ),
            {"a": first, "b": last},
        )
    }
    stored = 0
    d = first
    while d <= last:
        if d not in done:
            await freeze_day(session, d)
            stored += 1
        d += timedelta(days=1)
    await session.commit()
    return stored


# --- load (database) ------------------------------------------------------------------------------


def _midnight(d: date) -> datetime:
    return datetime.combine(d, time(0), tzinfo=UTC)


async def load(session: AsyncSession, s: Settings, today: date) -> ObservatoryInput:
    inp = ObservatoryInput(today=today, min_nodes=s.min_nodes)
    # Nodes.
    counts = (
        await session.execute(
            text(
                "SELECT (SELECT count(*) FROM nodes) AS members, "
                "(SELECT count(DISTINCT node_id) FROM batches "
                " WHERE day >= :recent AND day < :today) AS active"
            ),
            {"today": today, "recent": today - timedelta(days=7)},
        )
    ).one()
    inp.members, inp.active_7d = int(counts.members), int(counts.active)
    inp.eligible = len(await consensus.eligible_nodes(session, s, today))
    days_of: dict[uuid.UUID, list[date]] = defaultdict(list)
    enrolled: dict[uuid.UUID, date] = {}
    for r in await session.execute(
        text(
            "SELECT n.id, n.enrolled_day, b.day FROM nodes n "
            "JOIN batches b ON b.node_id = n.id AND b.items > 0 "
            "AND b.day >= :since AND b.day < :today "
            "WHERE n.standing = 'active' AND n.reputation >= CAST(:min_rep AS real)"
        ),
        {"since": today - timedelta(days=14), "today": today, "min_rep": s.min_reputation},
    ):
        enrolled[r.id] = r.enrolled_day
        days_of[r.id].append(r.day)
    inp.earliest_eligible = [
        earliest_eligible(
            today,
            enrolled[n],
            days_of[n],
            min_age_days=s.node_min_age_days,
            min_active_days=s.node_min_active_days,
        )
        for n in enrolled
    ]
    inp.country_members = {
        str(r.cc): int(r.n)
        for r in await session.execute(
            text(
                "SELECT btrim(country) AS cc, count(*) AS n FROM nodes "
                "WHERE show_country AND country IS NOT NULL AND btrim(country) <> '' "
                "GROUP BY 1"
            )
        )
    }
    # Activity.
    since = today - timedelta(days=FINAL_LAG_DAYS + SERIES_DAYS)
    heads: dict[date, int] = {}
    values: dict[date, dict[str, int]] = defaultdict(dict)
    for r in await session.execute(
        text(
            "SELECT day, metric, key, total, nodes FROM observatory_daily "
            "WHERE day >= :since ORDER BY day"
        ),
        {"since": since},
    ):
        if r.metric == "total":
            heads[r.day] = int(r.nodes)
            values[r.day]["sources"] = int(r.total)
        elif r.metric == "activity" and r.key in ACTIVITY_FIELDS:
            values[r.day][r.key] = int(r.total)
        elif r.metric == "kind" and r.key in KIND_FIELDS:
            values[r.day][r.key] = int(r.total)
        elif r.metric in ("service", "tag", "family"):
            inp.items.append(ItemRow(r.day, r.metric, r.key, int(r.total), int(r.nodes)))
    inp.days = [DayRow(d, n, values[d]) for d, n in sorted(heads.items())]
    # Outcomes.
    out_last = today - timedelta(days=OUTCOME_LAG_DAYS)
    out_first = out_last - timedelta(days=SERIES_DAYS - 1)
    tallies: dict[date, dict[str, int]] = defaultdict(dict)
    for column in ("confirmed", "reported", "taken_down"):
        for r in await session.execute(
            text(
                f"SELECT {column}_day AS day, count(*) AS n FROM targets "  # noqa: S608
                f"WHERE {column}_day BETWEEN :a AND :b GROUP BY 1"
            ),
            {"a": out_first, "b": out_last},
        ):
            tallies[r.day][column] = int(r.n)
    inp.outcomes = [OutcomeDay(d, **t) for d, t in sorted(tallies.items())]
    w_first = out_last - timedelta(days=29)
    window = {"a": _midnight(w_first), "b": _midnight(out_last + timedelta(days=1))}
    inp.reports_sent_30d = int(
        (
            await session.execute(
                text(
                    "SELECT count(*) FROM reports WHERE state = 'sent' "
                    "AND sent_at >= :a AND sent_at < :b"
                ),
                window,
            )
        ).scalar_one()
    )
    inp.abusech_sent_30d = int(
        (
            await session.execute(
                text(
                    "SELECT count(*) FROM abusech_submissions WHERE state = 'sent' "
                    "AND sent_at >= :a AND sent_at < :b"
                ),
                window,
            )
        ).scalar_one()
    )
    inp.takedown_gaps = [
        int(r[0])
        for r in await session.execute(
            text(
                "SELECT taken_down_day - reported_day FROM targets "
                "WHERE taken_down_day BETWEEN :a AND :b AND reported_day IS NOT NULL"
            ),
            {"a": w_first, "b": out_last},
        )
    ]
    return inp


# --- publish (disk) -------------------------------------------------------------------------------


def publish(root: Path, data: bytes) -> None:
    """Write ``network.json`` and its ``.gz`` sidecar, each with an atomic rename."""
    root.mkdir(parents=True, exist_ok=True)
    for name, body in ((FILE + ".gz", gz(data)), (FILE, data)):
        tmp = root / f".tmp-{name}-{secrets.token_hex(4)}"
        try:
            tmp.write_bytes(body)
            tmp.chmod(FILE_MODE)
            os.replace(tmp, root / name)
        finally:
            tmp.unlink(missing_ok=True)


__all__ = [
    "FILE",
    "SCHEMA",
    "ObservatoryInput",
    "freeze_days",
    "load",
    "publish",
    "render",
    "render_bytes",
]

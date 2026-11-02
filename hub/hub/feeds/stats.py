"""Public feed statistics and the removed-values file (design M30 sections 6.1 and 12).

``stats.json`` holds counts only: no value, no node id, no pseudonym. ``removed.json`` lists the
values removed in the last 30 days with the day and a reason of ``expired`` or ``taken_down``
only; delisted and excluded values are counted in the statistics and never repeated.
"""

from __future__ import annotations

import json
import statistics
from collections import Counter
from collections.abc import Callable, Mapping
from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_netproto.buckets import MIN_COUNTRIES_SHOWN
from suckerpot_netproto.feeds.models import LICENCE, format_ts
from suckerpot_netproto.feeds.render import dumps_json

from .lifecycle import HIGH_OF, PUBLISHED_LISTS, EntryRow, Plan
from .select import BASE_LISTS

STATS_SCHEMA = "selfhostr-feed-stats/1"
REMOVED_SCHEMA = "selfhostr-feed-removed/1"
DAILY_DAYS = 90
REMOVED_DAYS = 30
REMOVED_MAX = 20_000
DIRECTION = {"inbound": "inbound", "outbound": "outbound", "outbound-domains": "outbound"}


async def record_daily(session: AsyncSession, plan: Plan, today: date) -> None:
    """Upsert today's row of every base list: entries now, and what this run added and removed."""
    listed = plan.listed()
    for name in BASE_LISTS:
        rem = plan.removed.get(name, Counter())
        await session.execute(
            text(
                """
                INSERT INTO feed_daily (day, list, entries, added, removed_expired,
                    removed_taken_down, removed_delisted, removed_excluded)
                VALUES (:day, :list, :entries, :added, :exp, :td, :dl, :ex)
                ON CONFLICT (day, list) DO UPDATE SET entries = EXCLUDED.entries,
                    added = feed_daily.added + EXCLUDED.added,
                    removed_expired = feed_daily.removed_expired + EXCLUDED.removed_expired,
                    removed_taken_down = feed_daily.removed_taken_down
                        + EXCLUDED.removed_taken_down,
                    removed_delisted = feed_daily.removed_delisted + EXCLUDED.removed_delisted,
                    removed_excluded = feed_daily.removed_excluded
                        + EXCLUDED.removed_excluded
                """
            ),
            {
                "day": today,
                "list": name,
                "entries": len(listed[name]),
                "added": plan.added[name],
                "exp": rem["expired"] + rem["capped"],
                "td": rem["taken_down"],
                "dl": rem["delisted"],
                "ex": rem["excluded"],
            },
        )


def _counts(rows: list[EntryRow]) -> dict[str, int]:
    return {
        "entries": len(rows),
        "high": sum(1 for r in rows if r.tier == "high"),
        "v4": sum(1 for r in rows if r.family == 4),
        "v6": sum(1 for r in rows if r.family == 6),
    }


async def build_stats(session: AsyncSession, plan: Plan, *, serial: int, now: datetime) -> bytes:
    today = now.date()
    listed = plan.listed()
    lists: list[dict[str, Any]] = []
    for name in BASE_LISTS:
        rows = listed[name]
        item: dict[str, Any] = {"id": name, "direction": DIRECTION[name], **_counts(rows)}
        if name == "outbound":
            item["payload_hosts"] = sum(1 for r in rows if "payload-host" in r.categories)
            item["c2"] = sum(1 for r in rows if "c2" in r.categories)
        if name == "outbound-domains":
            del item["v4"], item["v6"]
        lists.append(item)
    daily_rows = (
        await session.execute(
            text(
                "SELECT day, list, entries, added, removed_expired, removed_taken_down, "
                "removed_delisted, removed_excluded FROM feed_daily WHERE day >= :since "
                "ORDER BY day, list"
            ),
            {"since": today - timedelta(days=DAILY_DAYS)},
        )
    ).all()
    daily = [
        {
            "day": r.day.isoformat(),
            "list": r.list,
            "entries": r.entries,
            "added": r.added,
            "removed": {
                "expired": r.removed_expired,
                "taken_down": r.removed_taken_down,
                "delisted": r.removed_delisted,
                "excluded": r.removed_excluded,
            },
        }
        for r in daily_rows
    ]
    since30 = today - timedelta(days=REMOVED_DAYS)
    spans = [
        (r.removed_day - r.listed_day).days
        for r in (
            await session.execute(
                text(
                    "SELECT removed_day, listed_day FROM feed_entries WHERE state = 'removed' "
                    "AND removed_reason = 'taken_down' AND listed_day IS NOT NULL "
                    "AND removed_day >= :since"
                ),
                {"since": since30},
            )
        ).all()
    ]
    outbound_down = int(
        (
            await session.execute(
                text(
                    "SELECT count(*) FROM feed_entries WHERE state = 'removed' "
                    "AND removed_reason = 'taken_down' "
                    "AND list IN ('outbound', 'outbound-domains') "
                    "AND removed_day >= :since"
                ),
                {"since": since30},
            )
        ).scalar_one()
    )
    delist = (
        await session.execute(
            text(
                """
                SELECT
                  count(*) FILTER (WHERE created_day >= :since) AS requests,
                  count(*) FILTER (WHERE state = 'accepted' AND decided_day >= :since) AS accepted,
                  count(*) FILTER (WHERE state = 'rejected' AND decided_day >= :since) AS rejected,
                  count(*) FILTER (WHERE state IN ('received', 'suppressed')) AS open,
                  array_agg((decided_day - created_day) * 24)
                    FILTER (WHERE decided_day >= :since) AS hours
                FROM delist_requests
                """
            ),
            {"since": since30},
        )
    ).one()
    hours = [h for h in (delist.hours or []) if h is not None]
    network = (await session.execute(text("SELECT data FROM network_summary WHERE id = 1"))).first()
    totals: Mapping[str, Any] = (network[0].get("totals", {}) if network else {}) or {}
    countries = totals.get("countries")
    doc: dict[str, Any] = {
        "schema": STATS_SCHEMA,
        "generated_at": format_ts(now),
        "serial": serial,
        "licence": LICENCE,
        "lists": lists,
        "daily": daily,
        "takedown": {
            "outbound_removed_taken_down_30d": outbound_down,
            "median_days_listed_until_takedown": round(statistics.median(spans)) if spans else None,
        },
        "delisting": {
            "requests_30d": int(delist.requests),
            "accepted_30d": int(delist.accepted),
            "rejected_30d": int(delist.rejected),
            "open": int(delist.open),
            "median_hours_to_decision": round(statistics.median(hours)) if hours else None,
        },
        "exclusions": {
            "tor": plan.exclusions["tor"],
            "cdn": plan.exclusions["cdn"],
            "never_list": plan.exclusions["never_list"],
            "allow_list": plan.exclusions["allow_list"] + plan.exclusions["delisted"],
        },
        "network": {
            "members": totals.get("members"),
            "active_7d": totals.get("active_7d"),
            "countries": countries
            if isinstance(countries, int) and countries >= MIN_COUNTRIES_SHOWN
            else None,
        },
    }
    return dumps_json(doc).encode("utf-8")


async def build_removed(
    session: AsyncSession, *, now: datetime, excluded: Callable[[str, str], str | None]
) -> bytes:
    """Values removed in the last 30 days for ``expired`` or ``taken_down`` only.

    A value that an exclusion covers today (an allow-list row added since) is left out.
    """
    rows = (
        await session.execute(
            text(
                "SELECT list, value, removed_day, removed_reason FROM feed_entries "
                "WHERE state = 'removed' AND removed_reason IN ('expired', 'taken_down') "
                "AND removed_day >= :since ORDER BY removed_day DESC, list, value LIMIT :cap"
            ),
            {"since": now.date() - timedelta(days=REMOVED_DAYS), "cap": REMOVED_MAX},
        )
    ).all()
    doc = {
        "schema": REMOVED_SCHEMA,
        "generated_at": format_ts(now),
        "licence": LICENCE,
        "entries": [
            {
                "value": r.value,
                "list": r.list,
                "removed": r.removed_day.isoformat(),
                "reason": r.removed_reason,
            }
            for r in rows
            if excluded(r.list, r.value) is None
        ],
    }
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


__all__ = ["HIGH_OF", "PUBLISHED_LISTS", "build_removed", "build_stats", "record_daily"]

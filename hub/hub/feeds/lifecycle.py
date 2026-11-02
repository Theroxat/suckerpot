"""Feed entry lifecycle (design M30 sections 5.1, 5.2, 5.4 to 5.6). Pure: no I/O, no clock.

States: ``pending`` (in the hold) -> ``listed`` -> ``removed`` (``expired``, ``taken_down``,
``delisted``, ``excluded``, ``capped``). A removed value comes back only with a k-supported
sighting after its removal day, and never while an allow-list row covers it.

``plan`` computes the next state of every entry from the previous one and the candidates of this
run; the caller stores it only if the breaker lets the run through.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import date, datetime, timedelta

from .filter import ALLOW, DELISTED
from .select import BASE_LISTS, INBOUND, Candidate

PENDING, LISTED, REMOVED = "pending", "listed", "removed"
PUBLISHED_LISTS = ("inbound", "inbound-high", "outbound", "outbound-high", "outbound-domains")
HIGH_OF = {"inbound": "inbound-high", "outbound": "outbound-high"}
REASONS = ("expired", "taken_down", "delisted", "excluded", "capped")
DIFF_VALUES_MAX = 2000


@dataclass
class EntryRow:
    list_id: str
    value: str
    family: int | None
    tier: str
    state: str
    categories: list[str]
    services: list[str]
    tags: list[str]
    families: list[str]
    ports: list[int]
    first_seen: date
    last_seen: date
    expires: date
    reported: bool = False
    eligible_at: datetime | None = None
    listed_day: date | None = None
    removed_day: date | None = None
    removed_reason: str | None = None
    corroborated: bool | None = None
    corroborated_day: date | None = None
    target_id: str | None = None


@dataclass
class Plan:
    rows: dict[tuple[str, str], EntryRow]
    deletes: list[tuple[str, str]] = field(default_factory=list)
    added: Counter[str] = field(default_factory=Counter)  # per base list
    removed: dict[str, Counter[str]] = field(default_factory=dict)  # list -> reason -> n
    exclusions: Counter[str] = field(default_factory=Counter)

    def listed(self) -> dict[str, list[EntryRow]]:
        out: dict[str, list[EntryRow]] = {name: [] for name in BASE_LISTS}
        for row in self.rows.values():
            if row.state == LISTED:
                out[row.list_id].append(row)
        return out


def published_sets(listed: Mapping[str, Iterable[EntryRow]]) -> dict[str, set[str]]:
    """Value sets of the five published lists (the high lists are subsets of the base ones)."""
    out: dict[str, set[str]] = {name: set() for name in PUBLISHED_LISTS}
    for base, rows in listed.items():
        for row in rows:
            out[base].add(row.value)
            if row.tier == "high" and base in HIGH_OF:
                out[HIGH_OF[base]].add(row.value)
    return out


def _from_candidate(c: Candidate, now: datetime, hold: timedelta) -> EntryRow:
    start = now
    if c.confirmed_day is not None:
        midnight = datetime(
            c.confirmed_day.year, c.confirmed_day.month, c.confirmed_day.day, tzinfo=now.tzinfo
        )
        start = max(now, midnight)
    return EntryRow(
        list_id=c.list_id,
        value=c.value,
        family=c.family if isinstance(c.family, int) else None,
        tier=c.tier,
        state=PENDING,
        categories=sorted(c.categories),
        services=sorted(c.services),
        tags=sorted(c.tags),
        families=sorted(c.families),
        ports=sorted(c.ports),
        first_seen=c.first_seen,
        last_seen=c.last_seen,
        expires=c.expires,
        reported=c.reported,
        eligible_at=start + hold,
        target_id=c.target_id,
    )


def _refresh(row: EntryRow, c: Candidate) -> None:
    """Update a pending or listed row from this run's candidate."""
    row.tier = c.tier
    row.categories = sorted(c.categories)
    row.services = sorted(c.services)
    row.tags = sorted(c.tags)
    row.families = sorted(c.families)
    row.ports = sorted(c.ports)
    row.first_seen = min(row.first_seen, c.first_seen)
    row.last_seen = max(row.last_seen, c.last_seen)
    row.expires = max(row.expires, c.expires)
    row.reported = row.reported or c.reported
    row.target_id = c.target_id or row.target_id


def _remove(plan: Plan, row: EntryRow, reason: str, today: date) -> None:
    if row.state == LISTED:
        plan.removed.setdefault(row.list_id, Counter())[reason] += 1
    row.state = REMOVED
    row.removed_day = today
    row.removed_reason = reason
    row.eligible_at = None
    row.corroborated = None
    row.corroborated_day = None


def plan(
    *,
    existing: Mapping[tuple[str, str], EntryRow],
    candidates: Mapping[tuple[str, str], Candidate],
    now: datetime,
    hold: timedelta,
    caps: Mapping[str, int],
    excluded: Callable[[str, str], str | None],
    taken_down: set[tuple[str, str]],
    target_states: Mapping[str, str],
) -> Plan:
    """Next state of every entry. ``excluded(list, value)`` is the filter; ``target_states``
    holds the M29 state of the targets that entries point at."""
    today = now.date()
    out = Plan(rows={k: replace(v) for k, v in existing.items()})
    seen: set[tuple[str, str]] = set()

    for key, cand in candidates.items():
        seen.add(key)
        if key in taken_down:
            continue
        reason = excluded(*key)
        if reason is not None:
            out.exclusions[reason] += 1
            continue
        row = out.rows.get(key)
        if row is None:
            out.rows[key] = _from_candidate(cand, now, hold)
            continue
        if row.state == REMOVED:
            if row.removed_day is not None and cand.last_seen > row.removed_day:
                fresh = _from_candidate(cand, now, hold)
                fresh.corroborated = None
                out.rows[key] = fresh
            continue
        _refresh(row, cand)

    for key, row in list(out.rows.items()):
        if row.state == REMOVED:
            continue
        if key in taken_down:
            if row.state == LISTED:
                _remove(out, row, "taken_down", today)
            else:
                del out.rows[key]
                out.deletes.append(key)
            continue
        reason = excluded(*key)
        if reason is not None:
            if key not in seen:
                out.exclusions[reason] += 1
            if row.state == LISTED:
                _remove(out, row, "delisted" if reason == DELISTED else "excluded", today)
            else:
                del out.rows[key]
                out.deletes.append(key)
            continue
        if row.state == PENDING:
            if key not in candidates:
                del out.rows[key]
                out.deletes.append(key)
            elif row.eligible_at is not None and now >= row.eligible_at:
                row.state = LISTED
                row.listed_day = today
                row.eligible_at = None
                out.added[row.list_id] += 1
            continue
        # listed: stays while its target is alive and the expiry has not passed
        alive = (
            key in candidates
            or (
                row.target_id is not None
                and target_states.get(row.target_id) in ("confirmed", "reported")
            )
        ) and today <= row.expires
        if not alive:
            _remove(out, row, "expired", today)

    for name in BASE_LISTS:
        listed = [r for r in out.rows.values() if r.list_id == name and r.state == LISTED]
        cap = caps[name]
        if len(listed) > cap:
            listed.sort(key=lambda r: (r.tier != "high", -r.last_seen.toordinal(), r.value))
            for row in listed[cap:]:
                _remove(out, row, "capped", today)
    return out


# --- change breaker (design 5.6) -------------------------------------------------------------


@dataclass(frozen=True)
class Trip:
    list_id: str
    previous: int
    added: int
    removed: int
    reason: str  # "add" or "remove"


def breaker(
    previous: Mapping[str, set[str]],
    new: Mapping[str, set[str]],
    *,
    add_pct: int,
    remove_pct: int,
    minimum: int,
) -> list[Trip]:
    """Lists whose change is too large to publish without a human."""
    trips: list[Trip] = []
    for name in PUBLISHED_LISTS:
        before, after = previous.get(name, set()), new.get(name, set())
        added, removed = len(after - before), len(before - after)
        size = len(before)
        if added >= minimum and (size == 0 or added * 100 > add_pct * size):
            trips.append(Trip(name, size, added, removed, "add"))
        if removed >= minimum and removed * 100 > remove_pct * size:
            trips.append(Trip(name, size, added, removed, "remove"))
    return trips


def diff(
    previous: Mapping[str, set[str]], new: Mapping[str, set[str]]
) -> dict[str, dict[str, object]]:
    """Per list: counts, and the first values of each side (the operator reads them)."""
    out: dict[str, dict[str, object]] = {}
    for name in PUBLISHED_LISTS:
        before, after = previous.get(name, set()), new.get(name, set())
        add, rem = sorted(after - before), sorted(before - after)
        if not add and not rem:
            continue
        out[name] = {
            "added": len(add),
            "removed": len(rem),
            "added_values": add[:DIFF_VALUES_MAX],
            "removed_values": rem[:DIFF_VALUES_MAX],
        }
    return out


def digest(previous: Mapping[str, set[str]], new: Mapping[str, set[str]]) -> str:
    """A fingerprint of a change, so a release or discard names exactly the diff it saw."""
    parts = {
        name: [
            sorted(new.get(name, set()) - previous.get(name, set())),
            sorted(previous.get(name, set()) - new.get(name, set())),
        ]
        for name in PUBLISHED_LISTS
    }
    return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()


def has_additions(previous: Mapping[str, set[str]], new: Mapping[str, set[str]]) -> bool:
    return any(new.get(n, set()) - previous.get(n, set()) for n in PUBLISHED_LISTS)


def changed(previous: Mapping[str, set[str]], new: Mapping[str, set[str]]) -> bool:
    return any(new.get(n, set()) != previous.get(n, set()) for n in PUBLISHED_LISTS)


__all__ = [
    "ALLOW",
    "DELISTED",
    "INBOUND",
    "LISTED",
    "PENDING",
    "PUBLISHED_LISTS",
    "REMOVED",
    "EntryRow",
    "Plan",
    "Trip",
    "breaker",
    "changed",
    "diff",
    "digest",
    "has_additions",
    "plan",
    "published_sets",
]

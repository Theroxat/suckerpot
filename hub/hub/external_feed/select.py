"""Selection of the external list (design M36 section 7.2): a pure function of the stored CC0
copy and the hub exclusions. It takes no node data and no network list as input (X1, X2).

Order: expiry (7 days after the hub last saw the value in the source), the M30 exclusions, a
cap, and the change breaker. There is no hold: the data is public.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any

LIST_ID = "external-outbound"
TTL_DAYS = 7
MAX_ENTRIES = 20_000
CATEGORY = "c2"


@dataclass(frozen=True)
class Trip:
    list_id: str
    previous: int
    added: int
    removed: int
    reason: str  # "add" or "remove"


@dataclass(frozen=True)
class SourceRow:
    source: str
    value: str
    family: int
    ports: tuple[int, ...]
    families: tuple[str, ...]
    first_seen: date
    last_seen: date


@dataclass
class Selection:
    entries: list[dict[str, Any]] = field(default_factory=list)
    expired: int = 0
    excluded: Counter[str] = field(default_factory=Counter)
    capped: int = 0

    @property
    def values(self) -> set[str]:
        return {e["value"] for e in self.entries}


def select_entries(
    rows: Iterable[SourceRow],
    *,
    today: date,
    excluded: Callable[[str], str | None],
    cap: int = MAX_ENTRIES,
) -> Selection:
    """Merge rows of every source by value and apply expiry, exclusions and the cap. The result
    is deterministic: it depends on the rows, the day and the exclusions only."""
    out = Selection()
    merged: dict[str, dict[str, Any]] = {}
    for r in sorted(rows, key=lambda r: (r.value, r.source)):
        expires = r.last_seen + timedelta(days=TTL_DAYS)
        if expires < today:
            out.expired += 1
            continue
        reason = excluded(r.value)
        if reason is not None:
            out.excluded[reason] += 1
            continue
        cur = merged.get(r.value)
        if cur is None:
            merged[r.value] = {
                "value": r.value,
                "family": r.family,
                "list": LIST_ID,
                "categories": [CATEGORY],
                "sources": [r.source],
                "families": sorted(set(r.families)),
                "ports": sorted(set(r.ports))[:16],
                "first_seen": r.first_seen.isoformat(),
                "last_seen": r.last_seen.isoformat(),
                "expires": expires.isoformat(),
            }
        else:
            cur["sources"] = sorted({*cur["sources"], r.source})
            cur["families"] = sorted({*cur["families"], *r.families})
            cur["ports"] = sorted({*cur["ports"], *r.ports})[:16]
            cur["first_seen"] = min(cur["first_seen"], r.first_seen.isoformat())
            cur["last_seen"] = max(cur["last_seen"], r.last_seen.isoformat())
            cur["expires"] = max(cur["expires"], expires.isoformat())
    entries = sorted(merged.values(), key=lambda e: (e["last_seen"], e["value"]), reverse=True)
    if len(entries) > cap:
        out.capped = len(entries) - cap
        entries = entries[:cap]
    out.entries = entries
    return out


def breaker(
    before: set[str] | None, after: set[str], *, add_pct: int, remove_pct: int, minimum: int
) -> list[Trip]:
    """Same thresholds as the main lists. Nothing published yet (``before`` is None) cannot
    trip: the first run publishes whatever the source holds, which is public data."""
    if before is None:
        return []
    added, removed, size = len(after - before), len(before - after), len(before)
    trips: list[Trip] = []
    if added >= minimum and (size == 0 or added * 100 > add_pct * size):
        trips.append(Trip(LIST_ID, size, added, removed, "add"))
    if removed >= minimum and removed * 100 > remove_pct * size:
        trips.append(Trip(LIST_ID, size, added, removed, "remove"))
    return trips


def digest(before: set[str] | None, after: set[str]) -> str:
    """A fingerprint of a change, so a release names exactly the diff the operator saw."""
    base = before or set()
    parts = [sorted(after - base), sorted(base - after)]
    return hashlib.sha256(json.dumps(parts).encode()).hexdigest()

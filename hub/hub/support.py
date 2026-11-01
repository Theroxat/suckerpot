"""k-support: member-visible target fields change only when k eligible nodes back the change.

Without it, an attacker could reuse an already listed source address to probe one suspected
address: a new ``last_day`` or service on the listing would show that a single node saw the
probe, which would reveal that the probed address runs a sensor. Every published field of a
target (days, services, activity, tags, families) goes through these helpers. Feed code reuses
them.
"""

from __future__ import annotations

from collections.abc import Hashable, Mapping
from datetime import date
from typing import Any


def k_supported[T: Hashable](seen_by: Mapping[T, set[object]], k: int) -> set[T]:
    """Values seen by at least ``k`` distinct nodes."""
    return {value for value, nodes in seen_by.items() if len(nodes) >= k}


def last_day_supported(days_by_node: Mapping[Any, set[date]], k: int) -> date | None:
    """Latest day D such that at least ``k`` nodes have a sighting on or after D."""
    latest = sorted((max(d) for d in days_by_node.values() if d), reverse=True)
    return latest[k - 1] if len(latest) >= k else None


def first_day_supported(days_by_node: Mapping[Any, set[date]], k: int) -> date | None:
    """Earliest day D such that at least ``k`` nodes have a sighting on or before D."""
    earliest = sorted(min(d) for d in days_by_node.values() if d)
    return earliest[k - 1] if len(earliest) >= k else None

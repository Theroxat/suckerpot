"""Adapter to M27's local takedown re-checks (design M29 section 9.5).

M27 (``takedown_targets``) is on main, but its targets are keyed by the local report subject
(``kind`` url|ip|domain plus a ``role``) with a richer state set, while the hub names its own
``kind`` values (including ``c2_ip`` / ``c2_domain`` / ``sha256``). Mapping one onto the other is
not a one-line change, so this adapter stays a documented limit: every target is ``unknown`` and
the worker sends nothing for it. A later change only has to make ``local_states`` read the stored
M27 state of each ``(kind, value)`` and return ``up`` or ``down``. It must never connect to a
target itself.
"""

from __future__ import annotations

from typing import Literal

State = Literal["up", "down", "unknown"]


async def local_states(items: list[tuple[str, str, str]]) -> dict[str, State]:
    """States by hub target id for ``(hub_id, kind, value)`` items."""
    return {hub_id: "unknown" for hub_id, _kind, _value in items}

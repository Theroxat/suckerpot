"""Adapter to M27's local takedown re-checks (design M29 section 9.5).

M27 is not merged yet, so every target is ``unknown`` and the worker sends nothing for it. When
M27 lands, only ``local_states`` changes: it must read the local re-check result of each
``(kind, value)`` and return ``up`` or ``down``. It must never connect to a target itself.
"""

from __future__ import annotations

from typing import Literal

State = Literal["up", "down", "unknown"]


async def local_states(items: list[tuple[str, str, str]]) -> dict[str, State]:
    """States by hub target id for ``(hub_id, kind, value)`` items."""
    return {hub_id: "unknown" for hub_id, _kind, _value in items}

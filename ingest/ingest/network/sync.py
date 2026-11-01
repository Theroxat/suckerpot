"""Pulling confirmed targets, answering reveal and recheck requests, the daily summary.

Everything pulled is data: validated by the netproto models, stored, shown. Nothing pulled opens
a connection to a target or runs anything (N9). A reveal answer goes out only for a hash the hub
asked for, only when this node holds the clear value, and only after the identity guard (N6).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any

from suckerpot_netproto import blind
from suckerpot_netproto import models as wire
from suckerpot_reporting import GuardContext, SelfTerms, guard

from . import takedown
from .builder import mentions_self
from .client import HubClient
from .store import Store

MAX_PAGES = 20
PAGE = 1000
MAX_REVEALS = wire.MAX_REVEALS
MAX_RECHECKS = wire.MAX_RECHECKS


@dataclass(slots=True)
class PullResult:
    cursor: str | None
    reveal: list[wire.RevealRef] = field(default_factory=list)
    recheck: list[wire.RecheckRef] = field(default_factory=list)
    blinded: set[str] = field(default_factory=set)


async def pull(client: HubClient, store: Store, cursor: str | None) -> PullResult:
    """Fetch targets until the cursor is current and store them."""
    out = PullResult(cursor)
    for _ in range(MAX_PAGES):
        page = await client.targets(out.cursor, PAGE)
        await store.upsert_targets(page.targets)
        out.reveal += page.reveal
        out.recheck += page.recheck
        out.blinded |= {t.value_b for t in page.targets if t.value is None and t.value_b}
        done = len(page.targets) < PAGE or page.cursor == out.cursor
        out.cursor = page.cursor
        if done:
            break
    out.reveal, out.recheck = out.reveal[:PAGE], out.recheck[:50]
    return out


def _clear_by_blind(kind: str, values: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for v in values:
        try:
            out.setdefault(blind.blind(kind, v), v)
        except ValueError:
            continue
    return out


async def mark_mine(store: Store, pending: set[str]) -> None:
    """Flag targets this sensor saw: by clear value in SQL, by blinded hash here."""
    await store.refresh_mine()
    if not pending:
        return
    wanted: set[str] = set()
    for kind in ("url", "domain"):
        wanted |= set(_clear_by_blind(kind, await store.recent_values(kind))) & pending
    await store.mark_mine_blinded(wanted)


async def answer_reveals(
    client: HubClient,
    store: Store,
    asked: list[wire.RevealRef],
    terms: SelfTerms | None,
    *,
    allow_documentation: bool = False,
) -> int:
    """Send the clear value of requested hashes this node holds. Returns how many were sent."""
    if not asked or terms is None:
        return 0
    # Only a hash we hold as a confirmed, blinded network target is ever revealed (a hub asking
    # for any other hash learns nothing), at most MAX_REVEALS per pull.
    allowed = await store.revealable({r.value_b for r in asked[:PAGE]})
    wanted: dict[tuple[str, str], None] = {
        (r.kind, r.value_b): None for r in asked[:PAGE] if r.value_b in allowed
    }
    if not wanted:
        return 0
    known: dict[tuple[str, str], str] = {}
    for kind in {k for k, _ in wanted}:
        for value_b, clear in _clear_by_blind(kind, await store.reveal_values(kind)).items():
            if (kind, value_b) in wanted:
                known[(kind, value_b)] = clear
    items: list[dict[str, str]] = []
    ctx = GuardContext(allow_documentation=allow_documentation)
    for (kind, value_b), clear in known.items():
        item = {"kind": kind, "value_b": value_b, "value": clear}
        if mentions_self(clear, terms):
            continue
        result = guard(clear, terms, fmt="text", ctx=ctx)
        if not set(result.codes) <= {"no_self_address"}:
            continue
        if not set(guard(item, terms, fmt="json", ctx=ctx).codes) <= {"no_self_address"}:
            continue
        items.append(item)
        if len(items) >= MAX_REVEALS:
            break
    if not items:
        return 0
    await client.reveals(items)
    return len(items)


async def answer_rechecks(client: HubClient, asked: list[wire.RecheckRef], today: date) -> int:
    """Send local re-check results (``up`` or ``down``). ``unknown`` is never sent."""
    if not asked:
        return 0
    states = await takedown.local_states([(r.id, r.kind, r.value) for r in asked])
    items = [{"id": hub_id, "state": s} for hub_id, s in states.items() if s in ("up", "down")][
        :MAX_RECHECKS
    ]
    if not items:
        return 0
    await client.rechecks(today.isoformat(), items)
    return len(items)


def summary_json(summary: wire.NetworkSummary) -> dict[str, Any]:
    return summary.model_dump(mode="json")

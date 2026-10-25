"""The assignment rules of campaign clustering, as a pure function.

Input: the unclustered sessions with their keys, and which campaign each known key already
belongs to. Output: who joins which campaign, which campaigns merge, and which groups of
sessions found a new one.

* any key already mapped: the session joins that campaign;
* keys mapped to several campaigns: those campaigns merge into the oldest;
* otherwise a key seen from at least ``min_sources`` distinct sources (3 for ``credlist``)
  among the unassigned sessions founds a campaign; sessions linked by such keys share it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ingest.campaigns.keys import Key

CREDLIST_MIN_SOURCES = 3


@dataclass(slots=True)
class Cand:
    """An unclustered session and the keys derived from it."""

    session_id: str
    sensor: str
    src_ip: str
    last_event_at: datetime
    started_at: datetime
    keys: set[Key] = field(default_factory=set)
    country: str | None = None
    asn: int | None = None
    tags: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    commands: int = 0
    downloads: int = 0
    login_attempts: int = 0
    demo: bool = False


@dataclass(slots=True)
class Plan:
    joins: dict[str, int] = field(default_factory=dict)
    merges: list[tuple[int, int]] = field(default_factory=list)  # (loser, winner)
    groups: list[list[str]] = field(default_factory=list)
    deferred: int = 0  # sessions left for the next cycle because the merge budget ran out


def required_sources(kind: str, min_sources: int) -> int:
    return max(min_sources, CREDLIST_MIN_SOURCES) if kind == "credlist" else min_sources


def build_plan(
    cands: list[Cand],
    key_campaign: dict[Key, int],
    campaign_order: dict[int, tuple[datetime, int]],
    min_sources: int,
    merge_budget: int = 50,
) -> Plan:
    """``key_campaign`` already points at live (non-merged) campaigns."""
    plan = Plan()
    merged_into: dict[int, int] = {}

    def root(cid: int) -> int:
        while cid in merged_into:
            cid = merged_into[cid]
        return cid

    pending = sorted(cands, key=lambda x: (x.last_event_at, x.session_id))
    unassigned: list[Cand] = pending
    progress = True
    while progress and unassigned:
        progress = False
        rest: list[Cand] = []
        for c in unassigned:
            mapped = {root(key_campaign[k]) for k in c.keys if k in key_campaign}
            if not mapped:
                rest.append(c)
                continue
            target = min(mapped, key=lambda cid: campaign_order.get(cid, (datetime.max, cid)))
            losers = mapped - {target}
            if losers and len(plan.merges) + len(losers) > merge_budget:
                plan.deferred += 1
                continue
            for loser in sorted(losers):
                plan.merges.append((loser, target))
                merged_into[loser] = target
                for key, cid in list(key_campaign.items()):
                    if cid == loser:
                        key_campaign[key] = target
            plan.joins[c.session_id] = target
            for k in c.keys:
                key_campaign.setdefault(k, target)
            progress = True
        unassigned = rest

    # Sessions of an earlier join may point at a campaign merged later in the same pass.
    plan.joins = {sid: root(cid) for sid, cid in plan.joins.items()}

    by_key: dict[Key, list[Cand]] = {}
    for c in unassigned:
        for key in c.keys:
            by_key.setdefault(key, []).append(c)
    parent: dict[str, str] = {c.session_id: c.session_id for c in unassigned}

    def find(sid: str) -> str:
        while parent[sid] != sid:
            parent[sid] = parent[parent[sid]]
            sid = parent[sid]
        return sid

    linked: set[str] = set()
    for (kind, _value), members in sorted(by_key.items()):
        if len({m.src_ip for m in members}) < required_sources(kind, min_sources):
            continue
        first = members[0].session_id
        for m in members:
            linked.add(m.session_id)
            parent[find(m.session_id)] = find(first)
    groups: dict[str, list[str]] = {}
    for c in unassigned:
        if c.session_id in linked:
            groups.setdefault(find(c.session_id), []).append(c.session_id)
    plan.groups = sorted(groups.values(), key=lambda g: g[0])
    return plan

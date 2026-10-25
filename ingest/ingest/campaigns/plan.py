"""The assignment rules of campaign clustering, as a pure function.

Input: the unclustered sessions with their keys, and which campaign each known key already
belongs to. Output: who joins which campaign, which campaigns merge, and which groups of
sessions found a new one.

* a session whose key is already mapped joins that campaign (the oldest, if several);
* campaigns merge only through a *strong* key, one seen from at least ``min_sources`` distinct
  networks (a /24 for IPv4, a /64 for IPv6), and at most one merge per session. A weak key
  never bridges campaigns, so one attacker cannot glue unrelated campaigns together;
* otherwise a strong key among the unassigned sessions founds a campaign, and sessions linked
  by such keys share it;
* a joining session only teaches the campaign its non-matching keys when those are strong.

Linear in the number of sessions and keys: a key index and union-find, no rescans.
"""

from __future__ import annotations

import ipaddress
from collections import deque
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
    deferred: int = 0  # reserved: sessions left for a later cycle
    #: Keys to store for each existing campaign (matched or strong), by live campaign id.
    persist: dict[int, set[Key]] = field(default_factory=dict)
    #: Keys to store for each new group (index into ``groups``): the strong ones.
    group_keys: list[set[Key]] = field(default_factory=list)


def required_sources(kind: str, min_sources: int) -> int:
    return max(min_sources, CREDLIST_MIN_SOURCES) if kind == "credlist" else min_sources


def net_of(ip: str) -> str:
    """The network an address counts as: its /24 (IPv4) or /64 (IPv6)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    prefix = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))


def build_plan(
    cands: list[Cand],
    key_campaign: dict[Key, int],
    campaign_order: dict[int, tuple[datetime, int]],
    min_sources: int,
    merge_budget: int = 50,
    key_sources: dict[Key, int] | None = None,
) -> Plan:
    """``key_campaign`` points at live (non-merged) campaigns; ``key_sources`` is the number of
    distinct sources already recorded for stored keys."""
    plan = Plan()
    stored = key_sources or {}
    by_key: dict[Key, list[Cand]] = {}
    for c in cands:
        for key in c.keys:
            by_key.setdefault(key, []).append(c)
    nets = {k: {net_of(m.src_ip) for m in members} for k, members in by_key.items()}

    def strong(key: Key) -> bool:
        need = required_sources(key[0], min_sources)
        return max(stored.get(key, 0), len(nets.get(key, ()))) >= need

    merged_into: dict[int, int] = {}

    def root(cid: int) -> int:
        while cid in merged_into:
            cid = merged_into[cid]
        return cid

    def oldest(ids: set[int]) -> int:
        return min(ids, key=lambda cid: campaign_order.get(cid, (datetime.max, cid)))

    mapping = dict(key_campaign)
    original = set(key_campaign)
    joined: dict[str, int] = {}
    queue: deque[Cand] = deque(sorted(cands, key=lambda x: (x.last_event_at, x.session_id)))
    while queue:
        c = queue.popleft()
        if c.session_id in joined:
            continue
        mapped = {root(mapping[k]) for k in c.keys if k in mapping}
        if not mapped:
            continue
        target = oldest(mapped)
        strong_mapped = {root(mapping[k]) for k in c.keys if k in mapping and strong(k)}
        if target in strong_mapped and len(plan.merges) < merge_budget:
            losers = strong_mapped - {target}
            if losers:  # at most one merge per session
                loser = oldest(losers)
                plan.merges.append((loser, target))
                merged_into[loser] = target
        joined[c.session_id] = target
        for k in sorted(c.keys):
            if k in mapping:
                continue
            if strong(k):
                mapping[k] = target
                queue.extend(m for m in by_key[k] if m.session_id not in joined)
    plan.joins = {sid: root(cid) for sid, cid in joined.items()}
    for c in cands:
        cid = plan.joins.get(c.session_id)
        if cid is None:
            continue
        keep = {k for k in c.keys if k in original or strong(k)}
        plan.persist.setdefault(cid, set()).update(keep)

    # New campaigns among the sessions that matched nothing: union-find over strong keys.
    unassigned = [c for c in cands if c.session_id not in plan.joins]
    parent: dict[str, str] = {c.session_id: c.session_id for c in unassigned}

    def find(sid: str) -> str:
        while parent[sid] != sid:
            parent[sid] = parent[parent[sid]]
            sid = parent[sid]
        return sid

    free = set(parent)
    linked: set[str] = set()
    group_keys_of: dict[str, set[Key]] = {}
    for key, members in sorted(by_key.items()):
        live = [m for m in members if m.session_id in free]
        if not live or len({net_of(m.src_ip) for m in live}) < required_sources(
            key[0], min_sources
        ):
            continue
        first = live[0].session_id
        for m in live:
            linked.add(m.session_id)
            parent[find(m.session_id)] = find(first)
    groups: dict[str, list[str]] = {}
    for c in unassigned:
        if c.session_id in linked:
            groups.setdefault(find(c.session_id), []).append(c.session_id)
    for key, members in sorted(by_key.items()):
        live = [m for m in members if m.session_id in linked]
        if live and len({net_of(m.src_ip) for m in live}) >= required_sources(key[0], min_sources):
            group_keys_of.setdefault(find(live[0].session_id), set()).add(key)
    ordered = sorted(groups.items(), key=lambda kv: kv[1][0])
    plan.groups = [g for _, g in ordered]
    plan.group_keys = [group_keys_of.get(root_id, set()) for root_id, _ in ordered]
    return plan

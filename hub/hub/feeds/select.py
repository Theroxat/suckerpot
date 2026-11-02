"""Which confirmed targets become feed candidates (design M30 sections 4.2 to 4.4).

Pure functions over loaded rows. Inputs are M29 consensus targets in state ``confirmed`` or
``reported`` and the per-node observations of eligible nodes. Rules stricter than consensus:

* **TCP-proven inbound behaviour only.** Scans, bare connects and ``http``-only evidence never
  list an address. Evidence that exists only on ``sip`` (UDP, spoofable) never lists one either.
* **k-support.** Every published value (activity category, service, tag, family, port) and both
  dates need at least ``k`` distinct eligible nodes behind them, so one node's sighting changes
  nothing public (``hub.support`` holds the helpers).
* **Outbound** needs a payload fetched with a known family by two nodes (or outside
  corroboration), or two distinct droppers that two nodes each named for a C2.

``evaluate`` returns the candidate (or ``None``) and whether an outside lookup could still turn
the answer around, so the caller can spend its quota only where it matters.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, timedelta

from suckerpot_netproto.enums import FAMILIES_V1, SERVICES, is_valid_tag

from ..never import split_host_port
from ..support import first_day_supported, k_supported, last_day_supported

INBOUND = "inbound"
OUTBOUND = "outbound"
DOMAINS = "outbound-domains"
BASE_LISTS = (INBOUND, OUTBOUND, DOMAINS)

STRONG_IN = frozenset({"login_success", "command", "download", "exploit"})
ACTIVITY_CATEGORY = {
    "login": "brute-force",
    "login_success": "login-success",
    "command": "command-exec",
    "download": "malware-drop",
    "exploit": "exploit",
}
UDP_SERVICES = frozenset({"sip"})
LOGIN_ATTEMPTS_MIN = 2  # bucket 2 = 10 to 99 attempts
MIN_FETCHERS = 2
MIN_DROPPERS = 2
HIGH_DAYS = 3
HIGH_COHORTS = 3
GOOD_STATES = frozenset({"confirmed", "reported"})

KIND_LIST = {
    "ip": INBOUND,
    "payload_ip": OUTBOUND,
    "c2_ip": OUTBOUND,
    "domain": DOMAINS,
    "c2_domain": DOMAINS,
}


@dataclass(frozen=True)
class Obs:
    """One observation row of an eligible node."""

    node: uuid.UUID
    day: date
    services: tuple[str, ...] = ()
    activity: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    families: tuple[str, ...] = ()
    attempts: int | None = None
    fetched: bool = False
    via: str | None = None


@dataclass(frozen=True)
class TargetInput:
    target_id: str
    kind: str
    value: str  # clear value; "ip:port" or "[v6]:port" for c2_ip
    state: str
    confirmed_day: date | None
    reported: bool
    obs: Sequence[Obs]


@dataclass(frozen=True)
class SelectContext:
    k: int
    today: date
    cohort_of: Mapping[uuid.UUID, date]  # enrolment week of every eligible node
    ttl_inbound: int = 7
    ttl_payload: int = 14
    ttl_c2: int = 30


@dataclass
class Candidate:
    """A value that qualifies for a base list (the high list is derived from ``tier``)."""

    list_id: str
    value: str
    family: int | str  # 4, 6 or "dns"
    tier: str
    categories: set[str] = field(default_factory=set)
    services: set[str] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)
    families: set[str] = field(default_factory=set)
    ports: set[int] = field(default_factory=set)
    first_seen: date = date.min
    last_seen: date = date.min
    expires: date = date.min
    reported: bool = False
    target_id: str | None = None
    confirmed_day: date | None = None


@dataclass(frozen=True)
class Evaluation:
    candidate: Candidate | None
    # True when the answer depends on an outside lookup that has not been made yet.
    needs_lookup: bool = False


def _by_node(rows: Sequence[Obs]) -> dict[uuid.UUID, set[date]]:
    out: dict[uuid.UUID, set[date]] = defaultdict(set)
    for r in rows:
        out[r.node].add(r.day)
    return dict(out)


def _seen(rows: Sequence[Obs], attr: str) -> dict[str, set[object]]:
    out: dict[str, set[object]] = defaultdict(set)
    for r in rows:
        for v in getattr(r, attr):
            out[v].add(r.node)
    return dict(out)


def _published_fields(rows: Sequence[Obs], k: int) -> tuple[set[str], set[str], set[str]]:
    services = {v for v in k_supported(_seen(rows, "services"), k) if v in SERVICES}
    tags = {v for v in k_supported(_seen(rows, "tags"), k) if is_valid_tag(v)}
    families = {v for v in k_supported(_seen(rows, "families"), k) if v in FAMILIES_V1}
    return services, tags, families


def _high(
    rows: Sequence[Obs], ctx: SelectContext, days: set[date], corroborated: bool | None
) -> bool:
    nodes = {r.node for r in rows}
    cohorts = {ctx.cohort_of[n] for n in nodes if n in ctx.cohort_of}
    return (
        len(nodes) >= 2 * ctx.k
        and len(days) >= HIGH_DAYS
        and len(cohorts) >= HIGH_COHORTS
        and corroborated is True
    )


def _tcp(row: Obs) -> bool:
    return any(s not in UDP_SERVICES for s in row.services)


def _window(ttl: int, last: date) -> date:
    return last + timedelta(days=ttl)


def _evaluate_inbound(t: TargetInput, ctx: SelectContext, corroborated: bool | None) -> Evaluation:
    rows = list(t.obs)
    if len({r.node for r in rows}) < ctx.k:
        return Evaluation(None)
    # Evidence kinds. "login" counts only as a heavy brute force (attempts bucket >= 2).
    everywhere: dict[str, set[object]] = defaultdict(set)
    on_tcp: dict[str, set[object]] = defaultdict(set)
    for r in rows:
        keys = {a for a in r.activity if a in STRONG_IN}
        if "login" in r.activity and (r.attempts or 0) >= LOGIN_ATTEMPTS_MIN:
            keys.add("login")
        for key in keys:
            everywhere[key].add(r.node)
            if _tcp(r):
                on_tcp[key].add(r.node)
    supported = {key for key, nodes in everywhere.items() if len(nodes) >= ctx.k}
    if not any(len(on_tcp.get(key, ())) >= ctx.k for key in supported):
        return Evaluation(None)
    # Dates follow the rows that carry k-supported evidence on a TCP service.
    evidence = [
        r
        for r in rows
        if _tcp(r)
        and (
            any(a in supported for a in r.activity if a in STRONG_IN)
            or ("login" in supported and "login" in r.activity)
        )
    ]
    days_by_node = _by_node(evidence)
    last = last_day_supported(days_by_node, ctx.k)
    first = first_day_supported(days_by_node, ctx.k)
    if last is None or first is None:
        return Evaluation(None)
    expires = _window(ctx.ttl_inbound, last)
    if expires < ctx.today:
        return Evaluation(None)
    services, tags, _ = _published_fields(rows, ctx.k)
    all_days = {r.day for r in evidence}
    needs = corroborated is None and _high(evidence, ctx, all_days, True)
    tier = "high" if _high(evidence, ctx, all_days, corroborated) else "standard"
    family = ipaddress.ip_address(t.value).version
    return Evaluation(
        Candidate(
            INBOUND,
            t.value,
            family,
            tier,
            categories={ACTIVITY_CATEGORY[a] for a in supported},
            services=services,
            tags=tags,
            first_seen=first,
            last_seen=last,
            expires=expires,
            reported=t.reported,
            target_id=t.target_id,
            confirmed_day=t.confirmed_day,
        ),
        needs_lookup=needs,
    )


def _fetch_evidence(rows: Sequence[Obs]) -> bool:
    """A payload fetched with a known malware family by at least two nodes."""
    fetchers = {r.node for r in rows if r.fetched and any(f in FAMILIES_V1 for f in r.families)}
    return len(fetchers) >= MIN_FETCHERS


def _dropper_evidence(rows: Sequence[Obs]) -> bool:
    """At least two distinct droppers, each named by at least two nodes."""
    named: dict[str, set[object]] = defaultdict(set)
    for r in rows:
        if r.via:
            named[r.via].add(r.node)
    return sum(1 for nodes in named.values() if len(nodes) >= MIN_FETCHERS) >= MIN_DROPPERS


def _evaluate_outbound(
    t: TargetInput, ctx: SelectContext, corroborated: bool | None, abusech: bool
) -> Evaluation:
    rows = list(t.obs)
    c2 = t.kind in ("c2_ip", "c2_domain")
    if len({r.node for r in rows}) < ctx.k:
        return Evaluation(None)
    # The abuse.ch corroboration (URLhaus for a payload host, ThreatFox for a C2) replaces the
    # sample evidence; an address-reputation hit only counts towards the high tier.
    if not (abusech or (_dropper_evidence(rows) if c2 else _fetch_evidence(rows))):
        return Evaluation(None)
    days_by_node = _by_node(rows)
    last = last_day_supported(days_by_node, ctx.k)
    first = first_day_supported(days_by_node, ctx.k)
    if last is None or first is None:
        return Evaluation(None)
    expires = _window(ctx.ttl_c2 if c2 else ctx.ttl_payload, last)
    if expires < ctx.today:
        return Evaluation(None)
    _, tags, families = _published_fields(rows, ctx.k)
    ports: set[int] = set()
    value = t.value
    if t.kind == "c2_ip":
        value, port = split_host_port(t.value)
        if port is not None:
            ports.add(port)
    all_days = {r.day for r in rows}
    needs = corroborated is None and _high(rows, ctx, all_days, True)
    tier = "high" if _high(rows, ctx, all_days, corroborated) else "standard"
    is_domain = t.kind in ("domain", "c2_domain")
    family: int | str = "dns" if is_domain else ipaddress.ip_address(value).version
    return Evaluation(
        Candidate(
            DOMAINS if is_domain else OUTBOUND,
            value,
            family,
            tier,
            categories={"c2"} if c2 else {"payload-host"},
            tags=tags,
            families=families,
            ports=ports,
            first_seen=first,
            last_seen=last,
            expires=expires,
            reported=t.reported,
            target_id=t.target_id,
            confirmed_day=t.confirmed_day,
        ),
        needs_lookup=needs,
    )


def evaluate(
    t: TargetInput, ctx: SelectContext, corroborated: bool | None, abusech: bool = False
) -> Evaluation:
    """The candidate for one target, or ``None``.

    ``corroborated`` (any outside source says the value is hostile) is ``None`` when it was not
    asked; it only decides the high tier. ``abusech`` is the URLhaus or ThreatFox answer.
    """
    if t.state not in GOOD_STATES or t.kind not in KIND_LIST:
        return Evaluation(None)
    if t.kind == "ip":
        return _evaluate_inbound(t, ctx, corroborated)
    return _evaluate_outbound(t, ctx, corroborated, abusech)


def merge(a: Candidate, b: Candidate) -> Candidate:
    """Two targets of one value (a C2 on several ports, a payload host that is also a C2)."""
    return Candidate(
        a.list_id,
        a.value,
        a.family,
        "high" if "high" in (a.tier, b.tier) else "standard",
        a.categories | b.categories,
        a.services | b.services,
        a.tags | b.tags,
        a.families | b.families,
        a.ports | b.ports,
        min(a.first_seen, b.first_seen),
        max(a.last_seen, b.last_seen),
        max(a.expires, b.expires),
        a.reported or b.reported,
        min(x for x in (a.target_id, b.target_id) if x is not None)
        if a.target_id or b.target_id
        else None,
        min(x for x in (a.confirmed_day, b.confirmed_day) if x is not None)
        if a.confirmed_day or b.confirmed_day
        else None,
    )


def merge_all(items: Sequence[Candidate]) -> dict[tuple[str, str], Candidate]:
    out: dict[tuple[str, str], Candidate] = {}
    for c in items:
        key = (c.list_id, c.value)
        out[key] = merge(out[key], c) if key in out else c
    return out

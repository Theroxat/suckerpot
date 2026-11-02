"""Exclusions (design M30 section 5.3): what no feed may ever carry.

Applied to candidates and again to every entry that is already listed, because the lists grow
between runs (a new CDN range, a new allow-list row, a longer never-list). ``classify`` answers
with the first matching reason, or ``None``.

Sources, in this order:

* ``reserved``: private, loopback, link-local, multicast, documentation (unless the test flag is
  set), CGNAT and other non-global space, and anything that is not a canonical single address;
* ``never_list``: ``hub/data/never.yaml`` (a superset of the M16 values), the operator's
  ``never_list`` table and ``HUB_FEED_NEVER``;
* ``allow_list`` / ``delisted``: the operator allow-list (``feed_allow``), which may hold CIDRs
  (allowing is safe, listing a prefix is not);
* ``cdn`` and ``tor``: address ranges kept in ``feed_auto_ranges`` by the range fetcher. Tor exits
  are always excluded; there is no switch.

Delisting decisions and suppressions are scoped per list: a request about ``inbound`` never
removes the same value from ``outbound`` (a bot address that also serves malware).
"""

from __future__ import annotations

import bisect
import ipaddress
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_netproto.blind import canonical_domain
from suckerpot_netproto.feeds.models import check_ip_global

from ..config import Settings
from .external import load_sources

NEVER_FILE = Path(__file__).resolve().parent.parent / "data" / "never.yaml"
RANGES_MAX_AGE_DAYS = 30

IPNet = ipaddress.IPv4Network | ipaddress.IPv6Network

# Reasons, as stored in counters and stats.json.
RESERVED = "reserved"
NEVER = "never_list"
ALLOW = "allow_list"
DELISTED = "delisted"
CDN = "cdn"
TOR = "tor"
SUPPRESSIBLE = "inbound"  # the only list a pending delisting request may hide a value from


class RangesStale(RuntimeError):
    """A CDN or Tor source is missing or older than 30 days: every feed run stops."""


def required_sources() -> set[str]:
    """Every source of ``ranges.yaml``, and ``tor`` always (Tor exits are always excluded)."""
    return {src.name for src in load_sources()} | {TOR}


class NetSet:
    """Merged address intervals, answering "is this address inside any network" in O(log n)."""

    def __init__(self, networks: list[IPNet] | None = None) -> None:
        self._starts: dict[int, list[int]] = {4: [], 6: []}
        self._ends: dict[int, list[int]] = {4: [], 6: []}
        spans: dict[int, list[tuple[int, int]]] = {4: [], 6: []}
        for n in networks or []:
            spans[n.version].append((int(n.network_address), int(n.broadcast_address)))
        for version, items in spans.items():
            items.sort()
            merged: list[tuple[int, int]] = []
            for lo, hi in items:
                if merged and lo <= merged[-1][1] + 1:
                    merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
                else:
                    merged.append((lo, hi))
            self._starts[version] = [m[0] for m in merged]
            self._ends[version] = [m[1] for m in merged]

    def __contains__(self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        starts = self._starts[addr.version]
        i = bisect.bisect_right(starts, int(addr)) - 1
        return i >= 0 and int(addr) <= self._ends[addr.version][i]

    def __bool__(self) -> bool:
        return bool(self._starts[4] or self._starts[6])


def _suffix_hit(name: str, domains: set[str]) -> bool:
    parts = name.lower().rstrip(".").split(".")
    return any(".".join(parts[i:]) in domains for i in range(len(parts)))


def parse_network(raw: str) -> IPNet | None:
    try:
        return ipaddress.ip_network(raw.strip(), strict=False)
    except ValueError:
        return None


def load_never_file(path: Path = NEVER_FILE) -> tuple[list[IPNet], set[str]]:
    """Networks and domains of the packaged never-list."""
    data: Any = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    nets = [n for n in (parse_network(str(v)) for v in data.get("ips", [])) if n is not None]
    domains = {canonical_domain(str(v)) for v in data.get("domains", [])}
    return nets, domains


ANY_LIST = "*"


@dataclass
class Exclusions:
    never_nets: NetSet = field(default_factory=NetSet)
    never_domains: set[str] = field(default_factory=set)
    allow_nets: NetSet = field(default_factory=NetSet)
    allow_domains: set[str] = field(default_factory=set)
    # Delisting decisions and suppressions, per list they apply to (``ANY_LIST`` for every list).
    # A request about ``inbound`` never takes a value off ``outbound`` (security review H1).
    delisted_nets: dict[str, NetSet] = field(default_factory=dict)
    delisted_domains: dict[str, set[str]] = field(default_factory=dict)
    cdn_nets: NetSet = field(default_factory=NetSet)
    tor_nets: NetSet = field(default_factory=NetSet)
    allow_documentation: bool = False

    def _scopes(self, list_id: str | None) -> list[str]:
        """The scopes that apply to ``list_id``; ``None`` (no list known) means all of them."""
        if list_id is None:
            return sorted(set(self.delisted_nets) | set(self.delisted_domains))
        return [ANY_LIST, list_id]

    def classify(self, value: str, *, is_domain: bool, list_id: str | None = None) -> str | None:
        """The reason ``value`` may not be listed on ``list_id``, or ``None``."""
        scopes = self._scopes(list_id)
        if is_domain:
            if any(_suffix_hit(value, self.delisted_domains.get(sc, set())) for sc in scopes):
                return DELISTED
            if _suffix_hit(value, self.allow_domains):
                return ALLOW
            if _suffix_hit(value, self.never_domains):
                return NEVER
            return None
        try:
            check_ip_global(value, allow_documentation=self.allow_documentation)
            addr = ipaddress.ip_address(value)
        except ValueError:
            return RESERVED
        if any(addr in self.delisted_nets[sc] for sc in scopes if sc in self.delisted_nets):
            return DELISTED
        if addr in self.allow_nets:
            return ALLOW
        if addr in self.never_nets:
            return NEVER
        if addr in self.cdn_nets:
            return CDN
        # Tor exits are always excluded (no switch): the attacker is not the exit.
        if addr in self.tor_nets:
            return TOR
        return None


def build_exclusions(
    s: Settings,
    *,
    never_rows: list[tuple[str, str]],
    allow_rows: list[tuple[str, str, str, str | None]],
    range_rows: list[tuple[str, str]],
) -> Exclusions:
    """Assemble the exclusion sets from loaded rows.

    ``never_rows``: ``(value, kind)`` of ``never_list``; ``allow_rows``: ``(value, kind,
    source, list)`` of live ``feed_allow`` rows (``list`` NULL for every list; only rows from a
    delisting carry one); ``range_rows``: ``(source, prefix)`` of ``feed_auto_ranges``.
    """
    nets, domains = load_never_file()
    for value, kind in never_rows:
        if kind == "ip" and (n := parse_network(value)) is not None:
            nets.append(n)
        elif kind == "domain":
            try:
                domains.add(canonical_domain(value))
            except ValueError:
                continue
    for raw in s.feed_never:
        if (n := parse_network(raw)) is not None:
            nets.append(n)
        else:
            try:
                domains.add(canonical_domain(raw))
            except ValueError:
                continue
    allow_nets: list[IPNet] = []
    allow_domains: set[str] = set()
    delisted_nets: dict[str, list[IPNet]] = {}
    delisted_domains: dict[str, set[str]] = {}
    for value, kind, source, scope in allow_rows:
        # A delisting decision (or any row scoped to one list) is kept per list; an operator row
        # without a list applies everywhere.
        delisted = source == "delist" or scope is not None
        key = scope or ANY_LIST
        if kind == "ip" and (n := parse_network(value)) is not None:
            if delisted:
                delisted_nets.setdefault(key, []).append(n)
            else:
                allow_nets.append(n)
        elif kind == "domain":
            try:
                name = canonical_domain(value)
            except ValueError:
                continue
            if delisted:
                delisted_domains.setdefault(key, set()).add(name)
            else:
                allow_domains.add(name)
    cdn: list[IPNet] = []
    tor: list[IPNet] = []
    for source, prefix in range_rows:
        if (n := parse_network(prefix)) is None:
            continue
        if source == "tor":
            tor.append(n)
        elif source.startswith("cdn:"):
            cdn.append(n)
    return Exclusions(
        never_nets=NetSet(nets),
        never_domains=domains,
        allow_nets=NetSet(allow_nets),
        allow_domains=allow_domains,
        delisted_nets={k: NetSet(v) for k, v in delisted_nets.items()},
        delisted_domains=delisted_domains,
        cdn_nets=NetSet(cdn),
        tor_nets=NetSet(tor),
        allow_documentation=s.allow_documentation,
    )


async def load_exclusions(session: AsyncSession, s: Settings, today: date) -> Exclusions:
    """Load every source. Raises ``RangesStale`` when the CDN or Tor ranges cannot be trusted."""
    never_rows = [
        (r[0], r[1]) for r in (await session.execute(text("SELECT value, kind FROM never_list")))
    ]
    allow_rows: list[tuple[str, str, str, str | None]] = [
        (r[0], r[1], r[2], r[3])
        for r in (
            await session.execute(
                text(
                    "SELECT value, kind, source, list FROM feed_allow "
                    "WHERE expires_day IS NULL OR expires_day >= :today"
                ),
                {"today": today},
            )
        )
    ]
    # A value hidden by a delisting request stays out of ``inbound`` until an operator decides.
    # Only ``inbound`` is ever suppressed (design 9.2): the outbound lists keep the value.
    for (hidden,) in await session.execute(
        text("SELECT value FROM delist_requests WHERE state = 'suppressed'")
    ):
        allow_rows.append(
            (hidden, "ip" if parse_network(hidden) else "domain", "delist", SUPPRESSIBLE)
        )
    ranges = (
        await session.execute(text("SELECT source, prefix, fetched_day FROM feed_auto_ranges"))
    ).all()
    newest: dict[str, date] = {}
    for source, _prefix, fetched in ranges:
        newest[source] = max(newest.get(source, fetched), fetched)
    # Fail closed per source: one source that was never fetched (or went stale) would let its
    # addresses through while the others look fine (security review M1).
    oldest_ok = today - timedelta(days=RANGES_MAX_AGE_DAYS)
    if any(newest.get(name, date.min) < oldest_ok for name in required_sources()):
        raise RangesStale("ranges_stale")
    return build_exclusions(
        s,
        never_rows=never_rows,
        allow_rows=allow_rows,
        range_rows=[(r[0], r[1]) for r in ranges],
    )


def count_reasons(reasons: list[str | None]) -> Counter[str]:
    return Counter(r for r in reasons if r)

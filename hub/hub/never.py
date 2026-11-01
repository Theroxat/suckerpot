"""The never-list: values that can never become a published or reported target.

Public resolvers, large CDNs and SaaS ranges, research scanners and anything the operator adds
(``python -m hub.admin never add``). Entry kinds:

* ``ip``: one address or a CIDR network;
* ``domain``: a name; it also covers every sub-domain;
* ``sha256``: a file hash (known-good files);
* ``url``: a canonical URL prefix is NOT supported; add its domain instead.

Reserved space (private, loopback, documentation, ...) is refused earlier, by the protocol
models, and needs no entry.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_netproto import blind

from .models import NeverList

CACHE_TTL_S = 60.0

IPNet = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass
class Never:
    networks: list[IPNet] = field(default_factory=list)
    domains: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)

    @classmethod
    def from_rows(cls, rows: list[tuple[str, str]]) -> Never:
        out = cls()
        for value, kind in rows:
            try:
                if kind == "ip":
                    out.networks.append(ipaddress.ip_network(value, strict=False))
                elif kind == "domain":
                    out.domains.add(blind.canonical_domain(value))
                elif kind == "sha256":
                    out.hashes.add(value.lower())
            except ValueError:
                continue  # a bad entry never breaks the hub
        return out

    def has_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip.split(":")[0] if ip.count(":") == 1 else ip)
        except ValueError:
            return False
        return any(addr.version == n.version and addr in n for n in self.networks)

    def has_domain(self, name: str) -> bool:
        parts = name.lower().rstrip(".").split(".")
        return any(".".join(parts[i:]) in self.domains for i in range(len(parts)))

    def has_hash(self, digest: str) -> bool:
        return digest.lower() in self.hashes

    def has_url(self, canonical: str) -> bool:
        host = blind.url_host(canonical)
        if host.startswith("["):
            return self.has_ip(host[1:-1])
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            return self.has_domain(host)
        return self.has_ip(host)

    def matches(self, kind: str, value: str) -> bool:
        """Whether a clear target value is on the list. Blinded values cannot be checked."""
        if kind in ("ip", "c2_ip"):
            return self.has_ip(value)
        if kind in ("domain", "c2_domain"):
            return self.has_domain(value)
        if kind == "url":
            return self.has_url(value)
        if kind == "sha256":
            return self.has_hash(value)
        return False


async def load_never(session: AsyncSession) -> Never:
    rows = (await session.execute(select(NeverList.value, NeverList.kind))).all()
    return Never.from_rows([(r[0], r[1]) for r in rows])


class NeverCache:
    """The list, reloaded at most once a minute."""

    def __init__(self) -> None:
        self._never = Never()
        self._at = -CACHE_TTL_S

    async def get(self, session: AsyncSession) -> Never:
        now = time.monotonic()
        if now - self._at >= CACHE_TTL_S:
            self._never = await load_never(session)
            self._at = now
        return self._never

    def invalidate(self) -> None:
        self._at = -CACHE_TTL_S

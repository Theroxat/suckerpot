"""RDAP bootstrap registries (RFC 9224): which server answers for an address, AS number or TLD."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

REGISTRIES = ("ipv4", "ipv6", "asn", "dns")
IANA_URL = "https://data.iana.org/rdap/{}.json"
IANA_HOST = "data.iana.org"
RIPESTAT_HOST = "stat.ripe.net"
SNAPSHOT_DIR = Path(__file__).parent / "bootstrap"

# Suffixes made of two labels, so that the registrable domain is the third label from the end.
TWO_LABEL_SUFFIXES = frozenset(
    "co.uk org.uk ac.uk gov.uk me.uk net.uk com.au net.au org.au co.jp ne.jp or.jp com.br net.br "
    "com.cn net.cn org.cn co.in net.in co.za com.tr com.mx co.nz com.sg com.hk co.kr or.kr "
    "com.ua com.ar".split()
)


def public_https_host(url: str) -> str | None:
    """The host of an https URL on a public name (never an address, never a single label)."""
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    if parts.scheme != "https" or "." not in host or parts.username or parts.password:
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    return None


@dataclass(frozen=True)
class Bootstrap:
    """The four registries as parsed JSON documents."""

    docs: dict[str, dict[str, Any]] = field(default_factory=dict)

    def _services(self, registry: str) -> list[tuple[list[str], list[str]]]:
        out: list[tuple[list[str], list[str]]] = []
        raw = self.docs.get(registry, {}).get("services", [])
        if not isinstance(raw, list):
            return out
        for entry in raw:
            if (
                isinstance(entry, list)
                and len(entry) == 2
                and isinstance(entry[0], list)
                and isinstance(entry[1], list)
            ):
                keys = [k for k in entry[0] if isinstance(k, str)]
                urls = [u for u in entry[1] if isinstance(u, str)]
                out.append((keys, urls))
        return out

    @staticmethod
    def _base(urls: list[str]) -> str | None:
        # RFC 9224: prefer https; only https on a public name is ever used here.
        for url in urls:
            if public_https_host(url):
                return url if url.endswith("/") else url + "/"
        return None

    def for_ip(self, ip: str) -> str | None:
        addr = ipaddress.ip_address(ip)
        best: tuple[int, str] | None = None
        for prefixes, urls in self._services("ipv4" if addr.version == 4 else "ipv6"):
            for prefix in prefixes:
                try:
                    net = ipaddress.ip_network(prefix, strict=False)
                except ValueError:
                    continue
                base = self._base(urls)
                if net.version == addr.version and addr in net and base:
                    if best is None or net.prefixlen > best[0]:
                        best = (net.prefixlen, base)
        return best[1] if best else None

    def for_asn(self, asn: int) -> str | None:
        for ranges, urls in self._services("asn"):
            for item in ranges:
                low, _, high = item.partition("-")
                try:
                    lo, hi = int(low), int(high or low)
                except ValueError:
                    continue
                if lo <= asn <= hi:
                    return self._base(urls)
        return None

    def for_tld(self, tld: str) -> str | None:
        wanted = tld.lower()
        for labels, urls in self._services("dns"):
            if wanted in (label.lower() for label in labels):
                return self._base(urls)
        return None

    def hosts(self) -> frozenset[str]:
        """Every RDAP server host named by the registries, plus the two fixed helpers."""
        found = {IANA_HOST, RIPESTAT_HOST}
        for registry in REGISTRIES:
            for _, urls in self._services(registry):
                found.update(h for u in urls if (h := public_https_host(u)))
        return frozenset(found)


def valid_registry(doc: object) -> bool:
    return (
        isinstance(doc, dict)
        and isinstance(doc.get("services"), list)
        and 0 < len(doc["services"]) <= 5000
    )


def load_snapshot() -> Bootstrap:
    docs: dict[str, dict[str, Any]] = {}
    for registry in REGISTRIES:
        doc = json.loads((SNAPSHOT_DIR / f"{registry}.json").read_text())
        if valid_registry(doc):
            docs[registry] = doc
    return Bootstrap(docs)


def registrable_domain(name: str) -> tuple[str, str] | None:
    """``(registrable domain, tld)`` of a host name, or None for a name that has none."""
    labels = [p for p in name.lower().strip(".").split(".") if p]
    if len(labels) < 2 or not all(1 <= len(p) <= 63 for p in labels):
        return None
    take = 3 if ".".join(labels[-2:]) in TWO_LABEL_SUFFIXES else 2
    if len(labels) < take:
        return None
    return ".".join(labels[-take:]), labels[-1]

"""Abuse contacts through RDAP (ported from the node's ``ingest/abuse/rdap.py``).

Same limits: https on public names only, at most two redirects (each to a host the IANA bootstrap
names), 512 KiB per answer, JSON depth 3, spacing per host, a global request budget per run.
This is the hub's own outbound traffic (project infrastructure); it never carries node data.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

log = logging.getLogger("hub.rdap")

USER_AGENT = "Mozilla/5.0 (compatible; rdap-client)"
TIMEOUT = httpx.Timeout(15.0, connect=10.0)
MAX_BODY = 512 * 1024
MAX_REDIRECTS = 2
MAX_DEPTH = 3
MAX_MAILBOXES = 5
HOST_SPACING_S = 2.0
IANA_URL = "https://data.iana.org/rdap/{}.json"
IANA_HOST = "data.iana.org"
BOOTSTRAP_TTL_S = 24 * 3600

_PRIVATE_TLDS = frozenset(
    "local localhost internal lan home corp intranet localdomain private arpa invalid test onion".split()
)
_LOCAL = re.compile(r"^[a-z0-9._%+\-]{1,64}$")
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$")
TWO_LABEL_SUFFIXES = frozenset(
    "co.uk org.uk ac.uk gov.uk me.uk net.uk com.au net.au org.au co.jp ne.jp or.jp com.br net.br "
    "com.cn net.cn org.cn co.in net.in co.za com.tr com.mx co.nz com.sg com.hk co.kr or.kr "
    "com.ua com.ar".split()
)


class RdapError(Exception):
    """A lookup failed; the message is a short constant code."""


def public_https_host(url: str) -> str | None:
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


def valid_mailbox(raw: object) -> str | None:
    if not isinstance(raw, str):
        return None
    mail = raw.strip().lower().removeprefix("mailto:")
    if not mail.isascii() or not 3 <= len(mail) <= 254 or mail.count("@") != 1:
        return None
    local, domain = mail.split("@")
    labels = domain.split(".")
    if not _LOCAL.match(local) or len(labels) < 2 or len(domain) > 253:
        return None
    if not all(_LABEL.match(p) for p in labels) or labels[-1] in _PRIVATE_TLDS:
        return None
    return None if labels[-1].isdigit() else mail


def _entities(doc: Mapping[str, Any], depth: int = 0) -> list[Mapping[str, Any]]:
    out: list[Mapping[str, Any]] = []
    raw = doc.get("entities")
    for ent in raw[:50] if isinstance(raw, list) else []:
        if isinstance(ent, dict):
            out.append(ent)
            if depth + 1 < MAX_DEPTH:
                out.extend(_entities(ent, depth + 1))
    return out


def abuse_mailboxes(doc: Mapping[str, Any]) -> list[str]:
    """Mailboxes of entities with the ``abuse`` role (nested up to three deep)."""
    out: list[str] = []
    for ent in _entities(doc):
        roles = ent.get("roles")
        if not (isinstance(roles, list) and "abuse" in [str(r).lower() for r in roles]):
            continue
        card = ent.get("vcardArray")
        items = card[1] if isinstance(card, list) and len(card) == 2 else []
        for item in items if isinstance(items, list) else []:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "email":
                if (mail := valid_mailbox(item[3])) is not None:
                    out.append(mail)
    return list(dict.fromkeys(out))[:MAX_MAILBOXES]


def registrable_domain(name: str) -> tuple[str, str] | None:
    labels = [p for p in name.lower().strip(".").split(".") if p]
    if len(labels) < 2 or not all(1 <= len(p) <= 63 for p in labels):
        return None
    take = 3 if ".".join(labels[-2:]) in TWO_LABEL_SUFFIXES else 2
    if len(labels) < take:
        return None
    return ".".join(labels[-take:]), labels[-1]


def _depth_ok(value: object, limit: int = 12) -> bool:
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict | list):
            if depth > limit:
                return False
            children = node.values() if isinstance(node, dict) else node
            stack.extend((c, depth + 1) for c in children if isinstance(c, dict | list))
    return True


def _services(doc: Mapping[str, Any]) -> list[tuple[list[str], list[str]]]:
    out: list[tuple[list[str], list[str]]] = []
    raw = doc.get("services", [])
    for entry in raw if isinstance(raw, list) else []:
        if isinstance(entry, list) and len(entry) == 2 and all(isinstance(x, list) for x in entry):
            out.append(
                (
                    [k for k in entry[0] if isinstance(k, str)],
                    [u for u in entry[1] if isinstance(u, str)],
                )
            )
    return out


def _base(urls: list[str]) -> str | None:
    for url in urls:
        if public_https_host(url):
            return url if url.endswith("/") else url + "/"
    return None


class Bootstrap:
    def __init__(self, docs: dict[str, dict[str, Any]]) -> None:
        self.docs = docs

    def for_ip(self, ip: str) -> str | None:
        addr = ipaddress.ip_address(ip)
        best: tuple[int, str] | None = None
        for prefixes, urls in _services(self.docs.get("ipv4" if addr.version == 4 else "ipv6", {})):
            base = _base(urls)
            for prefix in prefixes:
                try:
                    net = ipaddress.ip_network(prefix, strict=False)
                except ValueError:
                    continue
                if base and net.version == addr.version and addr in net:
                    if best is None or net.prefixlen > best[0]:
                        best = (net.prefixlen, base)
        return best[1] if best else None

    def for_tld(self, tld: str) -> str | None:
        for labels, urls in _services(self.docs.get("dns", {})):
            if tld.lower() in (label.lower() for label in labels):
                return _base(urls)
        return None

    def hosts(self) -> frozenset[str]:
        found = {IANA_HOST}
        for doc in self.docs.values():
            for _, urls in _services(doc):
                found.update(h for u in urls if (h := public_https_host(u)))
        return frozenset(found)


class RdapDirectory:
    """Finds the abuse mailbox for an address or a domain name."""

    def __init__(
        self,
        *,
        http: httpx.AsyncClient | None = None,
        budget: int = 200,
        host_spacing_s: float = HOST_SPACING_S,
    ) -> None:
        self.http = http or httpx.AsyncClient(
            timeout=TIMEOUT,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/rdap+json, application/json;q=0.5",
            },
            follow_redirects=False,
        )
        self._budget = budget
        self._spacing = host_spacing_s
        self._last: dict[str, float] = {}
        self._lock = asyncio.Lock()
        self._boot: Bootstrap | None = None
        self._boot_at = 0.0
        self._cache: dict[tuple[str, str], str | None] = {}

    async def aclose(self) -> None:
        await self.http.aclose()

    async def _get(self, url: str, allowed: frozenset[str]) -> dict[str, Any] | None:
        for _hop in range(MAX_REDIRECTS + 1):
            host = public_https_host(url)
            if host is None or host not in allowed:
                raise RdapError("host_not_allowed")
            if self._budget <= 0:
                raise RdapError("budget")
            self._budget -= 1
            async with self._lock:
                delay = self._last.get(host, 0.0) + self._spacing - time.monotonic()
                if delay > 0:
                    await asyncio.sleep(delay)
                self._last[host] = time.monotonic()
            try:
                async with self.http.stream("GET", url) as resp:
                    if resp.status_code in (301, 302, 303, 307, 308):
                        url = urljoin(url, resp.headers.get("location", ""))
                        continue
                    if resp.status_code == 404:
                        return None
                    if resp.status_code != 200:
                        raise RdapError(f"http_{resp.status_code}")
                    body = bytearray()
                    async for chunk in resp.aiter_bytes():
                        body += chunk
                        if len(body) > MAX_BODY:
                            raise RdapError("too_large")
            except httpx.TimeoutException:
                raise RdapError("timeout") from None
            except httpx.HTTPError:
                raise RdapError("network") from None
            try:
                doc = json.loads(bytes(body))
            except ValueError:
                raise RdapError("bad_json") from None
            if not isinstance(doc, dict) or not _depth_ok(doc):
                raise RdapError("bad_json")
            return doc
        raise RdapError("too_many_redirects")

    async def bootstrap(self) -> Bootstrap:
        if self._boot is not None and time.monotonic() - self._boot_at < BOOTSTRAP_TTL_S:
            return self._boot
        docs: dict[str, dict[str, Any]] = {}
        for registry in ("ipv4", "ipv6", "dns"):
            doc = await self._get(IANA_URL.format(registry), frozenset({IANA_HOST}))
            if doc is not None and isinstance(doc.get("services"), list) and doc["services"]:
                docs[registry] = doc
        if not docs:
            raise RdapError("no_bootstrap")
        self._boot, self._boot_at = Bootstrap(docs), time.monotonic()
        return self._boot

    async def abuse_for_ip(self, ip: str) -> str | None:
        boot = await self.bootstrap()
        base = boot.for_ip(ip)
        if base is None:
            return None
        doc = await self._get(f"{base}ip/{ip}", boot.hosts())
        mail = abuse_mailboxes(doc)[:1] if doc else []
        return mail[0] if mail else None

    async def abuse_for_domain(self, name: str) -> str | None:
        """The registrar's abuse mailbox for the registrable domain of ``name``."""
        reg = registrable_domain(name)
        if reg is None:
            return None
        boot = await self.bootstrap()
        base = boot.for_tld(reg[1])
        if base is None:
            return None
        doc = await self._get(f"{base}domain/{reg[0]}", boot.hosts())
        mail = abuse_mailboxes(doc)[:1] if doc else []
        return mail[0] if mail else None

    async def resolve(self, kind: str, host: str) -> str | None:
        """Mailbox for a host that is an address or a name. Failures answer None."""
        key = (kind, host)
        if key in self._cache:
            return self._cache[key]
        try:
            try:
                ipaddress.ip_address(host)
                mail = await self.abuse_for_ip(host)
            except ValueError:
                mail = await self.abuse_for_domain(host)
        except RdapError as exc:
            log.warning("rdap lookup failed: %s", exc)
            return None
        self._cache[key] = mail
        return mail


Resolver = Callable[[str, str], Awaitable[str | None]]

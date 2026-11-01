"""RDAP: parsing of answers and the client.

Parsing is pure. The client makes every request through ``ingest.egress`` (the VPN proxy and the
gate), checks the gate before it spends any quota, follows at most two redirects by hand (each
to a host the bootstrap names, over https), caps the body and spaces requests per host.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from itertools import islice
from typing import Any
from urllib.parse import urljoin

import httpx

from ingest.egress import EgressClosed, EgressGate, get_gate, make_client
from ingest.jsondepth import exceeds_depth

from .bootstrap import public_https_host

log = logging.getLogger(__name__)

# A generic browser-like agent: the project name never leaves the machine.
USER_AGENT = "Mozilla/5.0 (compatible; rdap-client)"
ACCEPT = "application/rdap+json, application/json;q=0.5"
TIMEOUT = httpx.Timeout(15.0, connect=10.0)
MAX_BODY = 512 * 1024
MAX_REDIRECTS = 2
MAX_DEPTH = 3
MAX_MAILBOXES = 5
HOST_SPACING_S = 2.0

_PRIVATE_TLDS = frozenset(
    (
        "local localhost internal lan home corp intranet localdomain private arpa invalid "
        "test onion"
    ).split()
)
_LOCAL = re.compile(r"^[a-z0-9._%+\-]{1,64}$")
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$")
_EMAIL_IN_TEXT = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")


class RdapError(Exception):
    """A lookup failed in a way worth retrying later. The message is a short constant code."""


class QuotaExhausted(Exception):
    """The hourly or daily RDAP quota is spent."""


def valid_mailbox(raw: object) -> str | None:
    """A lower-case ASCII mailbox on a dotted public domain, or None."""
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
    if labels[-1].isdigit():
        return None
    return mail


def _vcard_emails(entity: Mapping[str, Any]) -> list[str]:
    card = entity.get("vcardArray")
    items = card[1] if isinstance(card, list) and len(card) == 2 else []
    out: list[str] = []
    for item in items if isinstance(items, list) else []:
        if isinstance(item, list) and len(item) >= 4 and item[0] == "email":
            if (mail := valid_mailbox(item[3])) is not None:
                out.append(mail)
    return out


def _entities(doc: Mapping[str, Any], depth: int = 0) -> list[Mapping[str, Any]]:
    out: list[Mapping[str, Any]] = []
    raw = doc.get("entities")
    for ent in raw[:50] if isinstance(raw, list) else []:
        if isinstance(ent, dict):
            out.append(ent)
            if depth + 1 < MAX_DEPTH:
                out.extend(_entities(ent, depth + 1))
    return out


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))[:MAX_MAILBOXES]


def entity_mailboxes(doc: Mapping[str, Any]) -> list[str]:
    """Mailboxes of the entities whose roles include ``abuse`` (nested up to three deep)."""
    out: list[str] = []
    for ent in _entities(doc):
        roles = ent.get("roles")
        if isinstance(roles, list) and "abuse" in [str(r).lower() for r in roles]:
            out += _vcard_emails(ent)
    return _dedupe(out)


def remark_mailboxes(doc: Mapping[str, Any]) -> list[str]:
    """APNIC style: a remark that mentions abuse and holds a mailbox."""
    out: list[str] = []
    holders: list[Mapping[str, Any]] = [doc, *_entities(doc)]
    for holder in holders:
        remarks = holder.get("remarks")
        for remark in remarks[:20] if isinstance(remarks, list) else []:
            if not isinstance(remark, dict):
                continue
            lines = remark.get("description")
            joined = " ".join(str(x) for x in lines[:20]) if isinstance(lines, list) else ""
            title = str(remark.get("title", ""))
            if "abuse" in (joined + " " + title).lower():
                out += [m for raw in _EMAIL_IN_TEXT.findall(joined) if (m := valid_mailbox(raw))]
    return _dedupe(out)


def ripestat_mailboxes(doc: Mapping[str, Any]) -> list[str]:
    data = doc.get("data")
    raw = data.get("abuse_contacts") if isinstance(data, dict) else None
    return _dedupe(
        [m for x in raw[:10] if (m := valid_mailbox(x))] if isinstance(raw, list) else []
    )


@dataclass(frozen=True)
class NetworkInfo:
    cidr: str
    handle: str | None
    name: str | None
    country: str | None


def _clip(value: object, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = "".join(c for c in value if c.isprintable()).strip()[:limit]
    return cleaned or None


def network_info(doc: Mapping[str, Any], ip: str) -> NetworkInfo:
    """The block of the answer that contains ``ip`` (a host route when the answer has none)."""
    addr = ipaddress.ip_address(ip)
    fallback = ipaddress.ip_network(addr)
    chosen: ipaddress.IPv4Network | ipaddress.IPv6Network = fallback
    candidates: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    try:
        for item in doc.get("cidr0_cidrs", [])[:20]:
            prefix = item.get("v4prefix") or item.get("v6prefix")
            candidates.append(ipaddress.ip_network(f"{prefix}/{int(item['length'])}", strict=False))
        if not candidates and doc.get("startAddress") and doc.get("endAddress"):
            first = ipaddress.ip_address(str(doc["startAddress"]))
            last = ipaddress.ip_address(str(doc["endAddress"]))
            if isinstance(first, ipaddress.IPv4Address) and isinstance(last, ipaddress.IPv4Address):
                candidates.extend(islice(ipaddress.summarize_address_range(first, last), 64))
            elif isinstance(first, ipaddress.IPv6Address) and isinstance(
                last, ipaddress.IPv6Address
            ):
                candidates.extend(islice(ipaddress.summarize_address_range(first, last), 64))
    except (ValueError, TypeError, KeyError, AttributeError):
        candidates = []
    min_len = 8 if addr.version == 4 else 16  # a "whole internet" answer is not a network
    for net in candidates:
        if net.version == addr.version and addr in net and net.prefixlen >= min_len:
            chosen = net
            break
    country = _clip(doc.get("country"), 2)
    return NetworkInfo(
        cidr=str(chosen),
        handle=_clip(doc.get("handle"), 100),
        name=_clip(doc.get("name"), 200),
        country=country.upper() if country and len(country) == 2 else None,
    )


def entity_name(doc: Mapping[str, Any]) -> str | None:
    """Display name of the abuse entity (vCard ``fn``), for the recipient row."""
    for ent in _entities(doc):
        roles = ent.get("roles")
        if isinstance(roles, list) and "abuse" in [str(r).lower() for r in roles]:
            card = ent.get("vcardArray")
            items = card[1] if isinstance(card, list) and len(card) == 2 else []
            for item in items if isinstance(items, list) else []:
                if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                    return _clip(item[3], 200)
    return None


def parse_json(body: bytes) -> dict[str, Any]:
    if exceeds_depth(body):
        raise RdapError("too_deep")
    try:
        doc = json.loads(body)
    except ValueError:
        raise RdapError("bad_json") from None
    if not isinstance(doc, dict):
        raise RdapError("bad_json")
    return doc


Reserve = Callable[[], Awaitable[bool]]


class RdapClient:
    """``get_json`` for RDAP, RIPEstat and the IANA bootstrap files. Nothing else."""

    def __init__(
        self,
        reserve: Reserve,
        allowed_hosts: Callable[[], frozenset[str]],
        *,
        gate: EgressGate | None = None,
        client: httpx.AsyncClient | None = None,
        host_spacing_s: float = HOST_SPACING_S,
    ) -> None:
        self._gate = gate or get_gate()
        self._reserve = reserve
        self._allowed = allowed_hosts
        self._spacing = host_spacing_s
        self._last: dict[str, float] = {}
        self._lock = asyncio.Lock()
        self.client = client or make_client(
            TIMEOUT, gate=self._gate, headers={"User-Agent": USER_AGENT, "Accept": ACCEPT}
        )

    async def aclose(self) -> None:
        await self.client.aclose()

    async def _wait(self, host: str) -> None:
        async with self._lock:
            delay = self._last.get(host, 0.0) + self._spacing - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            self._last[host] = time.monotonic()

    async def get_json(self, url: str) -> dict[str, Any] | None:
        """The parsed answer, or None for 404 (no such record).

        Raises ``EgressClosed`` (nothing sent, no quota spent), ``QuotaExhausted``, ``RdapError``.
        """
        for _hop in range(MAX_REDIRECTS + 1):
            host = public_https_host(url)
            if host is None or host not in self._allowed():
                raise RdapError("host_not_allowed")
            self._gate.require_open()  # before any quota is spent
            if not await self._reserve():
                raise QuotaExhausted
            await self._wait(host)
            try:
                async with self.client.stream("GET", url) as resp:
                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("location", "")
                        url = urljoin(url, location)
                        continue
                    if resp.status_code == 404:
                        return None
                    if resp.status_code == 429:
                        raise RdapError("rate_limited")
                    if resp.status_code != 200:
                        raise RdapError(f"http_{resp.status_code}")
                    body = bytearray()
                    async for chunk in resp.aiter_bytes():
                        body += chunk
                        if len(body) > MAX_BODY:
                            raise RdapError("too_large")
            except EgressClosed:
                raise
            except httpx.TimeoutException:
                raise RdapError("timeout") from None
            except httpx.HTTPError:
                raise RdapError("network") from None
            return parse_json(bytes(body))
        raise RdapError("too_many_redirects")

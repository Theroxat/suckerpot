"""Probable command-and-control addresses of known malware, read from threat-intel providers.

For a file hash that VirusTotal or abuse.ch already recognise, the providers know which network
addresses public sandboxes saw that malware contact. This module holds the pure parts (parsing,
validation, confidence, caps) and the SQL; the requests themselves are made by ``IntelWorker``
under the same rules as every other lookup: fixed hosts, a body cap, persisted daily quotas.

What is read is a string. Nothing here, or anywhere after it, fetches, resolves or connects to an
address: they are shown to the owner as defanged text and offered to the blocklist scoring.

Confidence:

* ``high``: ThreatFox lists the address as ``botnet_cc`` for that hash.
* ``medium``: VirusTotal's sandboxes saw the malware contact it, and it is a public address that
  is not on the never-block list (resolvers, big SaaS and CDN names) nor in the owner's ignore
  list.
* anything else is dropped, never stored.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db.blocklist_values import normalize_value

from ingest.enrichment.textutil import clean, parse_when
from ingest.indicators import IndicatorSettings, normalize_host

Source = Literal["virustotal", "threatfox"]
CONTACT_SOURCES: tuple[Source, ...] = ("virustotal", "threatfox")

PER_SOURCE = 20  # rows kept per hash and source: at most 40 per hash
VT_PAGE = 20  # ``limit`` sent to each VirusTotal relationship
THREATFOX_SCAN = 100  # answer entries examined
CACHE_HOURS = 24
CONTACTS_QUOTA_SHARE = 0.7  # of each provider's daily quota; the rest stays for hash lookups
PER_CYCLE_CONTACTS = 2

THREATFOX_LINK = "https://threatfox.abuse.ch/ioc/{id}/"
VIRUSTOTAL_LINK = "https://www.virustotal.com/gui/file/{h}/relations"


@dataclass(frozen=True, slots=True)
class Contact:
    address: str
    kind: str  # ip | domain
    port: int | None
    source: Source
    confidence: str  # high | medium
    family: str | None = None
    provider_score: int | None = None
    reference: str | None = None
    first_seen: datetime | None = None  # the provider's date when it gives one


@dataclass(frozen=True, slots=True)
class ContactCandidate:
    id: int
    value: str
    missing: tuple[Source, ...]


def accept_address(raw: Any, settings: IndicatorSettings) -> tuple[str, str] | None:
    """``(kind, canonical value)`` for an address worth listing, else None.

    Refuses private, loopback, reserved and (unless the owner keeps them) documentation ranges,
    the owner's ignore list, resolvers and big SaaS or CDN names. Never resolves anything.
    """
    if not isinstance(raw, str) or not raw or len(raw) > 253:
        return None
    host = normalize_host(raw, settings)
    if host is None:
        return None
    kind, value = host
    value = normalize_value(kind, value) or ""
    return (kind, value) if value else None


def _port(value: Any) -> int | None:
    if isinstance(value, str) and value.isdigit() and len(value) <= 5:
        number = int(value)
        return number if 1 <= number <= 65535 else None
    return None


def split_host_port(raw: str) -> tuple[str, int | None]:
    """``203.0.113.5:443`` -> host and port; a bare IPv6 address has no port."""
    text_ = raw.strip()
    if text_.startswith("["):
        host, _, rest = text_[1:].partition("]")
        return host, _port(rest[1:]) if rest.startswith(":") else None
    try:
        ipaddress.ip_address(text_)
    except ValueError:
        pass
    else:
        return text_, None
    if text_.count(":") == 1:
        host, _, port = text_.partition(":")
        return host, _port(port)
    return text_, None


def virustotal_contacts(
    ips: Any, domains: Any, settings: IndicatorSettings, reference: str | None
) -> list[Contact]:
    """Medium-confidence contacts from the two relationship answers (``data[].id``)."""
    out: list[Contact] = []
    seen: set[str] = set()
    for payload, cap in ((ips, PER_SOURCE // 2), (domains, PER_SOURCE // 2)):
        taken = 0
        data = payload.get("data") if isinstance(payload, dict) else None
        for item in data[:VT_PAGE] if isinstance(data, list) else ():
            ident = item.get("id") if isinstance(item, dict) else None
            if taken >= cap or not isinstance(ident, str):
                continue
            host, port = split_host_port(ident)
            accepted = accept_address(host, settings)
            if accepted is None or accepted[1] in seen:
                continue
            seen.add(accepted[1])
            taken += 1
            out.append(Contact(accepted[1], accepted[0], port, "virustotal", "medium", None,
                               None, reference))  # fmt: skip
    return out


def threatfox_contacts(
    payload: Any,
    settings: IndicatorSettings,
) -> list[Contact]:
    """High-confidence contacts: entries of type ``botnet_cc`` (IP:port, domain or URL IOCs)."""
    entries = payload.get("data") if isinstance(payload, dict) else None
    out: list[Contact] = []
    seen: set[str] = set()
    for entry in entries[:THREATFOX_SCAN] if isinstance(entries, list) else ():
        if len(out) >= PER_SOURCE:
            break
        if not isinstance(entry, dict) or entry.get("threat_type") != "botnet_cc":
            continue
        ioc, ioc_type = entry.get("ioc"), entry.get("ioc_type")
        if not isinstance(ioc, str) or len(ioc) > 512:
            continue
        if ioc_type == "ip:port" or ioc_type == "domain":
            host, port = split_host_port(ioc)
        elif ioc_type == "url":
            authority = ioc.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0]
            host, port = split_host_port(authority.rsplit("@", 1)[-1])
        else:
            continue
        accepted = accept_address(host, settings)
        if accepted is None or accepted[1] in seen:
            continue
        seen.add(accepted[1])
        ident = str(entry.get("id", ""))
        score = entry.get("confidence_level")
        out.append(
            Contact(
                accepted[1],
                accepted[0],
                port,
                "threatfox",
                "high",
                clean(entry.get("malware_printable"), 64) or clean(entry.get("malware"), 64),
                score if isinstance(score, int) and 0 <= score <= 100 else None,
                THREATFOX_LINK.format(id=ident) if ident.isdigit() and len(ident) <= 12 else None,
                parse_when(entry.get("first_seen_utc") or entry.get("first_seen")),
            )
        )
    return out


async def candidates(
    factory: async_sessionmaker[AsyncSession],
    sources: tuple[Source, ...],
    limit: int = PER_CYCLE_CONTACTS,
) -> list[ContactCandidate]:
    """Known hashes without a fresh contact lookup at each wanted source, best evidence first.

    A hash is "known" when VirusTotal, URLhaus or ThreatFox already recognise it (an
    ``indicator_intel`` row with ``known``). Demo hashes are never looked up.
    """
    if not sources:
        return []
    stmt = text(
        """
        SELECT i.id, i.value,
               COALESCE(array_agg(c.source) FILTER (
                   WHERE c.source = ANY(:srcs)
                     AND c.checked_at > now() - make_interval(hours => :hours)), '{}') AS fresh
        FROM indicators i
        LEFT JOIN indicator_contact_checks c ON c.indicator_id = i.id
        WHERE i.type = 'hash' AND NOT i.demo AND i.last_seen > now() - interval '7 days'
          AND EXISTS (SELECT 1 FROM indicator_intel n
                      WHERE n.indicator_id = i.id AND n.known
                        AND NOT ('not-checked' = ANY (n.tags)))
        GROUP BY i.id
        HAVING count(*) FILTER (
                   WHERE c.source = ANY(:srcs)
                     AND c.checked_at > now() - make_interval(hours => :hours)) < :n
        ORDER BY (SELECT count(DISTINCT s.src_ip) FROM indicator_sessions s
                  WHERE s.indicator_id = i.id) DESC, i.sightings DESC, i.id
        LIMIT :k
        """
    )
    async with factory() as session:
        rows = (
            await session.execute(
                stmt,
                {
                    "srcs": list(sources),
                    "hours": CACHE_HOURS,
                    "n": len(sources),
                    "k": limit,
                },
            )
        ).all()
    out: list[ContactCandidate] = []
    for r in rows:
        wanted = tuple(s for s in sources if s not in (r.fresh or []))
        if wanted:
            out.append(ContactCandidate(r.id, r.value, wanted))
    return out


async def store(
    factory: async_sessionmaker[AsyncSession],
    indicator_id: int,
    source: Source,
    contacts: list[Contact],
) -> None:
    """Replace one hash's contacts from one source (at most ``PER_SOURCE`` rows) and cache it."""
    async with factory() as session, session.begin():
        for c in contacts[:PER_SOURCE]:
            await session.execute(
                text(
                    """
                    INSERT INTO indicator_contacts (hash_indicator_id, address, kind, port, source,
                        confidence, family, provider_score, reference, first_seen, checked_at)
                    VALUES (:i, :a, :k, :p, :s, :c, :f, :sc, :r, COALESCE(:fs, now()), now())
                    ON CONFLICT (hash_indicator_id, address, source) DO UPDATE SET
                        kind = :k, port = :p, confidence = :c, family = :f, provider_score = :sc,
                        reference = :r, checked_at = now()
                    """
                ),
                {
                    "i": indicator_id,
                    "a": c.address,
                    "k": c.kind,
                    "p": c.port,
                    "s": c.source,
                    "c": c.confidence,
                    "f": c.family,
                    "sc": c.provider_score,
                    "r": c.reference,
                    "fs": c.first_seen,
                },
            )
        # Addresses the provider no longer lists (checked_at is the transaction start).
        await session.execute(
            text(
                "DELETE FROM indicator_contacts WHERE hash_indicator_id = :i AND source = :s "
                "AND checked_at < now()"
            ),
            {"i": indicator_id, "s": source},
        )
        await session.execute(
            text(
                """
                INSERT INTO indicator_contact_checks (indicator_id, source, checked_at)
                VALUES (:i, :s, now())
                ON CONFLICT (indicator_id, source) DO UPDATE SET checked_at = now()
                """
            ),
            {"i": indicator_id, "s": source},
        )

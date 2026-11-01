"""What may be submitted to abuse.ch (design M27 section 7.3). Database reads only.

URLhaus: a URL that served a malware sample (a binary or a script, not a page) to the collector in
the last 48 hours, on a public host that is not in the never-list. ThreatFox: a command-and-control
``ip:port`` read with high confidence from a sample whose family has a Malpedia name. Domains are
not submitted. Demo indicators never are.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Final
from urllib.parse import urlsplit

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db.blocklist_values import is_never_host, is_shared_host

from ingest.abusech.body import (
    THREATFOX_THREAT,
    URLHAUS_THREAT,
    tags_for,
)

Factory = async_sessionmaker[AsyncSession]
MAX_URL: Final = 1024
FRESH_HOURS: Final = 48
C2_FRESH_DAYS: Final = 7
PER_CYCLE: Final = 50
SUBMITTABLE_KINDS: Final = ("elf", "pe", "macho", "script")
MAX_SESSION_IDS: Final = 5000


@dataclass(frozen=True, slots=True)
class Candidate:
    platform: str  # urlhaus | threatfox
    ioc_type: str  # url | ip:port
    value: str
    threat: str
    malware: str | None = None
    tags: tuple[str, ...] = ()
    sample_sha256: str | None = None
    fetch_target_id: int | None = None
    # Set when the value must never be submitted: the row is recorded with this status.
    refusal: str | None = field(default=None)


def url_refusal(url: str) -> str | None:
    """Why a URL is not submittable: ``None`` (it is), ``never_list`` (recorded as skipped) or a
    plain reason (silently not a candidate)."""
    if len(url) > MAX_URL:
        return "length"
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return "scheme"
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return "host"
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        if "." not in host or not host.isascii():
            return "host"
        return "never_list" if is_never_host(host) or is_shared_host(host) else None
    if not addr.is_global or addr.is_multicast:
        return "private"
    return "never_list" if is_never_host(host) else None


URLHAUS_SQL = f"""
SELECT f.id AS fetch_id, f.url, s.sha256, s.kind, s.arch, s.endian, s.family
FROM fetch_targets f
JOIN sample_sources ss ON ss.target_id = f.id
JOIN samples s ON s.sha256 = ss.sha256
LEFT JOIN indicators i ON i.id = f.indicator_id
WHERE f.status = 'fetched' AND ss.last_fetched > now() - interval '{FRESH_HOURS} hours'
  AND s.kind = ANY(:kinds) AND f.scheme IN ('http', 'https')
  AND char_length(f.url) <= {MAX_URL} AND COALESCE(i.demo, false) = false
  AND NOT EXISTS (SELECT 1 FROM abusech_submissions a
                  WHERE a.platform = 'urlhaus' AND a.value = f.url)
ORDER BY ss.last_fetched DESC LIMIT :n
"""  # noqa: S608 - module constants only

THREATFOX_SQL = f"""
SELECT DISTINCT ON (l.value, l.port) l.value AS ip, l.port, s.sha256, s.kind, s.arch,
       s.endian, s.family
FROM sample_links l
JOIN samples s ON s.sha256 = l.sha256
LEFT JOIN indicators i ON i.id = l.indicator_id
WHERE l.kind = 'c2_ip' AND l.port IS NOT NULL AND l.confidence = 'high'
  AND s.family IS NOT NULL AND s.last_seen > now() - interval '{C2_FRESH_DAYS} days'
  AND COALESCE(i.demo, false) = false
  AND NOT EXISTS (SELECT 1 FROM abusech_submissions a
                  WHERE a.platform = 'threatfox' AND a.value = l.value || ':' || l.port)
ORDER BY l.value, l.port, s.last_seen DESC
LIMIT :n
"""  # noqa: S608 - module constants only


async def urlhaus_candidates(factory: Factory, limit: int = PER_CYCLE) -> list[Candidate]:
    async with factory() as session:
        rows = (
            await session.execute(text(URLHAUS_SQL), {"kinds": list(SUBMITTABLE_KINDS), "n": limit})
        ).all()
    out: list[Candidate] = []
    for r in rows:
        refusal = url_refusal(r.url)
        if refusal not in (None, "never_list"):
            continue
        out.append(
            Candidate(
                "urlhaus",
                "url",
                r.url,
                URLHAUS_THREAT,
                None,
                tuple(tags_for(r.kind, r.arch, r.endian, r.family)),
                r.sha256,
                r.fetch_id,
                refusal,
            )
        )
    return out


async def threatfox_candidates(
    factory: Factory, malpedia: dict[str, str], limit: int = PER_CYCLE
) -> list[Candidate]:
    if not malpedia:
        return []
    async with factory() as session:
        rows = (await session.execute(text(THREATFOX_SQL), {"n": limit})).all()
    out: list[Candidate] = []
    for r in rows:
        name = malpedia.get((r.family or "").lower())
        if name is None:
            continue  # ThreatFox requires a Malpedia family
        try:
            addr = ipaddress.ip_address(r.ip)
        except ValueError:
            continue
        if not addr.is_global or addr.is_multicast or not 1 <= int(r.port) <= 65535:
            continue
        refusal = "never_list" if is_never_host(str(addr)) else None
        out.append(
            Candidate(
                "threatfox",
                "ip:port",
                f"{addr}:{int(r.port)}",
                THREATFOX_THREAT,
                name,
                tuple(tags_for(r.kind, r.arch, r.endian, r.family)),
                r.sha256,
                None,
                refusal,
            )
        )
    return out


async def session_ids(session: AsyncSession, fetch_target_id: int | None) -> frozenset[str]:
    """Internal session ids that saw the URL: the identity guard must not find them in a body."""
    if fetch_target_id is None:
        return frozenset()
    rows = await session.execute(
        text(
            "SELECT s.session_id FROM indicator_sessions s "
            "JOIN fetch_targets f ON f.indicator_id = s.indicator_id WHERE f.id = :f LIMIT :n"
        ),
        {"f": fetch_target_id, "n": MAX_SESSION_IDS},
    )
    return frozenset(rows.scalars().all())

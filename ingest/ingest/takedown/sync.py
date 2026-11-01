"""Targets come from sent reports and submitted indicators (design M27 section 3). Database only.

Nothing here talks to the network: it reads reports, their subjects and fetched URLs and writes
``takedown_targets`` rows. A payload URL becomes HTTP-eligible only when the collector already
fetched it and kept a sample (``fetch_targets.status = 'fetched'`` with a hash); that is the one
condition under which the collector may later re-check it.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ingest.takedown.config import TakedownSettings
from ingest.takedown.schedule import first_listing_at

log = logging.getLogger(__name__)

MAX_REPORTS = 200
MAX_SUBMISSIONS = 100
MAX_CHILDREN_PER_HOST = 20
AsnLookup = Callable[[str], tuple[int | None, str | None]]

ROLE_OF_REPORT = {"attack_source": "attack_source", "payload_host": "payload_host", "c2": "c2"}

UPSERT = """
INSERT INTO takedown_targets
    (kind, role, value, target_key, parent_id, fetch_target_id, network_id, asn, country,
     provider_key, provider_name, reported_at, channels, demo, track_until, listing_next_at,
     http_eligible, baseline_sha256, http_next_at)
VALUES
    (:kind, :role, :value, :key, :parent, :fetch, :net, :asn, :country, :pkey, :pname, :rep,
     CAST(:channels AS text[]), :demo, :until, :listing, :elig, :baseline,
     CASE WHEN :elig THEN CAST(:rep AS timestamptz) END)
ON CONFLICT (kind, role, value) DO UPDATE SET
    reported_at = LEAST(takedown_targets.reported_at, EXCLUDED.reported_at),
    track_until = LEAST(takedown_targets.track_until, EXCLUDED.track_until),
    channels = ARRAY(SELECT DISTINCT unnest(takedown_targets.channels || EXCLUDED.channels)
                     ORDER BY 1),
    network_id = COALESCE(takedown_targets.network_id, EXCLUDED.network_id),
    asn = COALESCE(takedown_targets.asn, EXCLUDED.asn),
    country = COALESCE(takedown_targets.country, EXCLUDED.country),
    provider_name = COALESCE(takedown_targets.provider_name, EXCLUDED.provider_name),
    provider_key = CASE WHEN takedown_targets.provider_key LIKE 'recipient:%'
                         OR takedown_targets.provider_key = 'unknown'
                        THEN EXCLUDED.provider_key ELSE takedown_targets.provider_key END,
    fetch_target_id = COALESCE(takedown_targets.fetch_target_id, EXCLUDED.fetch_target_id),
    parent_id = COALESCE(takedown_targets.parent_id, EXCLUDED.parent_id)
RETURNING id
"""

PENDING_REPORTS = """
SELECT r.id AS report_id, r.kind AS report_kind, r.demo, r.sent_at, r.recipient_id,
       s.subject_type, s.value, s.network_id,
       n.asn, n.name AS net_name, n.country, rec.name AS rec_name
FROM (
    SELECT id, kind, demo, sent_at, recipient_id FROM abuse_reports
    WHERE status IN ('sent', 'closed') AND sent_at IS NOT NULL
      AND sent_at > :since AND (NOT demo OR :demo)
      AND NOT EXISTS (SELECT 1 FROM takedown_target_links l WHERE l.report_id = abuse_reports.id)
      AND EXISTS (SELECT 1 FROM abuse_report_subjects x
                  WHERE x.report_id = abuse_reports.id AND x.subject_type IN ('ip', 'domain'))
    ORDER BY sent_at LIMIT :n
) r
JOIN abuse_report_subjects s ON s.report_id = r.id AND s.subject_type IN ('ip', 'domain')
JOIN abuse_recipients rec ON rec.id = r.recipient_id
LEFT JOIN abuse_networks n ON n.id = s.network_id
ORDER BY r.sent_at, r.id
"""

HOST_CHILDREN = """
SELECT t.id AS parent_id, t.reported_at, t.network_id, t.asn, t.country, t.provider_key,
       t.provider_name, t.channels, t.demo, f.id AS fetch_id, f.url, f.last_sha256,
       (SELECT count(*) FROM takedown_targets c WHERE c.parent_id = t.id) AS have
FROM takedown_targets t
JOIN fetch_targets f ON f.host = t.value
WHERE t.role = 'payload_host' AND t.tracking AND NOT t.demo AND t.track_until > :now
  AND f.status = 'fetched' AND f.last_sha256 IS NOT NULL AND char_length(f.url) <= 1024
  AND NOT EXISTS (SELECT 1 FROM takedown_targets c
                  WHERE c.kind = 'url' AND c.role = 'payload_url' AND c.value = f.url)
ORDER BY t.id, f.last_attempt_at DESC NULLS LAST
"""

PENDING_SUBMISSIONS = """
SELECT s.id, s.platform, s.value, s.fetch_target_id, s.submitted_at,
       f.status AS fetch_status, f.last_sha256
FROM abusech_submissions s LEFT JOIN fetch_targets f ON f.id = s.fetch_target_id
WHERE s.status = 'submitted' AND NOT s.demo AND s.submitted_at IS NOT NULL
  AND s.submitted_at > :since
  AND NOT EXISTS (SELECT 1 FROM takedown_target_links l WHERE l.submission_id = s.id)
ORDER BY s.submitted_at LIMIT :n
"""


def target_key(kind: str, value: str) -> str:
    """sha256(kind || ':' || value): a stable key that does not reveal the value (for M29)."""
    return hashlib.sha256(f"{kind}:{value}".encode()).hexdigest()


def host_kind(host: str) -> str:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return "domain"
    return "ip"


def provider_of(asn: int | None, recipient_id: int | None) -> str:
    if asn is not None:
        return f"as{asn}"
    return f"recipient:{recipient_id}" if recipient_id is not None else "unknown"


@dataclass(frozen=True, slots=True)
class Provider:
    key: str
    name: str | None = None
    asn: int | None = None
    country: str | None = None
    network_id: int | None = None


def _country(value: str | None) -> str | None:
    return value.upper() if value and len(value) == 2 and value.isalpha() else None


class TargetSync:
    def __init__(
        self,
        factory: async_sessionmaker[AsyncSession],
        settings: TakedownSettings,
        asn_lookup: AsnLookup | None = None,
    ) -> None:
        self.factory = factory
        self.s = settings
        self._asn_lookup = asn_lookup

    async def sync(self, now: datetime) -> dict[str, int]:
        since = now - timedelta(days=self.s.track_days)
        made = {
            "reports": await self._from_reports(now, since),
            "children": await self._children(now),
            "submissions": await self._from_submissions(now, since),
        }
        return made

    # ---- helpers ---------------------------------------------------------------------------
    async def _upsert(
        self,
        session: AsyncSession,
        *,
        kind: str,
        role: str,
        value: str,
        provider: Provider,
        reported_at: datetime,
        channels: list[str],
        demo: bool = False,
        parent: int | None = None,
        fetch_id: int | None = None,
        eligible: bool = False,
        baseline: str | None = None,
    ) -> int:
        params: dict[str, Any] = {
            "kind": kind, "role": role, "value": value[:1024], "key": target_key(kind, value),
            "parent": parent, "fetch": fetch_id, "net": provider.network_id,
            "asn": provider.asn, "country": provider.country, "pkey": provider.key[:64],
            "pname": provider.name[:200] if provider.name else None, "rep": reported_at,
            "channels": channels, "demo": demo,
            "until": reported_at + timedelta(days=self.s.track_days),
            "listing": first_listing_at(reported_at), "elig": eligible, "baseline": baseline,
        }  # fmt: skip
        return int((await session.execute(text(UPSERT), params)).scalar_one())

    @staticmethod
    async def _link(
        session: AsyncSession, target: int, *, report: int | None = None, sub: int | None = None
    ) -> None:
        await session.execute(
            text(
                "INSERT INTO takedown_target_links (target_id, report_id, submission_id) "
                "VALUES (:t, :r, :s) ON CONFLICT DO NOTHING"
            ),
            {"t": target, "r": report, "s": sub},
        )

    # ---- sent reports ----------------------------------------------------------------------
    async def _from_reports(self, now: datetime, since: datetime) -> int:
        async with self.factory() as session:
            rows = (
                await session.execute(
                    text(PENDING_REPORTS),
                    {"since": since, "demo": self.s.include_demo, "n": MAX_REPORTS},
                )
            ).all()
        if not rows:
            return 0
        count = 0
        async with self.factory() as session, session.begin():
            for r in rows:
                role = ROLE_OF_REPORT.get(r.report_kind)
                if role is None:
                    continue
                provider = Provider(
                    provider_of(r.asn, r.recipient_id),
                    r.net_name or r.rec_name,
                    r.asn,
                    _country(r.country),
                    r.network_id,
                )
                kind = "ip" if r.subject_type == "ip" else "domain"
                tid = await self._upsert(
                    session,
                    kind=kind,
                    role=role,
                    value=r.value,
                    provider=provider,
                    reported_at=r.sent_at,
                    channels=["mail"],
                    demo=r.demo,
                )
                await self._link(session, tid, report=r.report_id)
                count += 1
        return count

    # ---- URLs a tracked host served ----------------------------------------------------------
    async def _children(self, now: datetime) -> int:
        async with self.factory() as session:
            rows = (await session.execute(text(HOST_CHILDREN), {"now": now})).all()
        count = 0
        taken: dict[int, int] = {}
        async with self.factory() as session, session.begin():
            for r in rows:
                have = r.have + taken.get(r.parent_id, 0)
                if have >= MAX_CHILDREN_PER_HOST:
                    continue
                provider = Provider(r.provider_key, r.provider_name, r.asn, r.country, r.network_id)
                tid = await self._upsert(
                    session,
                    kind="url",
                    role="payload_url",
                    value=r.url,
                    provider=provider,
                    reported_at=r.reported_at,
                    channels=list(r.channels or ["mail"]),
                    parent=r.parent_id,
                    fetch_id=r.fetch_id,
                    eligible=True,
                    baseline=r.last_sha256,
                )
                # The child belongs to the same reports as its host.
                await session.execute(
                    text(
                        "INSERT INTO takedown_target_links (target_id, report_id, submission_id) "
                        "SELECT :c, report_id, submission_id FROM takedown_target_links "
                        "WHERE target_id = :p ON CONFLICT DO NOTHING"
                    ),
                    {"c": tid, "p": r.parent_id},
                )
                taken[r.parent_id] = taken.get(r.parent_id, 0) + 1
                count += 1
        return count

    # ---- abuse.ch submissions ----------------------------------------------------------------
    async def _from_submissions(self, now: datetime, since: datetime) -> int:
        async with self.factory() as session:
            rows = (
                await session.execute(
                    text(PENDING_SUBMISSIONS), {"since": since, "n": MAX_SUBMISSIONS}
                )
            ).all()
        count = 0
        async with self.factory() as session, session.begin():
            for r in rows:
                if r.platform == "threatfox":
                    host = _host_of_ioc(r.value)
                    if host is None:
                        continue
                    tid = await self._upsert(
                        session,
                        kind=host_kind(host),
                        role="c2",
                        value=host,
                        provider=self._provider_for_host(host),
                        reported_at=r.submitted_at,
                        channels=["threatfox"],
                    )
                    await self._link(session, tid, sub=r.id)
                    count += 1
                    continue
                host = (urlsplit(r.value).hostname or "").lower()
                if not host:
                    continue
                provider = self._provider_for_host(host)
                parent = await self._upsert(
                    session,
                    kind=host_kind(host),
                    role="payload_host",
                    value=host,
                    provider=provider,
                    reported_at=r.submitted_at,
                    channels=["urlhaus"],
                )
                eligible = r.fetch_status == "fetched" and r.last_sha256 is not None
                tid = await self._upsert(
                    session,
                    kind="url",
                    role="payload_url",
                    value=r.value,
                    provider=provider,
                    reported_at=r.submitted_at,
                    channels=["urlhaus"],
                    parent=parent,
                    fetch_id=r.fetch_target_id,
                    eligible=eligible,
                    baseline=r.last_sha256 if eligible else None,
                )
                await self._link(session, parent, sub=r.id)
                await self._link(session, tid, sub=r.id)
                count += 1
        return count

    def _provider_for_host(self, host: str) -> Provider:
        if host_kind(host) == "ip" and self._asn_lookup is not None:
            asn, org = self._asn_lookup(host)
            if asn is not None:
                return Provider(f"as{asn}", org, asn)
        return Provider("unknown")


def _host_of_ioc(value: str) -> str | None:
    """The address of a ThreatFox ``ip:port`` value."""
    host = value.rsplit(":", 1)[0].strip("[]") if ":" in value else value
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None

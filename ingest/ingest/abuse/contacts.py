"""Abuse contact lookup with caches, quotas and back-off (design M22, section 5.2).

A subject is looked up only after it passed selection. The order is: lookup row (negative cache
and back-off), cached network that contains the address, then RDAP through ``RdapClient``.
``EgressClosed`` is never caught here: it spends no quota and writes nothing, the caller waits.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ingest.enrichment.reputation import reserve_quota

from .bootstrap import Bootstrap, registrable_domain
from .config import AbuseSettings
from .rdap import (
    RdapClient,
    RdapError,
    entity_mailboxes,
    entity_name,
    network_info,
    remark_mailboxes,
    ripestat_mailboxes,
)

log = logging.getLogger(__name__)

POSITIVE_TTL = timedelta(days=30)
NEGATIVE_TTL = timedelta(hours=24)
BACKOFF = (timedelta(minutes=15), timedelta(hours=1), timedelta(hours=6))
RIPESTAT_URL = "https://stat.ripe.net/data/abuse-contact-finder/data.json?resource={ip}"

Status = Literal["found", "no_contact", "error", "pending"]


@dataclass(frozen=True)
class Outcome:
    status: Status
    network_id: int | None = None
    mailboxes: tuple[str, ...] = ()
    name: str | None = None
    asn: int | None = None
    network_name: str | None = None
    country: str | None = None


def quota_providers(now: datetime) -> tuple[str, str]:
    """``enrichment_quota`` keys: one row per day, and one per hour of the day."""
    return "rdap", f"rdap_h{now.hour:02d}"


def make_reserve(factory: async_sessionmaker[AsyncSession], settings: AbuseSettings) -> Any:
    async def reserve() -> bool:
        daily, hourly = quota_providers(datetime.now(UTC))
        if not await reserve_quota(factory, hourly, settings.rdap_hourly_quota):
            return False
        return await reserve_quota(factory, daily, settings.rdap_daily_quota)

    return reserve


class ContactResolver:
    def __init__(
        self,
        factory: async_sessionmaker[AsyncSession],
        client: RdapClient,
        bootstrap: Bootstrap,
    ) -> None:
        self.factory = factory
        self.client = client
        self.bootstrap = bootstrap

    # -- cache ---------------------------------------------------------------------------

    async def _lookup_row(self, session: AsyncSession, subject: str) -> Any:
        return (
            await session.execute(
                text(
                    """
                    SELECT l.status, l.attempts, l.next_check_at, l.network_id,
                           n.mailboxes, n.name AS net_name, n.asn, n.country, n.expires_at
                    FROM abuse_lookups l LEFT JOIN abuse_networks n ON n.id = l.network_id
                    WHERE l.subject = :s
                    """
                ),
                {"s": subject},
            )
        ).first()

    @staticmethod
    def _outcome_of(row: Any, mailboxes: list[str], status: Status) -> Outcome:
        return Outcome(
            status,
            row.network_id,
            tuple(mailboxes),
            asn=row.asn,
            network_name=row.net_name,
            country=row.country,
        )

    async def _save(
        self,
        subject: str,
        kind: str,
        status: Status,
        network_id: int | None,
        attempts: int,
        next_check: datetime | None,
    ) -> None:
        async with self.factory() as session, session.begin():
            await session.execute(
                text(
                    """
                    INSERT INTO abuse_lookups
                        (subject, kind, network_id, status, attempts, checked_at, next_check_at)
                    VALUES (:s, :k, :n, :st, :a, now(), :nc)
                    ON CONFLICT (subject) DO UPDATE SET network_id = :n, status = :st,
                        attempts = :a, checked_at = now(), next_check_at = :nc
                    """
                ),
                {
                    "s": subject,
                    "k": kind,
                    "n": network_id,
                    "st": status,
                    "a": attempts,
                    "nc": next_check,
                },
            )

    async def _store_network(
        self,
        kind: str,
        key: str,
        info: dict[str, Any],
        mailboxes: list[str],
        source: str,
        rir: str | None,
        asn: int | None,
    ) -> int:
        now = datetime.now(UTC)
        expires = now + (POSITIVE_TTL if mailboxes else NEGATIVE_TTL)
        sql = (
            """
            INSERT INTO abuse_networks (kind, cidr, handle, name, country, rir, asn, mailboxes,
                                        source, fetched_at, expires_at)
            VALUES ('ip', CAST(:key AS cidr), :h, :nm, :c, :rir, :asn, :mb, :src, :now, :exp)
            ON CONFLICT (cidr) DO UPDATE SET handle = :h, name = :nm, country = :c, rir = :rir,
                asn = :asn, mailboxes = :mb, source = :src, fetched_at = :now, expires_at = :exp
            RETURNING id
            """
            if kind == "ip"
            else """
            INSERT INTO abuse_networks (kind, domain, handle, name, country, rir, asn, mailboxes,
                                        source, fetched_at, expires_at)
            VALUES ('domain', :key, :h, :nm, :c, :rir, :asn, :mb, :src, :now, :exp)
            ON CONFLICT (domain) DO UPDATE SET handle = :h, name = :nm, country = :c, rir = :rir,
                asn = :asn, mailboxes = :mb, source = :src, fetched_at = :now, expires_at = :exp
            RETURNING id
            """
        )
        params = {
            "key": key,
            "h": info.get("handle"),
            "nm": info.get("name"),
            "c": info.get("country"),
            "rir": rir,
            "asn": asn,
            "mb": mailboxes,
            "src": source,
            "now": now,
            "exp": expires,
        }
        async with self.factory() as session, session.begin():
            net_id = int((await session.execute(text(sql), params)).scalar_one())
            if not mailboxes:
                await self._waiting_recipient(session, net_id, info.get("name") or key)
            return net_id

    @staticmethod
    async def _waiting_recipient(session: AsyncSession, network_id: int, label: str) -> None:
        """A network with no contact gets one recipient without a mailbox. The owner types the
        address there (``override_mailbox``); until then nothing is drafted for it."""
        have = (
            await session.execute(
                text("SELECT recipient_id FROM abuse_networks WHERE id = :i"), {"i": network_id}
            )
        ).scalar_one()
        if have is not None:
            return
        rid = (
            await session.execute(
                text(
                    "INSERT INTO abuse_recipients (mailbox, name, source) "
                    "VALUES (NULL, :n, 'rdap') RETURNING id"
                ),
                {"n": label[:200]},
            )
        ).scalar_one()
        await session.execute(
            text("UPDATE abuse_networks SET recipient_id = :r WHERE id = :i"),
            {"r": rid, "i": network_id},
        )

    # -- public API ----------------------------------------------------------------------

    async def resolve_ip(self, ip: str, asn: int | None, *, cache_only: bool = False) -> Outcome:
        """Contact of the network that holds ``ip``. May raise ``EgressClosed``.

        ``cache_only`` answers from the caches and never reaches the network."""
        subject = str(ipaddress.ip_address(ip))
        now = datetime.now(UTC)
        async with self.factory() as session:
            row = await self._lookup_row(session, subject)
            if row is not None and row.next_check_at and row.next_check_at > now:
                if row.status == "found" and row.network_id is not None:
                    return self._outcome_of(row, list(row.mailboxes or []), "found")
                if row.status == "error":
                    return Outcome("pending")
                if row.status == "no_contact":
                    return self._outcome_of(row, [], "no_contact")
            net = (
                await session.execute(
                    text(
                        """
                        SELECT id AS network_id, mailboxes, name AS net_name, asn, country
                        FROM abuse_networks
                        WHERE kind = 'ip' AND cidr >>= CAST(:ip AS inet) AND expires_at > now()
                        ORDER BY masklen(cidr) DESC LIMIT 1
                        """
                    ),
                    {"ip": subject},
                )
            ).first()
        attempts = int(row.attempts) if row is not None else 0
        if net is None and cache_only:
            return Outcome("pending")
        if net is not None:
            status: Status = "found" if net.mailboxes else "no_contact"
            ttl = POSITIVE_TTL if net.mailboxes else NEGATIVE_TTL
            await self._save(subject, "ip", status, net.network_id, 0, now + ttl)
            return self._outcome_of(net, list(net.mailboxes or []), status)
        try:
            return await self._rdap_ip(subject, asn, attempts)
        except RdapError as exc:
            delay = BACKOFF[min(attempts, len(BACKOFF) - 1)]
            await self._save(subject, "ip", "error", None, min(attempts + 1, 32000), now + delay)
            log.info("rdap lookup failed (%s)", exc)
            return Outcome("pending")

    async def _rdap_ip(self, ip: str, asn: int | None, attempts: int) -> Outcome:
        base = self.bootstrap.for_ip(ip)
        if base is None:
            raise RdapError("no_server")
        doc = await self.client.get_json(f"{base}ip/{ip}")
        rir = _rir(base)
        info: dict[str, Any] = {}
        mailboxes: list[str] = []
        source = "rdap"
        found_name: str | None = None
        net_cidr = ip
        if doc is not None:
            ni = network_info(doc, ip)
            net_cidr = ni.cidr
            info = {"handle": ni.handle, "name": ni.name, "country": ni.country}
            mailboxes = entity_mailboxes(doc)
            found_name = entity_name(doc)
            if not mailboxes:
                mailboxes, source = remark_mailboxes(doc), "rdap_remarks"
        else:
            net_cidr = str(ipaddress.ip_network(ip))
        if not mailboxes and rir == "ripe":
            stat = await self.client.get_json(RIPESTAT_URL.format(ip=ip))
            if stat is not None:
                mailboxes, source = ripestat_mailboxes(stat), "ripestat"
        if not mailboxes and asn is not None:
            abase = self.bootstrap.for_asn(asn)
            if abase is not None:
                adoc = await self.client.get_json(f"{abase}autnum/{asn}")
                if adoc is not None:
                    mailboxes, source = entity_mailboxes(adoc), "rdap_autnum"
                    found_name = found_name or entity_name(adoc)
        net_id = await self._store_network("ip", net_cidr, info, mailboxes, source, rir, asn)
        status: Status = "found" if mailboxes else "no_contact"
        ttl = POSITIVE_TTL if mailboxes else NEGATIVE_TTL
        await self._save(ip, "ip", status, net_id, 0, datetime.now(UTC) + ttl)
        return Outcome(
            status, net_id, tuple(mailboxes), found_name, asn, info.get("name"), info.get("country")
        )

    async def resolve_domain(self, name: str, *, cache_only: bool = False) -> Outcome:
        """Abuse contact of the registrar of ``name``. May raise ``EgressClosed``."""
        reg = registrable_domain(name)
        if reg is None:
            return Outcome("no_contact")
        domain, tld = reg
        now = datetime.now(UTC)
        async with self.factory() as session:
            row = await self._lookup_row(session, domain)
            if row is not None and row.next_check_at and row.next_check_at > now:
                if row.status == "found" and row.network_id is not None:
                    return self._outcome_of(row, list(row.mailboxes or []), "found")
                if row.status == "error":
                    return Outcome("pending")
                return self._outcome_of(row, [], "no_contact")
        if cache_only:
            return Outcome("pending")
        attempts = int(row.attempts) if row is not None else 0
        base = self.bootstrap.for_tld(tld)
        try:
            if base is None:
                raise RdapError("no_server")
            doc = await self.client.get_json(f"{base}domain/{domain}")
        except RdapError as exc:
            delay = BACKOFF[min(attempts, len(BACKOFF) - 1)]
            await self._save(domain, "domain", "error", None, min(attempts + 1, 32000), now + delay)
            log.info("rdap domain lookup failed (%s)", exc)
            return Outcome("pending")
        mailboxes = entity_mailboxes(doc) if doc is not None else []
        found_name = entity_name(doc) if doc is not None else None
        net_id = await self._store_network("domain", domain, {}, mailboxes, "rdap", None, None)
        status: Status = "found" if mailboxes else "no_contact"
        ttl = POSITIVE_TTL if mailboxes else NEGATIVE_TTL
        await self._save(domain, "domain", status, net_id, 0, datetime.now(UTC) + ttl)
        return Outcome(status, net_id, tuple(mailboxes), found_name)


def _rir(base: str) -> str | None:
    for rir in ("arin", "ripe", "apnic", "lacnic", "afrinic"):
        if rir in base:
            return rir
    return None

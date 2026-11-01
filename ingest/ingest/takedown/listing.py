"""Listing checks: what URLhaus, ThreatFox and AbuseIPDB say about a reported target (M27 4.4).

Passive and read-only. Only the existing lookup clients are used (``IntelWorker.urlhaus`` /
``threatfox`` and ``ReputationWorker.check_abuseipdb``); nothing is ever reported to AbuseIPDB and
no packet goes to the target. Every lookup spends one unit of the provider's own daily quota and
one of a share quota (``takedown_intel`` / ``takedown_abuseipdb``), so takedown tracking can never
take the whole budget. A closed egress gate means no lookup, no quota and no row.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime
from typing import Any, Final, Protocol

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ingest.egress import EgressClosed, EgressGate, gate_open, get_gate
from ingest.enrichment.intel import IntelResult
from ingest.enrichment.reputation import AbuseResult, ProviderError, reserve_quota
from ingest.takedown.config import TakedownSettings
from ingest.takedown.schedule import RETRY_AFTER, next_listing_at

log = logging.getLogger(__name__)

PER_CYCLE: Final = 5
PAUSE_S: Final = 3600.0
INTEL_SHARE: Final = "takedown_intel"
ABUSEIPDB_SHARE: Final = "takedown_abuseipdb"
Factory = async_sessionmaker[AsyncSession]


class IntelLike(Protocol):
    def enabled(self, provider: str) -> bool: ...
    def quota(self, provider: str) -> int: ...
    async def urlhaus(self, kind: str, value: str) -> IntelResult: ...
    async def threatfox(self, kind: str, value: str) -> IntelResult: ...


class ReputationLike(Protocol):
    def enabled(self, provider: str) -> bool: ...
    def quota(self, provider: str) -> int: ...
    async def check_abuseipdb(self, ip: str) -> AbuseResult: ...


async def refund_quota(factory: Factory, provider: str) -> None:
    async with factory() as session, session.begin():
        await session.execute(
            text(
                "UPDATE enrichment_quota SET used = GREATEST(used - 1, 0) "
                "WHERE provider = :p AND day = (now() AT TIME ZONE 'UTC')::date"
            ),
            {"p": provider},
        )


def urlhaus_outcome(result: IntelResult, now: datetime) -> tuple[str, dict[str, Any]]:
    """Constant outcome and small detail for a URLhaus answer."""
    if not result.known:
        return "not_listed", {}
    if result.url_status == "online":
        return "online", {}
    detail: dict[str, Any] = {}
    if result.last_online is not None:
        detail["last_online_age_h"] = max(
            0, int((now - result.last_online).total_seconds() // 3600)
        )
    if result.url_status == "offline":
        return "offline", detail
    return "unknown_status", detail


def abuseipdb_outcome(result: AbuseResult, reported_at: datetime) -> tuple[str, dict[str, Any]]:
    detail: dict[str, Any] = {"reports": result.reports}
    if result.last_reported_at is not None and result.last_reported_at > reported_at:
        return "reported_after", detail
    if result.reports == 0:
        return "not_listed", detail
    return "quiet", detail


class ListingChecker:
    def __init__(
        self,
        factory: Factory,
        settings: TakedownSettings,
        intel: IntelLike,
        reputation: ReputationLike,
        gate: EgressGate | None = None,
    ) -> None:
        self.factory = factory
        self.s = settings
        self.intel = intel
        self.reputation = reputation
        self._gate = gate
        self._paused: dict[str, float] = {}
        self._disabled: set[str] = set()
        self._retry: dict[int, float] = {}
        self.checks = 0

    @property
    def gate(self) -> EgressGate:
        return self._gate or get_gate()

    def _available(self, provider: str) -> bool:
        if provider in self._disabled or time.monotonic() < self._paused.get(provider, 0.0):
            return False
        if provider == "abuseipdb":
            return self.reputation.enabled("abuseipdb") and self.s.abuseipdb_daily_quota > 0
        return self.intel.enabled("abusech") and self.s.intel_daily_quota > 0

    def roles(self) -> list[str]:
        roles: list[str] = []
        if self._available("abusech"):
            roles += ["payload_url", "payload_host", "c2"]
        if self._available("abuseipdb"):
            roles.append("attack_source")
        return roles

    async def _reserve(self, provider: str) -> bool:
        """The share first, then the provider's own quota (the share is given back on failure)."""
        if provider == "abuseipdb":
            share, share_limit = ABUSEIPDB_SHARE, self.s.abuseipdb_daily_quota
            own, own_limit = "abuseipdb", self.reputation.quota("abuseipdb")
        else:
            share, share_limit = INTEL_SHARE, self.s.intel_daily_quota
            own, own_limit = "abusech", self.intel.quota("abusech")
        if share_limit <= 0 or own_limit <= 0:
            return False
        if not await reserve_quota(self.factory, share, share_limit):
            return False
        if not await reserve_quota(self.factory, own, own_limit):
            await refund_quota(self.factory, share)
            return False
        return True

    async def _release(self, provider: str) -> None:
        if provider == "abuseipdb":
            await refund_quota(self.factory, ABUSEIPDB_SHARE)
            await refund_quota(self.factory, "abuseipdb")
        else:
            await refund_quota(self.factory, INTEL_SHARE)
            await refund_quota(self.factory, "abusech")

    async def due(self, now: datetime, roles: list[str]) -> list[Any]:
        async with self.factory() as session:
            return list(
                (
                    await session.execute(
                        text(
                            """
                            SELECT id, kind, role, value, reported_at, track_until, listing_step
                            FROM takedown_targets
                            WHERE tracking AND NOT demo AND listing_next_at <= :now
                              AND track_until > :now AND role = ANY(:roles)
                            ORDER BY listing_next_at, id LIMIT :n
                            """
                        ),
                        {"now": now, "roles": roles, "n": PER_CYCLE * 3},
                    )
                ).all()
            )

    async def run(self, now: datetime) -> int:
        """Check the due targets. Returns how many checks were recorded."""
        roles = self.roles()
        if not roles or not gate_open(self._gate):
            return 0
        made = 0
        for t in await self.due(now, roles):
            if made >= PER_CYCLE:
                break
            if time.monotonic() < self._retry.get(t.id, 0.0):
                continue
            provider = "abuseipdb" if t.role == "attack_source" else "abusech"
            if not self._available(provider):
                continue
            if not gate_open(self._gate):
                break
            if not await self._reserve(provider):
                log.info("takedown %s quota exhausted", provider)
                self._paused[provider] = time.monotonic() + 600
                continue
            try:
                outcome, method, detail = await self._lookup(t, now)
            except EgressClosed:
                await self._release(provider)  # nothing was sent: no quota, no row
                break
            except ProviderError as exc:
                self._retry[t.id] = time.monotonic() + RETRY_AFTER.total_seconds()
                if exc.kind == "auth":
                    self._disabled.add(provider)
                    log.error("%s rejected the API key: takedown lookups stop", provider)
                elif exc.kind == "rate_limited":
                    self._paused[provider] = time.monotonic() + PAUSE_S
                else:
                    log.warning("takedown %s lookup failed (%s)", provider, exc.kind)
                continue
            await self._record(t, method, outcome, detail, now)
            made += 1
        self.checks += made
        return made

    async def _lookup(self, t: Any, now: datetime) -> tuple[str, str, dict[str, Any]]:
        if t.role == "attack_source":
            ar = await self.reputation.check_abuseipdb(t.value)
            outcome, detail = abuseipdb_outcome(ar, t.reported_at)
            return outcome, "abuseipdb", detail
        if t.role == "c2":
            tf = await self.intel.threatfox(t.kind, t.value)
            return ("listed" if tf.known else "not_listed"), "threatfox", {}
        uh = await self.intel.urlhaus("url" if t.kind == "url" else t.kind, t.value)
        outcome, detail = urlhaus_outcome(uh, now)
        return outcome, "urlhaus", detail

    async def _record(
        self, t: Any, method: str, outcome: str, detail: dict[str, Any], now: datetime
    ) -> None:
        step, at = next_listing_at(t.listing_step, t.reported_at, now, t.track_until)
        async with self.factory() as session, session.begin():
            await session.execute(
                text(
                    "INSERT INTO takedown_checks (target_id, checked_at, method, outcome, detail) "
                    "VALUES (:t, :now, :m, :o, CAST(:d AS jsonb))"
                ),
                {"t": t.id, "now": now, "m": method, "o": outcome, "d": json.dumps(detail)},
            )
            await session.execute(
                text(
                    "UPDATE takedown_targets SET listing_step = :s, listing_next_at = :at "
                    "WHERE id = :i"
                ),
                {"s": step, "at": at, "i": t.id},
            )

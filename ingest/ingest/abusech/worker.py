"""The abuse.ch submission worker (design M27 section 7). Off by default, twice.

Nothing is computed, looked up or sent unless ``ABUSECH_SUBMIT_ENABLED=true`` (the server switch,
``FeatureSettings.abusech_submit_enabled``) AND the owner's mode in Settings is ``review`` or
``auto``. In ``review`` the owner approves each URL in the dashboard (the API moves a candidate to
``pending``); in ``auto`` this worker schedules each looked-up candidate after the hold time.

Order of one submission, each step stopping the whole thing:

1. the row is ``pending``, not demo, and the owner's mode still allows it;
2. the exact body is built from the allow-list and passes the identity guard (a failure sends
   nothing and is final: ``guard_failed:<codes>``);
3. a key is configured, the egress gate is open and the daily cap (quota ``abusech_submit``) allows;
4. ``submitting`` is committed BEFORE the request. Only ``pending`` rows are ever picked, a
   ``submitting`` row older than 5 minutes becomes ``failed`` / ``unknown_outcome``: at most once;
5. one POST through the VPN proxy; the answer becomes a constant code and a final status.

``EgressClosed`` before the request returns the row to ``pending``. Lookups come first: a value
the service already knows is recorded as ``skipped_known`` and never submitted.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Protocol

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db.secretbox import SecretBox, SecretError
from suckerpot_reporting import GuardContext, SelfTerms, guard

from ingest.abusech import candidates as cand
from ingest.abusech.body import threatfox_body, urlhaus_body
from ingest.abusech.client import (
    ALREADY_KNOWN,
    AUTH_FAILED,
    BLACKLISTED,
    INSERTED,
    INVALID,
    RATE_LIMITED,
    UNKNOWN_OUTCOME,
    AbusechClient,
)
from ingest.egress import EgressClosed, EgressGate, gate_open, get_gate
from ingest.enrichment.intel import IntelResult
from ingest.enrichment.reputation import ProviderError, reserve_quota
from ingest.features import FeatureSettings, FeatureWorker
from ingest.takedown.listing import refund_quota

log = logging.getLogger(__name__)

KEY_AAD: Final = "abusech_submission"
QUOTA: Final = "abusech_submit"
STALE_SUBMITTING: Final = timedelta(minutes=5)
MAX_PER_CYCLE: Final = 5
MAX_LOOKUPS: Final = 5
MAX_SCHEDULE: Final = 50
PAUSE_S: Final = 3600.0
# Guard codes that mean "not yet" rather than "never": nothing is recorded or sent meanwhile.
TRANSIENT_GUARD: Final = frozenset({"no_self_address", "self_terms_unavailable"})
FINAL_STATUS: Final = {
    INSERTED: "submitted",
    ALREADY_KNOWN: "duplicate",
    INVALID: "rejected",
    BLACKLISTED: "rejected",
}
Factory = async_sessionmaker[AsyncSession]


class TermsLike(Protocol):
    async def get(self) -> SelfTerms | None: ...


class IntelLike(Protocol):
    def enabled(self, provider: str) -> bool: ...
    def quota(self, provider: str) -> int: ...
    async def urlhaus(self, kind: str, value: str) -> IntelResult: ...
    async def threatfox(self, kind: str, value: str) -> IntelResult: ...


@dataclass(frozen=True, slots=True)
class Profile:
    mode: str
    threatfox_enabled: bool
    anonymous: bool
    hold_minutes: int
    daily_cap: int
    key: str | None


class AbusechSubmitWorker(FeatureWorker):
    name = "abusech_submit"
    interval_s = 60.0

    def __init__(
        self,
        settings: FeatureSettings,
        factory: Factory | None,
        terms: TermsLike | None = None,
        gate: EgressGate | None = None,
        box: SecretBox | None = None,
        *,
        intel: IntelLike | None = None,
        client: AbusechClient | None = None,
        malpedia: dict[str, str] | None = None,
    ) -> None:
        super().__init__(settings, enabled=settings.abusech_submit_enabled)
        self._factory = factory
        self.terms = terms
        self._gate = gate
        self.box = box
        self.intel = intel
        self.malpedia = malpedia or {}
        self.client = client
        if self.client is None and self.enabled:
            self.client = AbusechClient(gate)
        self._paused_until = 0.0
        self._lookup_paused_until = 0.0
        self._lookup_disabled = False
        self.counters: dict[str, int] = {}

    @property
    def db(self) -> Factory:
        if self._factory is None:
            raise RuntimeError("the worker has no database")
        return self._factory

    @property
    def gate(self) -> EgressGate:
        return self._gate or get_gate()

    def _count(self, key: str, n: int = 1) -> None:
        self.counters[key] = self.counters.get(key, 0) + n

    # ---- profile -------------------------------------------------------------------------
    async def load_profile(self) -> Profile | None:
        async with self.db() as session:
            row = (
                await session.execute(
                    text(
                        "SELECT mode, threatfox_enabled, anonymous, auto_hold_minutes, daily_cap, "
                        "key_ciphertext, key_nonce FROM abusech_submission WHERE id = 1"
                    )
                )
            ).first()
        if row is None:
            return None
        key: str | None = None
        if row.key_ciphertext is not None and self.box is not None:
            try:
                key = self.box.decrypt(KEY_AAD, bytes(row.key_ciphertext), bytes(row.key_nonce)).key
            except SecretError:
                key = None
        return Profile(
            row.mode,
            row.threatfox_enabled,
            row.anonymous,
            row.auto_hold_minutes,
            row.daily_cap,
            key,
        )

    # ---- one cycle -----------------------------------------------------------------------
    async def run_once(self) -> None:
        if not self.enabled or self._factory is None or self.client is None:
            return  # the server switch is off: nothing is computed, looked up or sent
        profile = await self.load_profile()
        if profile is None:
            return
        if profile.mode == "off":
            await self._cancel_pending(only_auto=False, code="mode_off")
            return  # candidates are not even computed
        if profile.mode == "review":
            await self._cancel_pending(only_auto=True, code="mode_changed")
        await self._sweep()
        await self.discover(profile)
        await self.lookups(profile)
        if profile.mode == "auto":
            await self.schedule(profile)
        await self.send_due(profile)

    async def _cancel_pending(self, *, only_auto: bool, code: str) -> None:
        async with self.db() as session, session.begin():
            await session.execute(
                text(
                    "UPDATE abusech_submissions SET status = 'cancelled', result_code = :c, "
                    "done_at = now() WHERE status = 'pending' AND (auto OR NOT :only_auto)"
                ),
                {"c": code, "only_auto": only_auto},
            )

    async def _sweep(self) -> None:
        """A row left in ``submitting`` ended in an outcome nobody knows: failed, never retried."""
        async with self.db() as session, session.begin():
            await session.execute(
                text(
                    "UPDATE abusech_submissions SET status = 'failed', "
                    "result_code = 'unknown_outcome', done_at = now() "
                    "WHERE status = 'submitting' AND started_at < now() - make_interval(secs => :s)"
                ),
                {"s": STALE_SUBMITTING.total_seconds()},
            )

    # ---- candidates ----------------------------------------------------------------------
    def build_body(self, platform: str, value: str, malware: str | None, tags: list[str],
                   anonymous: bool) -> bytes:  # fmt: skip
        if platform == "urlhaus":
            return urlhaus_body(value, tags, anonymous=anonymous)
        return threatfox_body(value, malware or "", tags, anonymous=anonymous)

    async def _guard(
        self, body: bytes, fetch_target_id: int | None, session: AsyncSession
    ) -> tuple[bool, tuple[str, ...]]:
        """(ok, codes). A missing deny set or an unknown own address is a failure (fail closed)."""
        terms = await self.terms.get() if self.terms is not None else None
        ids = await cand.session_ids(session, fetch_target_id)
        result = guard(body, terms, fmt="json", ctx=GuardContext(internal_ids=ids))
        return result.ok, tuple(result.codes)

    async def discover(self, profile: Profile) -> int:
        found = await cand.urlhaus_candidates(self.db)
        if profile.threatfox_enabled:
            found += await cand.threatfox_candidates(self.db, self.malpedia)
        added = 0
        for c in found:
            status, code = "candidate", None
            async with self.db() as session, session.begin():
                if c.refusal == "never_list":
                    status, code = "skipped_never_list", "never_list"
                else:
                    try:
                        body = self.build_body(
                            c.platform, c.value, c.malware, list(c.tags), profile.anonymous
                        )
                    except ValueError:
                        continue
                    ok, codes = await self._guard(body, c.fetch_target_id, session)
                    if not ok:
                        if set(codes) <= TRANSIENT_GUARD:
                            continue  # not recorded: retried when the deny set is ready
                        status, code = "guard_failed", ("guard_failed:" + ",".join(codes))[:120]
                inserted = await session.execute(
                    text(
                        """
                        INSERT INTO abusech_submissions
                            (platform, ioc_type, value, threat, malware, tags, sample_sha256,
                             fetch_target_id, status, result_code)
                        VALUES (:p, :t, :v, :th, :m, CAST(:tags AS text[]), :sha, :f, :s, :c)
                        ON CONFLICT (platform, value) DO NOTHING
                        """
                    ),
                    {
                        "p": c.platform, "t": c.ioc_type, "v": c.value, "th": c.threat,
                        "m": c.malware, "tags": list(c.tags), "sha": c.sample_sha256,
                        "f": c.fetch_target_id, "s": status, "c": code,
                    },
                )  # fmt: skip
                added += int(inserted.rowcount or 0)  # type: ignore[attr-defined]
        self._count("candidates", added)
        return added

    # ---- lookup first (dedupe) ------------------------------------------------------------
    async def lookups(self, profile: Profile) -> int:
        intel = self.intel
        if (
            intel is None
            or self._lookup_disabled
            or time.monotonic() < self._lookup_paused_until
            or not intel.enabled("abusech")
        ):
            return 0  # the candidate stays 'pending lookup' and is not submittable
        async with self.db() as session:
            rows = (
                await session.execute(
                    text(
                        "SELECT id, platform, value FROM abusech_submissions "
                        "WHERE status = 'candidate' AND lookup = 'pending' AND NOT demo "
                        "ORDER BY id LIMIT :n"
                    ),
                    {"n": MAX_LOOKUPS},
                )
            ).all()
        done = 0
        for r in rows:
            if not gate_open(self._gate):
                break
            if not await reserve_quota(self.db, "abusech", intel.quota("abusech")):
                self._lookup_paused_until = time.monotonic() + 600
                break
            try:
                if r.platform == "urlhaus":
                    res = await intel.urlhaus("url", r.value)
                else:
                    res = await intel.threatfox("ip", r.value.rsplit(":", 1)[0])
            except EgressClosed:
                await refund_quota(self.db, "abusech")
                break
            except ProviderError as exc:
                if exc.kind == "auth":
                    self._lookup_disabled = True
                elif exc.kind == "rate_limited":
                    self._lookup_paused_until = time.monotonic() + PAUSE_S
                break
            await self._store_lookup(r.id, res, profile)
            done += 1
        self._count("lookups", done)
        return done

    async def _store_lookup(self, sid: int, res: IntelResult, profile: Profile) -> None:
        async with self.db() as session, session.begin():
            if res.known:
                await session.execute(
                    text(
                        "UPDATE abusech_submissions SET lookup = 'known', "
                        "status = 'skipped_known', reference = :ref, "
                        "result_code = 'already_known', done_at = now() "
                        "WHERE id = :i AND status = 'candidate'"
                    ),
                    {"i": sid, "ref": (res.reference or None) and res.reference[:256]},
                )
            else:
                await session.execute(
                    text(
                        "UPDATE abusech_submissions SET lookup = 'unknown' "
                        "WHERE id = :i AND status = 'candidate'"
                    ),
                    {"i": sid},
                )

    async def schedule(self, profile: Profile) -> int:
        """Auto mode: each looked-up candidate becomes pending after the hold time."""
        at = datetime.now(UTC) + timedelta(minutes=profile.hold_minutes)
        if not profile.key:
            return 0  # auto needs a key (the settings row enforces it too)
        async with self.db() as session, session.begin():
            result = await session.execute(
                text(
                    """
                    UPDATE abusech_submissions SET status = 'pending', auto = true,
                        scheduled_at = :at
                    WHERE id IN (
                        SELECT id FROM abusech_submissions
                        WHERE status = 'candidate' AND lookup = 'unknown' AND NOT demo
                          AND (platform = 'urlhaus' OR :tf)
                        ORDER BY id LIMIT :n)
                    """
                ),
                {"at": at, "tf": profile.threatfox_enabled, "n": MAX_SCHEDULE},
            )
            n = int(result.rowcount or 0)  # type: ignore[attr-defined]
        self._count("scheduled", n)
        return n

    # ---- sending -------------------------------------------------------------------------
    async def send_due(self, profile: Profile) -> int:
        if time.monotonic() < self._paused_until or not profile.key:
            return 0
        async with self.db() as session:
            ids = (
                (
                    await session.execute(
                        text(
                            "SELECT id FROM abusech_submissions WHERE status = 'pending' "
                            "AND NOT demo AND (scheduled_at IS NULL OR scheduled_at <= now()) "
                            "AND (platform = 'urlhaus' OR :tf) ORDER BY auto, id LIMIT :n"
                        ),
                        {"tf": profile.threatfox_enabled, "n": MAX_PER_CYCLE},
                    )
                )
                .scalars()
                .all()
            )
        sent = 0
        for sid in ids:
            if time.monotonic() < self._paused_until:
                break
            if await self._send_one(sid, profile):
                sent += 1
        self._count("sent", sent)
        return sent

    async def _send_one(self, sid: int, profile: Profile) -> bool:
        client = self.client
        if client is None or not profile.key:
            return False
        async with self.db() as session:
            row = (
                await session.execute(
                    text(
                        "SELECT platform, value, malware, tags, fetch_target_id, auto "
                        "FROM abusech_submissions "
                        "WHERE id = :i AND status = 'pending' AND NOT demo"
                    ),
                    {"i": sid},
                )
            ).first()
            if row is None:
                return False
            if row.auto and profile.mode != "auto":
                return False
            try:
                body = self.build_body(
                    row.platform, row.value, row.malware, list(row.tags), profile.anonymous
                )
            except ValueError:
                await self._finish(sid, "failed", "invalid")
                return False
            ok, codes = await self._guard(body, row.fetch_target_id, session)
        if not ok:
            if not set(codes) <= TRANSIENT_GUARD:
                await self._finish(sid, "guard_failed", ("guard_failed:" + ",".join(codes))[:120])
            return False  # nothing was sent
        if not gate_open(self._gate):
            return False
        if not await reserve_quota(self.db, QUOTA, profile.daily_cap):
            return False  # the daily cap: it stays pending until tomorrow
        if not await self._claim(sid):
            await refund_quota(self.db, QUOTA)
            return False
        try:
            code = await client.submit(row.platform, body, profile.key)
        except EgressClosed:
            await self._unclaim(sid)  # raised before any socket: nothing was sent
            await refund_quota(self.db, QUOTA)
            return False
        except Exception as exc:  # never let a message escape; after the claim it is unknown
            log.warning("abuse.ch submission %s failed (%s)", sid, type(exc).__name__)
            code = UNKNOWN_OUTCOME
        await self._finish(sid, FINAL_STATUS.get(code, "failed"), code, sent=code == INSERTED)
        if code in (AUTH_FAILED, RATE_LIMITED):
            self._paused_until = time.monotonic() + PAUSE_S
        return code == INSERTED

    async def _claim(self, sid: int) -> bool:
        """``submitting`` is committed on its own BEFORE the request."""
        async with self.db() as session, session.begin():
            claimed = await session.execute(
                text(
                    "UPDATE abusech_submissions SET status = 'submitting', started_at = now() "
                    "WHERE id = :i AND status = 'pending'"
                ),
                {"i": sid},
            )
            return claimed.rowcount == 1  # type: ignore[attr-defined,no-any-return]

    async def _unclaim(self, sid: int) -> None:
        async with self.db() as session, session.begin():
            await session.execute(
                text(
                    "UPDATE abusech_submissions SET status = 'pending', started_at = NULL "
                    "WHERE id = :i AND status = 'submitting'"
                ),
                {"i": sid},
            )

    async def _finish(self, sid: int, status: str, code: str, *, sent: bool = False) -> None:
        async with self.db() as session, session.begin():
            await session.execute(
                text(
                    "UPDATE abusech_submissions SET status = :s, result_code = :c, "
                    "done_at = now(), submitted_at = CASE WHEN :sent THEN now() END "
                    "WHERE id = :i AND status IN ('pending', 'submitting')"
                ),
                {"s": status, "c": code[:120], "sent": sent, "i": sid},
            )

    async def status(self) -> dict[str, Any]:
        base = await super().status()
        base[self.name].update(self.counters)
        return base

    async def aclose(self) -> None:
        if self.client is not None:
            await self.client.aclose()

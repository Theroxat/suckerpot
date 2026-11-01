"""Sending abuse reports by SMTP, the ingest side of M25 (design doc M25, section 2.3).

The API writes ``abuse_send_requests`` rows; this module answers them. In auto mode it also
schedules the ready reports after the hold. Nothing is sent unless the owner configured the
profile and chose a mode; demo reports and reports that fail the identity guard are never sent.

Order of a send, each step stopping the whole thing:

1. the request is still pending (row locked, so a cancel waits and a late cancel is refused);
2. the profile is complete, the mode allows it, the daily cap (auto) is not reached;
3. the egress gate is open. If not, the request STAYS pending (a test fails with
   ``egress_closed`` after two minutes): nothing is attempted, no socket is created;
4. the report is re-rendered from the stored evidence and the complete serialized message is
   guarded (``guard_failed:<codes>``, including ``no_self_address``);
5. delivery through the VPN proxy (``outgoing.deliver``), gate checked again right before connect;
6. the report becomes ``sent`` (``sent_via = 'smtp'``) and the request ``sent``, in one commit.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db.secretbox import SecretBox, SecretError
from suckerpot_reporting import (
    Evidence,
    GuardContext,
    RenderedMessage,
    RenderUnavailable,
    ReportSettings,
    render_csv,
    render_text,
    render_xarf,
)

from ingest.abuse.build import default_options, options_of
from ingest.abuse.config import AbuseSettings
from ingest.abuse.selfterms import TermsCache
from ingest.egress import EgressClosed, EgressGate, gate_open, get_gate
from ingest.reportmail.outgoing import (
    SMTP_DEADLINE_S,
    Profile,
    SendFailure,
    build_message,
    build_test_message,
    check_message,
    deliver,
)

log = logging.getLogger(__name__)

MAX_PER_CYCLE = 10
MAX_SCHEDULE = 50
TEST_EGRESS_WAIT = timedelta(minutes=2)
MAX_SESSION_IDS = 5000
PASSWORD_AAD = "report_smtp"  # noqa: S105 - a label, not a secret; bound to the ciphertext, see api.abuse_smtp


MARK_SENT = (
    "UPDATE abuse_reports SET status = 'sent', sent_at = now(), sent_by = :by, sent_via = 'smtp' "
    "WHERE id = :i AND status IN ('draft', 'reviewed')"
)
# An automatic send of a draft is stamped as reviewed by 'auto' (the trigger allows nothing else).
MARK_AUTO = (
    "UPDATE abuse_reports SET status = 'sent', sent_at = now(), sent_by = :by, sent_via = 'smtp', "
    "reviewed_at = now(), reviewed_by = 'auto', reviewed_revision = revision "
    "WHERE id = :i AND status IN ('draft', 'reviewed')"
)


@dataclass(frozen=True, slots=True)
class Request:
    id: int
    report_id: int | None
    kind: str
    auto: bool
    requested_by: str
    requested_at: datetime
    scheduled_at: datetime | None


class ReportSender:
    def __init__(
        self,
        factory: async_sessionmaker[AsyncSession],
        terms: TermsCache,
        abuse: AbuseSettings,
        *,
        box: SecretBox | None = None,
        gate: EgressGate | None = None,
        allow_documentation: bool = False,
    ) -> None:
        self.factory = factory
        self.terms = terms
        self.abuse = abuse
        self.box = box
        self._gate = gate
        # Tests only: their evidence uses documentation addresses. Production keeps False, so a
        # report that names a documentation range is never sent.
        self._allow_documentation = allow_documentation

    @property
    def gate(self) -> EgressGate:
        return self._gate or get_gate()

    # -- profile -------------------------------------------------------------------------

    async def load_profile(self, session: AsyncSession) -> Profile | None:
        row = (
            await session.execute(
                text(
                    "SELECT host, port, security, username, from_address, from_name, mode, "
                    "auto_hold_minutes, daily_cap, password_ciphertext, password_nonce "
                    "FROM report_smtp WHERE id = 1"
                )
            )
        ).first()
        if row is None:
            return None
        password = ""
        if row.password_ciphertext is not None:
            if self.box is None:
                return None  # no key to decrypt with: the profile is unusable
            try:
                password = self.box.decrypt(
                    PASSWORD_AAD, bytes(row.password_ciphertext), bytes(row.password_nonce)
                ).key
            except SecretError:
                return None
        elif row.username:
            return None  # a login without a password
        return Profile(
            host=row.host,
            port=row.port,
            security=row.security,
            username=row.username,
            from_address=row.from_address,
            from_name=row.from_name,
            mode=row.mode,
            auto_hold_minutes=row.auto_hold_minutes,
            daily_cap=row.daily_cap,
            password=password,
        )

    # -- one cycle -----------------------------------------------------------------------

    async def run(self, now: datetime) -> None:
        async with self.factory() as session:
            ids = (
                (
                    await session.execute(
                        text(
                            "SELECT id FROM abuse_send_requests WHERE status = 'pending' "
                            "ORDER BY id LIMIT :n"
                        ),
                        {"n": MAX_PER_CYCLE},
                    )
                )
                .scalars()
                .all()
            )
        for rid in ids:
            await self._handle(rid, now)
        await self.schedule(now)

    async def schedule(self, now: datetime) -> int:
        """Auto mode: a pending request, ``auto_hold_minutes`` ahead, for each ready report that
        never had one. Cancelled and failed requests are not rescheduled (the owner decided or
        can press Send)."""
        async with self.factory() as session, session.begin():
            profile = await self.load_profile(session)
            if profile is None or profile.mode != "auto":
                return 0
            result = await session.execute(
                text(
                    """
                    INSERT INTO abuse_send_requests (report_id, kind, auto, requested_by,
                                                     scheduled_at)
                    SELECT r.id, 'send', true, 'auto', :at
                    FROM abuse_reports r JOIN abuse_recipients rec ON rec.id = r.recipient_id
                    WHERE r.status IN ('draft', 'reviewed') AND NOT r.demo AND r.guard_ok
                      AND NOT rec.muted
                      AND COALESCE(NULLIF(rec.override_mailbox, ''), rec.mailbox) IS NOT NULL
                      AND NOT EXISTS (
                          SELECT 1 FROM abuse_send_requests q WHERE q.report_id = r.id)
                    ORDER BY r.id LIMIT :n
                    """
                ),
                {"at": now + timedelta(minutes=profile.auto_hold_minutes), "n": MAX_SCHEDULE},
            )
            return int(result.rowcount or 0)  # type: ignore[attr-defined]

    async def _sent_today(self, session: AsyncSession) -> int:
        return int(
            await session.scalar(
                text(
                    "SELECT count(*) FROM abuse_send_requests WHERE kind = 'send' "
                    "AND status = 'sent' AND done_at >= "
                    "(date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')"
                )
            )
            or 0
        )

    async def _finish(
        self, session: AsyncSession, rid: int, status: str, code: str | None = None
    ) -> None:
        await session.execute(
            text(
                "UPDATE abuse_send_requests SET status = :s, error_code = :c, done_at = now() "
                "WHERE id = :i AND status = 'pending'"
            ),
            {"s": status, "c": code, "i": rid},
        )

    # -- one request ---------------------------------------------------------------------

    async def _handle(self, rid: int, now: datetime) -> None:
        async with self.factory() as session, session.begin():
            row = (
                await session.execute(
                    text(
                        "SELECT id, report_id, kind, auto, requested_by, requested_at, "
                        "scheduled_at FROM abuse_send_requests "
                        "WHERE id = :i AND status = 'pending' FOR UPDATE SKIP LOCKED"
                    ),
                    {"i": rid},
                )
            ).first()
            if row is None:
                return  # cancelled meanwhile, or the API holds the row
            req = Request(*row)
            profile = await self.load_profile(session)
            if profile is None:
                await self._finish(session, rid, "failed", "not_configured")
                return
            if req.scheduled_at is not None and req.scheduled_at > now:
                return
            if req.kind == "send":
                refused = self._mode_refusal(req, profile)
                if refused is not None:
                    await self._finish(session, rid, refused[0], refused[1])
                    return
                if req.auto and await self._sent_today(session) >= profile.daily_cap:
                    return  # the cap is per UTC day: it stays pending until tomorrow
            if not gate_open(self.gate):
                # Nothing is attempted: no socket, no tunnel. A send waits for the VPN.
                if req.kind == "test" and now - req.requested_at > TEST_EGRESS_WAIT:
                    await self._finish(session, rid, "failed", "egress_closed")
                return
            try:
                await self._send(session, req, profile, now)
            except SendFailure as exc:
                if exc.code == "egress_closed" and req.kind == "send":
                    return  # the gate closed under us: still pending
                await self._finish(session, rid, "failed", exc.stored)
                log.info("abuse mail request %s failed (%s)", rid, exc.code)
            except Exception as exc:  # never let a message text escape
                log.warning("abuse mail request %s failed (%s)", rid, type(exc).__name__)
                await self._finish(session, rid, "failed", "internal")

    @staticmethod
    def _mode_refusal(req: Request, profile: Profile) -> tuple[str, str] | None:
        if profile.mode == "off":
            return ("failed", "mode_off")
        if req.auto and profile.mode != "auto":
            return ("cancelled", "mode_changed")
        return None

    async def _send(
        self, session: AsyncSession, req: Request, profile: Profile, now: datetime
    ) -> None:
        terms = await self.terms.get()
        if req.kind == "test":
            raw = build_test_message(profile)
            rcpt = profile.from_address
            check_message(raw, profile, rcpt, terms)
            await self._deliver(profile, raw, rcpt)
            await self._finish(session, req.id, "sent")
            return
        if req.report_id is None:
            raise SendFailure("not_ready")
        report = await self._load_report(session, req.report_id)
        if report is None:
            raise SendFailure("not_ready")
        rendered, ctx = await self._render(session, report)
        raw = build_message(profile, rendered, now=now)
        rcpt = rendered.to
        check_message(raw, profile, rcpt, terms, ctx=ctx, rendered=rendered)
        await self._deliver(profile, raw, rcpt)
        stamp: dict[str, Any] = {"i": report["id"], "by": req.requested_by[:120]}
        auto_review = req.auto and report["status"] == "draft"
        # The mail is gone: whatever happens to the bookkeeping, the request must end as sent,
        # or the next cycle would send it again.
        try:
            async with session.begin_nested():
                await session.execute(
                    text(MARK_AUTO if auto_review else MARK_SENT),
                    stamp,
                )
        except DBAPIError:
            log.warning("abuse report %s was sent but could not be marked", report["id"])
        await self._finish(session, req.id, "sent")

    async def _deliver(self, profile: Profile, raw: bytes, rcpt: str) -> None:
        try:
            self.gate.require_open()  # before any thread, socket or tunnel exists
            await asyncio.wait_for(
                asyncio.to_thread(deliver, self.gate, profile, raw, rcpt), SMTP_DEADLINE_S
            )
        except EgressClosed:
            raise SendFailure("egress_closed") from None
        except TimeoutError:
            raise SendFailure("timeout") from None

    # -- the report ----------------------------------------------------------------------

    async def _load_report(self, session: AsyncSession, report_id: int) -> dict[str, Any] | None:
        row = (
            await session.execute(
                text(
                    "SELECT r.id, r.status, r.demo, r.kind, r.guard_ok, r.evidence, r.options, "
                    "r.window_start, r.window_end, rec.muted, rec.mailbox, rec.override_mailbox "
                    "FROM abuse_reports r JOIN abuse_recipients rec ON rec.id = r.recipient_id "
                    "WHERE r.id = :i"
                ),
                {"i": report_id},
            )
        ).first()
        if row is None:
            return None
        report = dict(row._mapping)
        mailbox = report["override_mailbox"] or report["mailbox"]
        if (
            report["status"] not in ("draft", "reviewed")
            or report["demo"]
            or not report["guard_ok"]
            or report["muted"]
            or not mailbox
        ):
            return None
        report["recipient"] = mailbox
        return report

    async def _render(
        self, session: AsyncSession, report: dict[str, Any]
    ) -> tuple[RenderedMessage, GuardContext]:
        settings_row = (
            await session.execute(
                text(
                    "SELECT reply_contact, signature, intro, outro, note, subject_template, "
                    "xarf_user_agent, defaults FROM report_settings WHERE id = 1"
                )
            )
        ).first()
        settings = ReportSettings()
        defaults: dict[str, Any] = {}
        if settings_row is not None:
            settings = ReportSettings(
                reply_contact=settings_row.reply_contact,
                signature=settings_row.signature,
                intro=settings_row.intro,
                outro=settings_row.outro,
                note=settings_row.note,
                subject_template=settings_row.subject_template,
                xarf_user_agent=settings_row.xarf_user_agent,
            )
            defaults = dict(settings_row.defaults or {})
        options = options_of(report["options"], default_options(self.abuse, defaults))
        data = dict(report["evidence"])
        data.update(
            kind=report["kind"],
            recipient=report["recipient"],
            window_start=report["window_start"],
            window_end=report["window_end"],
            demo=False,
            options=options.model_dump(),
        )
        try:
            evidence = Evidence.model_validate(data)
            rendered = await asyncio.to_thread(_render_mail, evidence, settings)
        except RenderUnavailable as exc:
            raise SendFailure("guard_failed", reasons=(exc.code,)) from None
        except ValueError:
            raise SendFailure("not_ready") from None
        ips = [s.value for s in evidence.subjects if s.type == "ip"]
        ids: set[str] = set()
        if ips:
            found = await session.execute(
                text(
                    "SELECT session_id FROM sessions WHERE src_ip = ANY(CAST(:ips AS inet[])) "
                    "AND started_at >= :a AND started_at <= :b LIMIT :n"
                ),
                {"ips": ips, "a": evidence.window_start, "b": evidence.window_end,
                 "n": MAX_SESSION_IDS},
            )  # fmt: skip
            ids.update(found.scalars().all())
        return rendered, GuardContext(
            internal_ids=frozenset(ids), allow_documentation=self._allow_documentation
        )


def _render_mail(evidence: Evidence, settings: ReportSettings) -> RenderedMessage:
    """What the owner would paste: the X-ARF message when possible, else text and evidence CSV."""
    try:
        return render_xarf(evidence, settings)
    except RenderUnavailable:
        body = render_text(evidence, settings)
        return replace(body, attachments=(render_csv(evidence),))

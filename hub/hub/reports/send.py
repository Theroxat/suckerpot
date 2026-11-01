"""Sending approved reports by SMTP, under the daily caps (section 8.5).

One mail per recipient per day, at most ``HUB_REPORT_DAILY_CAP`` mails a day. Only reports in the
``approved`` state are sent; in ``review`` mode that means an operator ran
``python -m hub.admin reports approve``. Headers are neutral: no mailer name, no project name.
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import date, datetime
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings

log = logging.getLogger("hub.reports")

# (recipient, subject, body, x-arf part or None) -> raises SendError on failure
Mailer = Callable[[str, str, str, str | None], Awaitable[None]]


class SendError(Exception):
    """The message is a short constant code (never a server answer)."""


@dataclass
class SendResult:
    sent: int = 0
    failed: int = 0
    deferred: dict[str, int] = field(default_factory=dict)


def build_message(
    s: Settings, to: str, subject: str, body: str, xarf: str | None, now: datetime
) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = s.smtp_from
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = format_datetime(now)
    msg["Message-ID"] = make_msgid(domain=s.smtp_from.rpartition("@")[2] or "localhost")
    if s.report_reply_to:
        msg["Reply-To"] = s.report_reply_to
    if xarf:
        msg["X-ARF"] = "YES"
    msg.set_content(body)
    if xarf:
        msg.add_attachment(xarf, subtype="plain", filename="report.txt")
    return msg


def smtp_mailer(s: Settings, clock: Callable[[], datetime]) -> Mailer:
    """A mailer for the configured server: implicit TLS on 465, STARTTLS otherwise."""

    def deliver(to: str, subject: str, body: str, xarf: str | None) -> None:
        msg = build_message(s, to, subject, body, xarf, clock())
        context = ssl.create_default_context()
        try:
            if s.smtp_port == 465:
                with smtplib.SMTP_SSL(s.smtp_host, s.smtp_port, context=context, timeout=30) as c:
                    _login_and_send(c, s, msg)
            else:
                with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=30) as c:
                    if s.smtp_starttls:
                        c.starttls(context=context)
                    _login_and_send(c, s, msg)
        except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
            raise SendError(type(exc).__name__) from None

    async def send(to: str, subject: str, body: str, xarf: str | None) -> None:
        if not (s.smtp_host and s.smtp_from):
            raise SendError("smtp_not_configured")
        await asyncio.to_thread(deliver, to, subject, body, xarf)

    return send


def _login_and_send(client: smtplib.SMTP, s: Settings, msg: EmailMessage) -> None:
    if s.smtp_user:
        client.login(s.smtp_user, s.smtp_password)
    client.send_message(msg)


def split_stored(body_text: str) -> tuple[str, str]:
    """Reports store ``Subject: ...`` on the first line, a blank line, then the body."""
    head, _, rest = body_text.partition("\n\n")
    return head.removeprefix("Subject: "), rest


async def send_due(
    session: AsyncSession, s: Settings, now: datetime, today: date, mailer: Mailer
) -> SendResult:
    result = SendResult()
    if s.report_mode == "off":
        return result
    sent_today = (
        await session.execute(
            text("SELECT coalesce(sum(count), 0) FROM recipient_log WHERE day = :d"), {"d": today}
        )
    ).scalar_one()
    rows = (
        await session.execute(
            text(
                "SELECT id, recipient, body_text, xarf, target_ids FROM reports "
                "WHERE state = 'approved' ORDER BY id"
            )
        )
    ).all()
    for r in rows:
        if sent_today >= s.report_daily_cap:
            result.deferred["daily_cap"] = result.deferred.get("daily_cap", 0) + 1
            continue
        again = (
            await session.execute(
                text("SELECT count FROM recipient_log WHERE recipient = :r AND day = :d"),
                {"r": r.recipient, "d": today},
            )
        ).first()
        if again is not None and again[0] >= 1:
            result.deferred["recipient_cap"] = result.deferred.get("recipient_cap", 0) + 1
            continue
        subject, body = split_stored(r.body_text)
        try:
            await mailer(r.recipient, subject, body, r.xarf)
        except SendError as exc:
            await session.execute(
                text("UPDATE reports SET state = 'failed', error_code = :e WHERE id = :id"),
                {"e": str(exc.args[0] if exc.args else "send_error")[:60], "id": r.id},
            )
            await session.execute(
                text("UPDATE targets SET report_id = NULL WHERE report_id = :id"), {"id": r.id}
            )
            result.failed += 1
            await session.commit()
            continue
        await session.execute(
            text("UPDATE reports SET state = 'sent', sent_at = :now WHERE id = :id"),
            {"now": now, "id": r.id},
        )
        await session.execute(
            text(
                "INSERT INTO recipient_log (recipient, day, count) VALUES (:r, :d, 1) "
                "ON CONFLICT (recipient, day) DO UPDATE SET count = recipient_log.count + 1"
            ),
            {"r": r.recipient, "d": today},
        )
        await session.execute(
            text(
                "UPDATE targets SET state = 'reported', reported_day = :d, updated_at = now() "
                "WHERE id = ANY(:ids) AND state = 'confirmed'"
            ),
            {"d": today, "ids": list(r.target_ids)},
        )
        await session.commit()
        sent_today += 1
        result.sent += 1
    return result

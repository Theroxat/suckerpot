"""One outgoing abuse mail: build it, guard the COMPLETE serialized message, deliver it (M25).

The only SMTP code of the reporting feature (``reporting/`` stays free of ``smtplib``).

* The message has neutral headers: ``From``, ``To`` (the abuse mailbox only), ``Subject``,
  ``Date`` (UTC), a ``Message-ID`` on the sender's domain with a random local part, ``MIME-Version``
  and the content headers, plus ``X-ARF: YES`` for X-ARF parts. No ``Cc``/``Bcc``, no
  ``X-Mailer``, no ``User-Agent``.
* The identity guard runs on the serialized bytes (every header and every MIME part, decoded) and
  on the envelope, right before delivery. A failure, including ``no_self_address`` (nothing is
  known about the monitored system's address), sends nothing.
* Delivery goes through ``suckerpot_egress`` (``TunnelSMTP``, the VPN proxy) only. The gate is
  checked right before connecting; there is no direct socket and no fallback. TLS is mandatory
  with certificate and host name checks. The EHLO name is the domain of the sender address.

Errors are constant codes. The password, the message and the server's answers are never logged.
"""

from __future__ import annotations

import email.policy
import re
import secrets
import smtplib
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage
from email.utils import format_datetime, formataddr
from typing import Final

from suckerpot_egress import TunnelSMTP, TunnelSMTP_SSL
from suckerpot_reporting import (
    GuardContext,
    GuardResult,
    RenderedMessage,
    SelfTerms,
    guard,
    guard_message,
    guard_parts,
)
from suckerpot_reporting.normalize import to_ascii

from ingest.egress import EgressClosed, EgressGate
from ingest.mailname import sender_domain

SMTP_TIMEOUT_S: Final = 15.0
SMTP_DEADLINE_S: Final = 60.0  # the whole exchange, whatever the server drips
MAX_LINE: Final = 900

_MAILBOX: Final = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$")

TEST_SUBJECT: Final = "Test message"
TEST_BODY: Final = "This is a short test message. No action is needed.\n"

# Error codes stored in ``abuse_send_requests.error_code`` (``guard_failed`` carries the guard's
# reason codes after a colon).
CODES: Final = (
    "auth_failed",
    "tls_failed",
    "refused",
    "timeout",
    "network",
    "egress_closed",
    "guard_failed",
    "not_configured",
    "mode_off",
    "mode_changed",
    "not_ready",
    "internal",
)


class SendFailure(Exception):
    """A mail was not sent. ``code`` is a constant; nothing else is ever attached."""

    def __init__(self, code: str, *, reasons: tuple[str, ...] = ()) -> None:
        super().__init__(code)
        self.code = code
        self.reasons = reasons

    @property
    def stored(self) -> str:
        """The value for ``error_code`` (guard reason codes are constants, never matched text)."""
        if self.reasons:
            return f"{self.code}:{','.join(sorted(set(self.reasons)))}"[:120]
        return self.code


@dataclass(frozen=True, slots=True)
class Profile:
    """The ``report_smtp`` row with its password decrypted (ingest is the only reader)."""

    host: str
    port: int
    security: str
    username: str
    from_address: str
    from_name: str
    mode: str
    auto_hold_minutes: int
    daily_cap: int
    password: str = field(default="", repr=False)

    @property
    def domain(self) -> str:
        return sender_domain(self.from_address)


def _wrap(value: str) -> str:
    """ASCII text with lines short enough for a 7bit part, CRLF line ends."""
    out: list[str] = []
    for line in to_ascii(value).replace("\r", "").split("\n"):
        while len(line) > MAX_LINE:
            out.append(line[:MAX_LINE])
            line = line[MAX_LINE:]
        out.append(line)
    return "\r\n".join(out)


def _display(profile: Profile) -> str:
    name = to_ascii(profile.from_name).strip()
    return formataddr((name, profile.from_address)) if name else profile.from_address


def build_message(
    profile: Profile,
    rendered: RenderedMessage,
    *,
    now: datetime | None = None,
    to: str | None = None,
) -> bytes:
    """The serialized message (CRLF, 7bit ASCII). ``to`` defaults to the rendered recipient."""
    recipient = (to or rendered.to).strip()
    if not _MAILBOX.match(recipient):
        raise SendFailure("not_ready")
    mail = EmailMessage(policy=email.policy.SMTP)
    mail["From"] = _display(profile)
    mail["To"] = recipient
    mail["Subject"] = re.sub(r"[\r\n]+", " ", to_ascii(rendered.subject))
    mail["Date"] = format_datetime((now or datetime.now(UTC)).astimezone(UTC))
    mail["Message-ID"] = f"<{secrets.token_urlsafe(18)}@{profile.domain}>"
    if rendered.xarf:
        mail["X-ARF"] = "YES"
    mail.set_content(_wrap(rendered.body), subtype="plain", charset="us-ascii", cte="7bit")
    for att in rendered.attachments:
        subtype = att.media_type.partition("/")[2]
        mail.add_attachment(
            _wrap(att.content),
            subtype=subtype or "plain",
            charset="us-ascii",
            cte="7bit",
            filename=re.sub(r"[^A-Za-z0-9._-]", "_", att.name),
            disposition="attachment",
        )
    return mail.as_bytes(policy=email.policy.SMTP)


def build_test_message(profile: Profile) -> bytes:
    """A short neutral message from the profile to its own sender address."""
    plain = RenderedMessage(to=profile.from_address, subject=TEST_SUBJECT, body=TEST_BODY)
    return build_message(profile, plain)


def check_message(
    raw: bytes,
    profile: Profile,
    rcpt: str,
    terms: SelfTerms | None,
    *,
    ctx: GuardContext | None = None,
    rendered: RenderedMessage | None = None,
) -> None:
    """Guard everything that leaves: all headers and parts (decoded), then the envelope and the
    EHLO name. Raises ``SendFailure('guard_failed', reasons=...)``. ``terms=None`` (the deny set
    could not be read) and an unknown monitored address both fail closed."""
    result: GuardResult = guard(raw, terms, fmt="eml", ctx=ctx)
    envelope = (
        f"{profile.from_address}\n{rcpt}\n{profile.domain}\n{profile.host}\n{profile.username}"
    )
    result = result.merge(guard_parts([("envelope", envelope, "text")], terms, ctx=ctx))
    if rendered is not None:
        result = result.merge(guard_message(rendered, terms, ctx=ctx))
    if not result.ok:
        raise SendFailure("guard_failed", reasons=tuple(result.codes))


def deliver(gate: EgressGate, profile: Profile, raw: bytes, rcpt: str) -> None:
    """Blocking (run it in a thread). The gate is checked immediately before connecting, and the
    connection is a CONNECT tunnel through the VPN proxy: ``TunnelSMTP`` is the only way out."""
    context = ssl.create_default_context()  # certificate chain and host name are verified
    helo = profile.domain
    stage = "connect"
    try:
        gate.require_open()  # EgressClosed before any client, socket or tunnel is created
        if profile.security == "ssl":
            server: smtplib.SMTP = TunnelSMTP_SSL(
                gate, profile.host, profile.port, timeout=SMTP_TIMEOUT_S, context=context,
                local_hostname=helo,
            )  # fmt: skip
        else:
            server = TunnelSMTP(
                gate, profile.host, profile.port, timeout=SMTP_TIMEOUT_S, local_hostname=helo
            )  # fmt: skip
        with server:
            if profile.security != "ssl":
                server.ehlo()
                stage = "tls"
                server.starttls(context=context)  # fails when the server cannot: no plain text
                stage = "connect"
                server.ehlo()
            if profile.username:
                stage = "auth"
                server.login(profile.username, profile.password)
                stage = "send"
            server.sendmail(profile.from_address, [rcpt], raw)
    except EgressClosed:
        raise SendFailure("egress_closed") from None
    except smtplib.SMTPAuthenticationError:
        raise SendFailure("auth_failed") from None
    except smtplib.SMTPNotSupportedError:
        raise SendFailure("tls_failed" if stage == "tls" else "auth_failed") from None
    except ssl.SSLError:
        raise SendFailure("tls_failed") from None
    except TimeoutError:
        raise SendFailure("timeout") from None
    except smtplib.SMTPServerDisconnected:
        raise SendFailure("network") from None
    except smtplib.SMTPException:
        raise SendFailure("refused") from None
    except OSError:
        raise SendFailure("network") from None

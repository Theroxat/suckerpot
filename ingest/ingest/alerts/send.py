"""Delivery: webhooks (Discord, Teams) and e-mail. Ingest is the only service that sends.

Everything leaves through the VPN proxy (``suckerpot_egress``); ingest cannot resolve external
names itself. A closed egress gate makes a send fail with the retryable code ``egress_closed``
before anything is sent.

Webhooks:
* the URL is validated again right before the send (official hosts only, https, port 443);
* the request goes to the host name through the proxy: the proxy side refuses private answers
  (DNS rebinding protection) and the certificate is verified against the real name;
* redirects are never followed, the environment's proxy settings are ignored, the body of the
  answer is not read.

E-mail: TLS is mandatory (STARTTLS or implicit TLS) with certificate and host name verification.
The connection is a CONNECT tunnel through the same proxy (a literal IP host must be public).
The message is built with the standard library's ``EmailMessage``, which refuses header injection.

Errors carry a constant code only (``SendError.code``); a target, a token or a server answer never
reaches a log line, the database or the UI.
"""

from __future__ import annotations

import asyncio
import json
import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

import httpx
from suckerpot_db.alert_targets import TargetError, validate_email, validate_webhook
from suckerpot_egress import TunnelSMTP, TunnelSMTP_SSL

from ingest.alerts.config import AlertSettings
from ingest.alerts.messages import render_discord, render_email, render_teams
from ingest.egress import EgressClosed, EgressGate, get_gate, make_client

log = logging.getLogger(__name__)

HTTP_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
SMTP_TIMEOUT_S = 15.0
SMTP_DEADLINE_S = 60.0  # the whole exchange, whatever the server drips
MAX_BODY_BYTES = 12_000  # well under every service's limit


class SendError(Exception):
    """A delivery failed. ``code`` is a short constant; ``retryable`` says if a retry may work."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


def _status_error(status: int) -> SendError | None:
    if 200 <= status < 300:
        return None
    if 300 <= status < 400:
        return SendError("redirect")  # never followed
    if status == 429:
        return SendError("http_429", retryable=True)
    if status >= 500:
        return SendError("http_5xx", retryable=True)
    return SendError(f"http_{status}")


class Sender:
    def __init__(
        self,
        settings: AlertSettings,
        *,
        smtp_password: str = "",
        client: httpx.AsyncClient | None = None,
        gate: EgressGate | None = None,
    ) -> None:
        self.settings = settings
        self.smtp_password = smtp_password
        self._gate = gate or get_gate()
        # No connection is kept: a webhook is rare, and a pooled tunnel would outlive the gate.
        self.client = client or make_client(
            HTTP_TIMEOUT, gate=self._gate, limits=httpx.Limits(max_keepalive_connections=0)
        )

    async def aclose(self) -> None:
        await self.client.aclose()

    async def send(self, kind: str, target: str, message: dict[str, Any]) -> None:
        try:
            await self._dispatch(kind, target, message)
        except SendError:
            raise
        except EgressClosed:
            raise SendError("egress_closed", retryable=True) from None
        except Exception as exc:  # never let a message text (it may hold a target) escape
            log.warning("alert send failed unexpectedly (%s)", type(exc).__name__)
            raise SendError("internal") from None

    async def _dispatch(self, kind: str, target: str, message: dict[str, Any]) -> None:
        base = self.settings.dashboard_url
        if kind == "email":
            await self._send_email(target, message, base)
        elif kind == "discord":
            await self._post(kind, target, render_discord(message, base))
        elif kind == "teams":
            await self._post(kind, target, render_teams(message, base))
        else:
            raise SendError("unknown_kind")

    # ---- webhooks -----------------------------------------------------------------------------
    async def _post(self, kind: str, target: str, payload: dict[str, Any]) -> None:
        try:
            hook = validate_webhook(kind, target)
        except TargetError:
            raise SendError("blocked_target") from None
        body = json.dumps(payload, ensure_ascii=False).encode()
        if len(body) > MAX_BODY_BYTES:
            raise SendError("too_large")
        try:
            async with self.client.stream(
                "POST",
                hook.url,
                content=body,
                headers={"Content-Type": "application/json"},
                follow_redirects=False,
            ) as response:
                error = _status_error(response.status_code)
        except httpx.TimeoutException:
            raise SendError("timeout", retryable=True) from None
        except httpx.HTTPError as exc:
            cause = repr(exc.__cause__ or exc).lower()
            if "certificate" in cause or "ssl" in cause:
                raise SendError("tls") from None
            raise SendError("network", retryable=True) from None
        if error is not None:
            raise error

    # ---- e-mail -------------------------------------------------------------------------------
    async def _send_email(self, address: str, message: dict[str, Any], base: str) -> None:
        s = self.settings
        if not s.smtp_configured:
            raise SendError("smtp_not_configured")
        try:
            to = validate_email(address)
        except TargetError:
            raise SendError("blocked_target") from None
        subject, text, body_html = render_email(message, base)
        mail = EmailMessage()
        mail["From"] = s.smtp_from
        mail["To"] = to
        mail["Subject"] = subject
        mail.set_content(text)
        mail.add_alternative(body_html, subtype="html")
        self._gate.require_open()  # EgressClosed before the thread starts
        try:
            await asyncio.wait_for(asyncio.to_thread(self._smtp_send, mail, to), SMTP_DEADLINE_S)
        except TimeoutError:
            raise SendError("timeout", retryable=True) from None

    def _smtp_send(self, mail: EmailMessage, to: str) -> None:
        s = self.settings
        context = ssl.create_default_context()  # verifies the certificate chain and host name
        try:
            if s.smtp_security == "ssl":
                server: smtplib.SMTP = TunnelSMTP_SSL(
                    self._gate, s.smtp_host, s.smtp_port, timeout=SMTP_TIMEOUT_S, context=context,
                    local_hostname="localhost",
                )  # fmt: skip
            else:
                server = TunnelSMTP(
                    self._gate, s.smtp_host, s.smtp_port, timeout=SMTP_TIMEOUT_S,
                    local_hostname="localhost",
                )  # fmt: skip
            with server:
                if s.smtp_security != "ssl":
                    server.ehlo()
                    server.starttls(context=context)  # fails when the server cannot: no plain text
                    server.ehlo()
                if s.smtp_user:
                    server.login(s.smtp_user, self.smtp_password)
                server.send_message(mail, to_addrs=[to])
        except EgressClosed:
            raise SendError("egress_closed", retryable=True) from None
        except smtplib.SMTPAuthenticationError:
            raise SendError("smtp_auth") from None
        except smtplib.SMTPRecipientsRefused:
            raise SendError("smtp_recipient") from None
        except ssl.SSLError:
            raise SendError("tls") from None
        except smtplib.SMTPNotSupportedError:
            raise SendError("tls") from None  # no STARTTLS offered
        except (smtplib.SMTPServerDisconnected, TimeoutError, OSError):
            raise SendError("network", retryable=True) from None
        except smtplib.SMTPResponseException as exc:
            raise SendError("smtp_error", retryable=400 <= exc.smtp_code < 500) from None
        except smtplib.SMTPException:
            raise SendError("smtp_error") from None

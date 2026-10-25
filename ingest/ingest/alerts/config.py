"""Settings of the alert senders (environment; the SMTP password may come from Settings)."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

_HOST = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9-]{1,63}$"
)
_FROM = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}$")
SMTP_SECURITY = ("starttls", "ssl")  # plain text is not an option


@dataclass(frozen=True, slots=True)
class AlertSettings:
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_from: str = ""
    smtp_security: str = "starttls"
    dashboard_url: str = ""  # https link prefix put into alerts; empty = no links

    @property
    def smtp_configured(self) -> bool:
        return bool(self.smtp_host and self.smtp_from)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> AlertSettings:
        e = os.environ if env is None else env
        host = e.get("SMTP_HOST", "").strip()
        sender = e.get("SMTP_FROM", "").strip()
        security = e.get("SMTP_SECURITY", "").strip().lower() or "starttls"
        port_raw = e.get("SMTP_PORT", "").strip()
        if host and not _HOST.match(host):
            raise ValueError("SMTP_HOST must be a host name")
        if sender and not _FROM.match(sender):
            raise ValueError("SMTP_FROM must be a plain e-mail address")
        if security not in SMTP_SECURITY:
            raise ValueError("SMTP_SECURITY must be starttls or ssl")
        try:
            port = int(port_raw) if port_raw else (465 if security == "ssl" else 587)
        except ValueError:
            raise ValueError("SMTP_PORT must be an integer") from None
        if not 1 <= port <= 65535:
            raise ValueError("SMTP_PORT must be between 1 and 65535")
        user = e.get("SMTP_USER", "").strip()
        if any(c in user for c in "\r\n\0"):
            raise ValueError("SMTP_USER is not valid")
        base = e.get("ALERTS_DASHBOARD_URL", "").strip().rstrip("/")
        if base:
            parts = urlsplit(base)
            if parts.scheme != "https" or not parts.hostname or parts.username or parts.query:
                raise ValueError("ALERTS_DASHBOARD_URL must be an https URL")
        return cls(
            smtp_host=host,
            smtp_port=port,
            smtp_user=user,
            smtp_from=sender,
            smtp_security=security,
            dashboard_url=base,
        )

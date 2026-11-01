"""``imaplib`` clients that connect through the proxy (``imaplib`` has no proxy support).

The mailbox is the owner's own; the connection still leaves through the VPN gate (O1): the gate
is checked before any socket exists, so a closed gate means nothing is attempted.

``imaplib._MAXLINE`` (the longest line a server may send) is lowered once for the process: a
hostile or broken server cannot make the client buffer megabytes in one line. Literals (message
bodies) are read by size and are not affected. ``debug`` stays 0: server answers are never logged.
"""

from __future__ import annotations

import imaplib
import re
import socket
import ssl
from datetime import UTC, datetime, timedelta, timezone

from suckerpot_egress.gate import EgressGate
from suckerpot_egress.tunnel import open_tunnel_sync

MAX_LINE = 65_536
# Every protocol-level failure of an imaplib client (abort and readonly are subclasses).
ImapError = imaplib.IMAP4.error
DEFAULT_TIMEOUT = 15.0

setattr(imaplib, "_MAXLINE", MAX_LINE)  # noqa: B010 - private, absent from the type stubs

_INTERNALDATE = re.compile(
    rb'INTERNALDATE "(?P<day>[ 0123][0-9])-(?P<mon>[A-Z][a-z][a-z])-(?P<year>[0-9]{4})'
    rb" (?P<hour>[0-9]{2}):(?P<min>[0-9]{2}):(?P<sec>[0-9]{2})"
    rb' (?P<zonen>[-+])(?P<zoneh>[0-9]{2})(?P<zonem>[0-9]{2})"'
)
_MONTHS = [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun"]
_MONTHS += [b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"]


class TunnelIMAP4(imaplib.IMAP4):
    """Plain IMAP over a CONNECT tunnel. STARTTLS is mandatory before ``login`` (caller's job).

    Blocking: run it in a thread.
    """

    def __init__(self, gate: EgressGate, host: str, port: int, *, timeout: float) -> None:
        self._gate = gate  # must exist before the base class connects
        super().__init__(host, port, timeout=timeout)

    def _create_socket(self, timeout: float | None) -> socket.socket:
        sock: socket.socket = open_tunnel_sync(
            self._gate, self.host, self.port, timeout=timeout or DEFAULT_TIMEOUT
        )
        return sock


class TunnelIMAP4_SSL(imaplib.IMAP4_SSL):
    """Implicit-TLS IMAP over a CONNECT tunnel. The certificate is checked against ``host``."""

    def __init__(
        self,
        gate: EgressGate,
        host: str,
        port: int,
        *,
        ssl_context: ssl.SSLContext,
        timeout: float,
    ) -> None:
        self._gate = gate
        super().__init__(host, port, ssl_context=ssl_context, timeout=timeout)

    def _create_socket(self, timeout: float | None) -> socket.socket:
        raw = open_tunnel_sync(self._gate, self.host, self.port, timeout=timeout or DEFAULT_TIMEOUT)
        try:
            wrapped: socket.socket = self.ssl_context.wrap_socket(raw, server_hostname=self.host)
            return wrapped
        except BaseException:
            raw.close()
            raise


def internaldate_to_utc(response: bytes) -> datetime | None:
    """The INTERNALDATE of a FETCH response as an aware UTC datetime, or None if malformed."""
    match = _INTERNALDATE.search(response)
    if match is None:
        return None
    try:
        month = _MONTHS.index(match.group("mon")) + 1
        offset = timedelta(hours=int(match.group("zoneh")), minutes=int(match.group("zonem")))
        if match.group("zonen") == b"-":
            offset = -offset
        local = datetime(
            int(match.group("year")),
            month,
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("min")),
            int(match.group("sec")),
            tzinfo=timezone(offset),
        )
    except ValueError:
        return None
    return local.astimezone(UTC)


def format_since(day: datetime) -> str:
    """``dd-Mon-yyyy`` for ``SEARCH SINCE`` (English month names, whatever the locale)."""
    months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    return f"{day.day:02d}-{months[day.month - 1]}-{day.year:04d}"

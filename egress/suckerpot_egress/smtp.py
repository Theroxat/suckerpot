"""``smtplib`` clients that connect through the proxy (``smtplib`` has no proxy support)."""

from __future__ import annotations

import smtplib
import socket
from typing import Any

from suckerpot_egress.gate import EgressGate
from suckerpot_egress.tunnel import open_tunnel_sync


class TunnelSMTP(smtplib.SMTP):
    """Plain SMTP (STARTTLS is the caller's job) over a CONNECT tunnel. Blocking: use a thread."""

    def __init__(self, gate: EgressGate, host: str, port: int, **kwargs: Any) -> None:
        self._gate = gate  # must exist before the base class connects
        super().__init__(host, port, **kwargs)

    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        return open_tunnel_sync(self._gate, host, port, timeout=timeout)


class TunnelSMTP_SSL(smtplib.SMTP_SSL):
    """Implicit-TLS SMTP over a CONNECT tunnel. The certificate is checked against ``host``."""

    def __init__(self, gate: EgressGate, host: str, port: int, **kwargs: Any) -> None:
        self._gate = gate
        super().__init__(host, port, **kwargs)

    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        raw = open_tunnel_sync(self._gate, host, port, timeout=timeout)
        try:
            return self.context.wrap_socket(raw, server_hostname=host)
        except BaseException:
            raw.close()
            raise

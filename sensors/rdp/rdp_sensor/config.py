"""Runtime configuration, read from environment variables."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

_HOST_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-")


def _bool(raw: str) -> bool:
    return raw.strip().lower() in ("1", "true", "yes", "on")


def valid_hostname(name: str) -> bool:
    """A NetBIOS-compatible label: 1-15 chars, letters, digits and dashes, no leading dash."""
    return 0 < len(name) <= 15 and not name.startswith("-") and set(name) <= _HOST_CHARS


@dataclass(frozen=True)
class Config:
    """All tunables of the sensor. Defaults are safe for an internet-facing deployment."""

    host: str = "0.0.0.0"  # noqa: S104 - listens inside a container
    port: int = 3389
    public_port: int = 3389  # dst_port reported in events
    hostname: str = ""  # empty: derived from the per-deployment secret
    data_dir: str = "/data"
    enable_tls: bool = True
    max_connections: int = 200
    max_per_ip: int = 8
    first_data_timeout: float = 8.0  # waiting for the client's first bytes
    handshake_timeout: float = 10.0  # completing a started PDU / the TLS handshake
    credssp_timeout: float = 10.0  # waiting for the first TSRequest after TLS
    max_session: float = 60.0  # hard cap on one connection
    tls_per_sec_per_ip: float = 5.0  # TLS handshakes started per source (burst below)
    tls_burst_per_ip: float = 20.0
    max_tls_handshakes: int = 32  # TLS handshakes + CredSSP reads in progress, overall
    sessions_per_sec_per_ip: float = 2.0  # recorded connections per source (burst 15x)
    global_sessions_per_sec: float = 50.0  # recorded connections overall (burst 2x)
    global_events_per_sec: float = 200.0
    disconnect_events_per_sec: float = 60.0
    event_queue_size: int = 5000
    summary_interval: float = 60.0  # how often "N connections not recorded" events are sent
    quiet_loopback: bool = True  # no events for 127.0.0.1 / ::1 (the container healthcheck)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Config:
        e = os.environ if env is None else env
        hostname = e.get("RDP_HOSTNAME", "").strip()
        if hostname and not valid_hostname(hostname):
            raise ValueError("RDP_HOSTNAME must be a NetBIOS name (1-15 letters, digits, '-')")
        return cls(
            port=int(e.get("RDP_PORT", "3389")),
            public_port=int(e.get("RDP_PUBLIC_PORT", "3389")),
            hostname=hostname.upper(),
            data_dir=e.get("RDP_DATA_DIR", "/data"),
            enable_tls=_bool(e.get("RDP_ENABLE_TLS", "true")),
            max_connections=max(1, int(e.get("RDP_MAX_CONNECTIONS", "200"))),
            max_per_ip=max(1, int(e.get("RDP_MAX_PER_IP", "8"))),
            first_data_timeout=float(e.get("RDP_FIRST_DATA_TIMEOUT", "8")),
            handshake_timeout=float(e.get("RDP_HANDSHAKE_TIMEOUT", "10")),
            credssp_timeout=float(e.get("RDP_CREDSSP_TIMEOUT", "10")),
            max_session=float(e.get("RDP_MAX_SESSION", "60")),
            tls_per_sec_per_ip=float(e.get("RDP_TLS_PER_SEC_PER_IP", "5")),
            tls_burst_per_ip=float(e.get("RDP_TLS_BURST_PER_IP", "20")),
            max_tls_handshakes=max(1, int(e.get("RDP_MAX_TLS_HANDSHAKES", "32"))),
            disconnect_events_per_sec=float(e.get("RDP_DISCONNECT_EVENTS_PER_SEC", "60")),
            sessions_per_sec_per_ip=float(e.get("RDP_SESSIONS_PER_SEC_PER_IP", "2")),
            global_sessions_per_sec=float(e.get("RDP_GLOBAL_SESSIONS_PER_SEC", "50")),
            global_events_per_sec=float(e.get("RDP_GLOBAL_EVENTS_PER_SEC", "200")),
        )

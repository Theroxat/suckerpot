"""Runtime configuration, read from environment variables."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field

from rdp_sensor.ntlm import nt_hash

_HOST_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-")

NLA_REQUIRED = "required"  # only CredSSP (HYBRID / HYBRID_EX); the internet-facing default
NLA_OPTIONAL = "optional"  # also accept PROTOCOL_SSL and run MCS to the Client Info PDU
NLA_MODES = frozenset({NLA_REQUIRED, NLA_OPTIONAL})

# Default weak pairs whose NTLM response is verified against the known cleartext (decoy accounts).
_DEFAULT_ACCOUNTS = "administrator:P@ssw0rd,administrator:123456,admin:admin"
MAX_ACCOUNTS = 16

# A decoy account: (lowercased user, cleartext password, precomputed NT hash = MD4(password)).
Account = tuple[str, str, bytes]


def _bool(raw: str) -> bool:
    return raw.strip().lower() in ("1", "true", "yes", "on")


def valid_hostname(name: str) -> bool:
    """A NetBIOS-compatible label: 1-15 chars, letters, digits and dashes, no leading dash."""
    return 0 < len(name) <= 15 and not name.startswith("-") and set(name) <= _HOST_CHARS


def parse_accounts(raw: str) -> tuple[Account, ...]:
    """Parse ``user:password,...`` into bounded ``(user_lower, password, nt_hash)`` triples.

    The NT hash (``MD4(password)``) is computed once here at startup, never per attempt.
    """
    out: list[Account] = []
    for item in raw.split(","):
        item = item.strip()
        if not item or ":" not in item:
            continue
        user, _, password = item.partition(":")
        user = user.strip()
        if user and len(out) < MAX_ACCOUNTS:
            out.append((user.lower(), password, nt_hash(password)))
    return tuple(out)


@dataclass(frozen=True)
class Config:
    """All tunables of the sensor. Defaults are safe for an internet-facing deployment."""

    host: str = "0.0.0.0"  # noqa: S104 - listens inside a container
    port: int = 3389
    public_port: int = 3389  # dst_port reported in events
    hostname: str = ""  # empty: derived from the per-deployment secret
    data_dir: str = "/data"
    enable_tls: bool = True
    nla_mode: str = NLA_REQUIRED
    accounts: tuple[Account, ...] = field(default_factory=lambda: parse_accounts(_DEFAULT_ACCOUNTS))
    max_connections: int = 200
    max_per_ip: int = 8
    first_data_timeout: float = 8.0  # waiting for the client's first bytes
    handshake_timeout: float = 10.0  # completing a started PDU / the TLS handshake
    credssp_timeout: float = 10.0  # waiting for a TSRequest after TLS
    mcs_timeout: float = 15.0  # the whole MCS sequence after TLS (NLA-off path)
    max_session: float = 60.0  # hard cap on one connection
    max_mcs_pdus: int = 24  # MCS PDUs handled on the NLA-off path before closing
    tls_per_sec_per_ip: float = 5.0  # TLS handshakes started per source (burst below)
    tls_burst_per_ip: float = 20.0
    max_tls_handshakes: int = 32  # TLS handshakes + CredSSP/MCS reads in progress, overall
    max_tls_per_ip: int = 4  # concurrent TLS handshakes allowed from a single source
    cpu_per_sec_per_ip: float = 60.0  # expensive steps (NTLM crypto / MCS PDUs) per source
    cpu_burst_per_ip: float = 240.0
    memory_limit: int = 128 * 1024 * 1024  # used when the cgroup reports no limit
    max_buffered: int = 24 * 1024 * 1024  # parser buffers + pending output, all connections
    max_pending_output: int = 64 * 1024  # output queued on one connection before it is cut
    session_event_quota: int = 16  # events emitted by one connection
    sessions_per_sec_per_ip: float = 2.0  # recorded connections per source (burst 15x)
    global_sessions_per_sec: float = 50.0  # recorded connections overall (burst 2x)
    global_events_per_sec: float = 200.0
    per_ip_events_per_sec: float = 20.0  # non-priority events per source before the queue
    per_ip_events_burst: float = 60.0
    priority_events_per_sec: float = 80.0  # connect / login_attempt / disconnect
    per_ip_priority_per_sec: float = 10.0  # priority events per source before the shared budget
    per_ip_priority_burst: float = 30.0
    event_queue_size: int = 5000
    summary_interval: float = 60.0  # how often "N connections not recorded" events are sent
    quiet_loopback: bool = True  # no events for 127.0.0.1 / ::1 (the container healthcheck)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Config:
        e = os.environ if env is None else env
        hostname = e.get("RDP_HOSTNAME", "").strip()
        if hostname and not valid_hostname(hostname):
            raise ValueError("RDP_HOSTNAME must be a NetBIOS name (1-15 letters, digits, '-')")
        nla_mode = e.get("SENSOR_RDP_NLA_MODE", NLA_REQUIRED).strip().lower()
        if nla_mode not in NLA_MODES:
            raise ValueError(f"SENSOR_RDP_NLA_MODE must be one of {sorted(NLA_MODES)}")
        return cls(
            port=int(e.get("RDP_PORT", "3389")),
            public_port=int(e.get("RDP_PUBLIC_PORT", "3389")),
            hostname=hostname.upper(),
            data_dir=e.get("RDP_DATA_DIR", "/data"),
            enable_tls=_bool(e.get("RDP_ENABLE_TLS", "true")),
            nla_mode=nla_mode,
            accounts=parse_accounts(e.get("SENSOR_RDP_ACCOUNTS", _DEFAULT_ACCOUNTS)),
            max_connections=max(1, int(e.get("RDP_MAX_CONNECTIONS", "200"))),
            max_per_ip=max(1, int(e.get("RDP_MAX_PER_IP", "8"))),
            first_data_timeout=float(e.get("RDP_FIRST_DATA_TIMEOUT", "8")),
            handshake_timeout=float(e.get("RDP_HANDSHAKE_TIMEOUT", "10")),
            credssp_timeout=float(e.get("RDP_CREDSSP_TIMEOUT", "10")),
            mcs_timeout=float(e.get("RDP_MCS_TIMEOUT", "15")),
            max_session=float(e.get("RDP_MAX_SESSION", "60")),
            max_mcs_pdus=max(1, int(e.get("RDP_MAX_MCS_PDUS", "24"))),
            tls_per_sec_per_ip=float(e.get("RDP_TLS_PER_SEC_PER_IP", "5")),
            tls_burst_per_ip=float(e.get("RDP_TLS_BURST_PER_IP", "20")),
            max_tls_handshakes=max(1, int(e.get("RDP_MAX_TLS_HANDSHAKES", "32"))),
            max_tls_per_ip=max(1, int(e.get("RDP_MAX_TLS_PER_IP", "4"))),
            cpu_per_sec_per_ip=float(e.get("RDP_CPU_PER_SEC_PER_IP", "60")),
            cpu_burst_per_ip=float(e.get("RDP_CPU_BURST_PER_IP", "240")),
            memory_limit=max(1 << 20, int(e.get("RDP_MEMORY_LIMIT", str(128 * 1024 * 1024)))),
            max_buffered=max(4096, int(e.get("RDP_MAX_BUFFERED", str(24 * 1024 * 1024)))),
            max_pending_output=max(4096, int(e.get("RDP_MAX_PENDING_OUTPUT", str(64 * 1024)))),
            session_event_quota=max(4, int(e.get("RDP_SESSION_EVENT_QUOTA", "16"))),
            sessions_per_sec_per_ip=float(e.get("RDP_SESSIONS_PER_SEC_PER_IP", "2")),
            global_sessions_per_sec=float(e.get("RDP_GLOBAL_SESSIONS_PER_SEC", "50")),
            global_events_per_sec=float(e.get("RDP_GLOBAL_EVENTS_PER_SEC", "200")),
            per_ip_events_per_sec=float(e.get("RDP_PER_IP_EVENTS_PER_SEC", "20")),
            per_ip_events_burst=float(e.get("RDP_PER_IP_EVENTS_BURST", "60")),
            priority_events_per_sec=float(e.get("RDP_PRIORITY_EVENTS_PER_SEC", "80")),
            per_ip_priority_per_sec=float(e.get("RDP_PER_IP_PRIORITY_PER_SEC", "10")),
            per_ip_priority_burst=float(e.get("RDP_PER_IP_PRIORITY_BURST", "30")),
        )

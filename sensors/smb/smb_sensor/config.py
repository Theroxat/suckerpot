"""Runtime configuration, read from environment variables."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

_HOST_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-")

# How SMB1 traffic is handled (point 3 of the contract).
SMB1_STEER = "steer"  # answer an SMB1 NEGOTIATE with the "switch to SMB2" wildcard, then record
SMB1_RESET = "reset"  # record the probe and drop the connection without answering
SMB1_MODES = frozenset({SMB1_STEER, SMB1_RESET})


def _bool(raw: str) -> bool:
    return raw.strip().lower() in ("1", "true", "yes", "on")


def valid_hostname(name: str) -> bool:
    """A NetBIOS-compatible label: 1-15 chars, letters, digits and dashes, no leading dash."""
    return 0 < len(name) <= 15 and not name.startswith("-") and set(name) <= _HOST_CHARS


@dataclass(frozen=True)
class Config:
    """All tunables of the sensor. Defaults are safe for an internet-facing deployment."""

    host: str = "0.0.0.0"  # noqa: S104 - listens inside a container
    port: int = 4450
    public_port: int = 445  # dst_port reported in events
    hostname: str = ""  # empty: derived from the per-deployment secret
    domain: str = ""  # empty: derived from the per-deployment secret
    data_dir: str = "/data"
    smb1_mode: str = SMB1_STEER
    max_connections: int = 200
    max_per_ip: int = 10
    first_data_timeout: float = 10.0  # waiting for the client's first bytes
    idle_timeout: float = 20.0  # waiting for the next PDU on an established connection
    read_timeout: float = 10.0  # completing a single PDU already started
    max_session: float = 60.0  # hard cap on one connection
    max_pdu_bytes: int = 128 * 1024  # a single NetBIOS message
    max_session_input: int = 256 * 1024  # bytes read from one client, all PDUs together
    max_pdus: int = 64  # PDUs handled on one connection before it is closed
    max_buffered: int = 32 * 1024 * 1024  # parser buffers + pending output, all connections
    max_pending_output: int = 128 * 1024  # output queued on one connection before it is cut
    memory_limit: int = 256 * 1024 * 1024  # used when the cgroup reports no limit
    cpu_per_sec_per_ip: float = 80.0  # expensive responses (negotiate / NTLM) per source
    cpu_burst_per_ip: float = 320.0
    sessions_per_sec_per_ip: float = 2.0  # recorded connections per source (burst 15x)
    global_sessions_per_sec: float = 50.0  # recorded connections overall (burst 2x)
    global_events_per_sec: float = 200.0
    per_ip_events_per_sec: float = 20.0  # non-priority events per source before the queue
    per_ip_events_burst: float = 60.0
    priority_events_per_sec: float = 80.0  # connect / login_attempt / disconnect
    per_ip_priority_per_sec: float = 10.0  # priority events per source before the shared budget
    per_ip_priority_burst: float = 30.0
    session_event_quota: int = 24  # events emitted by one connection
    event_queue_size: int = 5000
    summary_interval: float = 60.0  # how often "N connections not recorded" events are sent
    quiet_loopback: bool = True  # no events for 127.0.0.1 / ::1 (the container healthcheck)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Config:
        e = os.environ if env is None else env
        hostname = e.get("SMB_HOSTNAME", "").strip()
        if hostname and not valid_hostname(hostname):
            raise ValueError("SMB_HOSTNAME must be a NetBIOS name (1-15 letters, digits, '-')")
        domain = e.get("SMB_DOMAIN", "").strip()
        if domain and not valid_hostname(domain):
            raise ValueError("SMB_DOMAIN must be a NetBIOS name (1-15 letters, digits, '-')")
        smb1_mode = e.get("SMB_SMB1_MODE", SMB1_STEER).strip().lower()
        if smb1_mode not in SMB1_MODES:
            raise ValueError(f"SMB_SMB1_MODE must be one of {sorted(SMB1_MODES)}")
        return cls(
            port=int(e.get("SMB_PORT", "4450")),
            public_port=int(e.get("SMB_PUBLIC_PORT", "445")),
            hostname=hostname.upper(),
            domain=domain.upper(),
            data_dir=e.get("SMB_DATA_DIR", "/data"),
            smb1_mode=smb1_mode,
            max_connections=max(1, int(e.get("SMB_MAX_CONNECTIONS", "200"))),
            max_per_ip=max(1, int(e.get("SMB_MAX_PER_IP", "10"))),
            first_data_timeout=float(e.get("SMB_FIRST_DATA_TIMEOUT", "10")),
            idle_timeout=float(e.get("SMB_IDLE_TIMEOUT", "20")),
            read_timeout=float(e.get("SMB_READ_TIMEOUT", "10")),
            max_session=float(e.get("SMB_MAX_SESSION", "60")),
            max_pdu_bytes=max(68, int(e.get("SMB_MAX_PDU_BYTES", str(128 * 1024)))),
            max_session_input=max(68, int(e.get("SMB_MAX_SESSION_INPUT", str(256 * 1024)))),
            max_pdus=max(1, int(e.get("SMB_MAX_PDUS", "64"))),
            max_buffered=max(4096, int(e.get("SMB_MAX_BUFFERED", str(32 * 1024 * 1024)))),
            max_pending_output=max(4096, int(e.get("SMB_MAX_PENDING_OUTPUT", str(128 * 1024)))),
            memory_limit=max(1 << 20, int(e.get("SMB_MEMORY_LIMIT", str(256 * 1024 * 1024)))),
            cpu_per_sec_per_ip=float(e.get("SMB_CPU_PER_SEC_PER_IP", "80")),
            cpu_burst_per_ip=float(e.get("SMB_CPU_BURST_PER_IP", "320")),
            sessions_per_sec_per_ip=float(e.get("SMB_SESSIONS_PER_SEC_PER_IP", "2")),
            global_sessions_per_sec=float(e.get("SMB_GLOBAL_SESSIONS_PER_SEC", "50")),
            global_events_per_sec=float(e.get("SMB_GLOBAL_EVENTS_PER_SEC", "200")),
            per_ip_events_per_sec=float(e.get("SMB_PER_IP_EVENTS_PER_SEC", "20")),
            per_ip_events_burst=float(e.get("SMB_PER_IP_EVENTS_BURST", "60")),
            priority_events_per_sec=float(e.get("SMB_PRIORITY_EVENTS_PER_SEC", "80")),
            per_ip_priority_per_sec=float(e.get("SMB_PER_IP_PRIORITY_PER_SEC", "10")),
            per_ip_priority_burst=float(e.get("SMB_PER_IP_PRIORITY_BURST", "30")),
            session_event_quota=max(4, int(e.get("SMB_SESSION_EVENT_QUOTA", "24"))),
        )

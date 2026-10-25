"""Runtime configuration, read from environment variables.

``REDIS_HOST``, ``REDIS_PORT``, ``REDIS_USER`` and ``REDIS_PASSWORD`` belong to the event
publisher; the tunables of the sensor use the ``SENSOR_`` prefix and only ``SIP_PUBLIC_PORT``
follows the shared naming scheme.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

MAX_WEAK = 50


def parse_weak(text: str) -> dict[str, str]:
    """Parse ``user:password,user:password`` (split on the first colon, at most 50 pairs)."""
    out: dict[str, str] = {}
    for item in text.split(","):
        user, sep, password = item.strip().partition(":")
        if sep and user and len(user) <= 64 and len(password) <= 64 and len(out) < MAX_WEAK:
            out[user] = password
    return out


def _flag(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Config:
    """All tunables of the sensor. Defaults are safe for an internet-facing deployment."""

    host: str = "0.0.0.0"  # noqa: S104 - listens inside a container
    port: int = 5060
    public_port: int = 5060  # dst_port reported in events
    tcp: bool = True
    data_dir: str = "/data"
    user_agent: str = ""  # empty: an Asterisk version derived from the secret
    realm: str = "asterisk"
    # Credentials that get a (stateless) 200 OK. Nothing is ever established.
    weak_credentials: tuple[tuple[str, str], ...] = (
        ("100", "100"),
        ("1000", "1000"),
        ("admin", "admin"),
    )
    own_ips: tuple[str, ...] = ()
    allow_private: bool = False  # answer RFC 1918 / reserved sources (tests, lab networks)
    allow_loopback: bool = True  # replies to 127.0.0.1 never leave the container
    # --- anti-reflection ---
    reply_per_ip_rate: float = 2.0
    reply_per_ip_burst: float = 5.0
    reply_global_rate: float = 100.0  # replies per second, all sources together
    reply_global_burst: float = 200.0
    reply_bytes_rate: float = 32768.0  # reply bytes per second, all sources together
    reply_bytes_burst: float = 65536.0
    # --- input work bounds ---
    pps_per_ip: float = 50.0
    pps_per_ip_burst: float = 100.0
    pps_global: float = 3000.0
    pps_global_burst: float = 6000.0
    # CPU seconds per second a single source (and all sources) may cost the event loop
    cpu_per_ip_rate: float = 0.05
    cpu_per_ip_burst: float = 0.1
    cpu_global_rate: float = 0.6
    cpu_global_burst: float = 0.5
    # --- TCP ---
    max_connections: int = 100
    max_per_ip: int = 5
    first_data_timeout: float = 15.0
    idle_timeout: float = 30.0
    max_session: float = 120.0
    write_timeout: float = 5.0
    max_messages: int = 200  # per TCP connection
    max_bytes_in: int = 256 * 1024  # per TCP connection
    memory_limit: int = 256 * 1024 * 1024
    # --- events ---
    session_idle: float = 30.0  # a source IP session ends after this much silence
    session_max: float = 300.0
    max_sessions: int = 5000
    sessions_per_sec_per_ip: float = 0.1
    sessions_burst_per_ip: float = 5.0
    global_sessions_per_sec: float = 50.0
    quota_priority: int = 200  # login_attempt + command events per session
    quota_noisy: int = 20  # immediate (non-aggregated) scan events per session
    global_events_per_sec: float = 200.0
    priority_events_per_sec: float = 300.0
    disconnect_events_per_sec: float = 60.0
    event_queue_size: int = 5000
    summary_interval: float = 60.0
    quiet_loopback: bool = True

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Config:
        e = os.environ if env is None else env

        def num(name: str, default: float) -> float:
            return float(e.get(name, str(default)))

        weak = (
            parse_weak(e["SENSOR_SIP_WEAK_CREDENTIALS"])
            if "SENSOR_SIP_WEAK_CREDENTIALS" in e
            else None
        )
        defaults = cls()
        return cls(
            port=int(e.get("SENSOR_PORT", "5060")),
            public_port=int(e.get("SIP_PUBLIC_PORT", "5060")),
            tcp=_flag(e.get("SENSOR_SIP_TCP", "true")),
            data_dir=e.get("SENSOR_DATA_DIR", "/data"),
            user_agent=e.get("SENSOR_SIP_USER_AGENT", "").strip()[:80],
            realm=e.get("SENSOR_SIP_REALM", "asterisk").strip()[:64] or "asterisk",
            weak_credentials=tuple(weak.items()) if weak is not None else defaults.weak_credentials,
            own_ips=tuple(
                x.strip() for x in e.get("SENSOR_SIP_OWN_IPS", "").split(",") if x.strip()
            ),
            allow_private=_flag(e.get("SENSOR_SIP_ALLOW_PRIVATE", "false")),
            reply_per_ip_rate=num("SENSOR_SIP_REPLY_PER_IP_RATE", 2.0),
            reply_per_ip_burst=num("SENSOR_SIP_REPLY_PER_IP_BURST", 5.0),
            reply_global_rate=num("SENSOR_SIP_REPLY_GLOBAL_RATE", 100.0),
            reply_global_burst=num("SENSOR_SIP_REPLY_GLOBAL_BURST", 200.0),
            reply_bytes_rate=num("SENSOR_SIP_REPLY_BYTES_RATE", 32768.0),
            reply_bytes_burst=num("SENSOR_SIP_REPLY_BYTES_BURST", 65536.0),
            pps_per_ip=num("SENSOR_SIP_PPS_PER_IP", 50.0),
            pps_global=num("SENSOR_SIP_PPS_GLOBAL", 3000.0),
            cpu_per_ip_rate=num("SENSOR_SIP_CPU_PER_IP", 0.05),
            cpu_global_rate=num("SENSOR_SIP_CPU_GLOBAL", 0.6),
            max_connections=max(1, int(e.get("SENSOR_MAX_CONNECTIONS", "100"))),
            max_per_ip=max(1, int(e.get("SENSOR_MAX_PER_IP", "5"))),
            first_data_timeout=num("SENSOR_FIRST_DATA_TIMEOUT", 15.0),
            idle_timeout=num("SENSOR_IDLE_TIMEOUT", 30.0),
            max_session=num("SENSOR_MAX_SESSION", 120.0),
            memory_limit=max(1 << 20, int(e.get("SENSOR_MEMORY_LIMIT", str(256 * 1024 * 1024)))),
            global_events_per_sec=num("SENSOR_GLOBAL_EVENTS_PER_SEC", 200.0),
            priority_events_per_sec=num("SENSOR_PRIORITY_EVENTS_PER_SEC", 300.0),
            disconnect_events_per_sec=num("SENSOR_DISCONNECT_EVENTS_PER_SEC", 60.0),
            global_sessions_per_sec=num("SENSOR_GLOBAL_SESSIONS_PER_SEC", 50.0),
            session_idle=num("SENSOR_SIP_SESSION_IDLE", 30.0),
        )

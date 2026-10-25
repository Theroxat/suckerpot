"""Runtime configuration, read from environment variables.

``REDIS_HOST``, ``REDIS_PORT``, ``REDIS_USER`` and ``REDIS_PASSWORD`` belong to the event
publisher (the Redis *stream* server), so the tunables of the sensor itself use the
``SENSOR_`` prefix. Only ``MSSQL_PUBLIC_PORT`` follows the shared naming scheme.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

from mssql_sensor.identity import valid_version

DEFAULT_WEAK_PASSWORDS = ("123456", "password", "Password1", "P@ssw0rd", "sa", "admin")


def _csv(raw: str | None, default: tuple[str, ...]) -> tuple[str, ...]:
    """Comma separated list; ``None`` keeps the default, an empty string means "none"."""
    if raw is None:
        return default
    return tuple(item for item in (p.strip() for p in raw.split(",")) if item)[:64]


@dataclass(frozen=True)
class Config:
    """All tunables of the sensor. Defaults are safe for an internet-facing deployment."""

    host: str = "0.0.0.0"  # noqa: S104 - listens inside a container
    port: int = 1433
    public_port: int = 1433  # dst_port reported in events
    version: str = ""  # e.g. "15.0.4375.4"; empty: picked from the secret
    accept_users: tuple[str, ...] = ("sa",)
    accept_passwords: tuple[str, ...] = DEFAULT_WEAK_PASSWORDS
    tls: bool = True  # offer TLS (self-signed) for the login phase and for Encrypt=yes clients
    max_tls: int = 0  # live TLS streams; 0 = as many as connections (a client never sees NOT_SUP)
    max_tls_per_ip: int = 3
    tls_deadline: float = 10.0  # PRELOGIN reply -> handshake done -> LOGIN7
    new_conn_per_sec_per_ip: float = 3.0
    new_conn_burst_per_ip: float = 40.0
    global_new_conn_per_sec: float = 200.0
    accept_any: bool = False  # accept every login (never the default)
    data_dir: str = "/data"
    max_connections: int = 200
    max_per_ip: int = 8
    first_data_timeout: float = 15.0  # nmap waits several seconds before its second probe
    idle_timeout: float = 45.0
    max_session: float = 240.0
    write_timeout: float = 10.0
    max_commands: int = 1000  # per connection
    max_bytes_in: int = 2 * 1024 * 1024  # per connection
    max_buffered: int = 12 * 1024 * 1024  # parser buffers of all connections together
    memory_limit: int = 256 * 1024 * 1024  # used when the cgroup reports no limit
    # Per-session event quotas (events beyond them are counted and reported at disconnect).
    quota_noisy: int = 40
    quota_commands: int = 300
    quota_priority: int = 400
    quota_logins: int = 50
    quota_downloads: int = 20
    quota_session_total: int = 600
    sessions_per_sec_per_ip: float = 2.0
    global_sessions_per_sec: float = 50.0
    global_events_per_sec: float = 200.0
    priority_events_per_sec: float = 300.0
    disconnect_events_per_sec: float = 60.0
    event_queue_size: int = 5000
    summary_interval: float = 60.0
    quiet_loopback: bool = True  # no events for 127.0.0.1 / ::1 (the container healthcheck)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Config:
        e = os.environ if env is None else env
        version = e.get("SENSOR_MSSQL_VERSION", "").strip()
        if version and not valid_version(version):
            raise ValueError("SENSOR_MSSQL_VERSION must look like 15.0.4375.4 (major 15 or 16)")

        def num(name: str, default: str) -> float:
            return float(e.get(name, default))

        return cls(
            port=int(e.get("SENSOR_PORT", "1433")),
            public_port=int(e.get("MSSQL_PUBLIC_PORT", "1433")),
            accept_users=_csv(e.get("SENSOR_MSSQL_ACCEPT_USERS"), ("sa",)),
            accept_passwords=_csv(e.get("SENSOR_MSSQL_ACCEPT_PASSWORDS"), DEFAULT_WEAK_PASSWORDS),
            tls=e.get("SENSOR_MSSQL_TLS", "true").strip().lower() != "false",
            max_tls=max(0, int(e.get("SENSOR_MAX_TLS", "0"))),
            max_tls_per_ip=max(1, int(e.get("SENSOR_MAX_TLS_PER_IP", "3"))),
            tls_deadline=num("SENSOR_TLS_DEADLINE", "10"),
            new_conn_per_sec_per_ip=num("SENSOR_NEW_CONN_PER_SEC_PER_IP", "3"),
            new_conn_burst_per_ip=num("SENSOR_NEW_CONN_BURST_PER_IP", "40"),
            global_new_conn_per_sec=num("SENSOR_GLOBAL_NEW_CONN_PER_SEC", "200"),
            accept_any=e.get("SENSOR_MSSQL_ACCEPT_ANY", "false").strip().lower() == "true",
            version=version,
            data_dir=e.get("SENSOR_DATA_DIR", "/data"),
            max_connections=max(1, int(e.get("SENSOR_MAX_CONNECTIONS", "200"))),
            max_per_ip=max(1, int(e.get("SENSOR_MAX_PER_IP", "8"))),
            first_data_timeout=num("SENSOR_FIRST_DATA_TIMEOUT", "15"),
            idle_timeout=num("SENSOR_IDLE_TIMEOUT", "45"),
            max_session=num("SENSOR_MAX_SESSION", "240"),
            write_timeout=num("SENSOR_WRITE_TIMEOUT", "10"),
            max_commands=max(1, int(e.get("SENSOR_MAX_COMMANDS", "1000"))),
            max_bytes_in=max(1024, int(e.get("SENSOR_MAX_BYTES_IN", str(2 * 1024 * 1024)))),
            max_buffered=max(1024, int(e.get("SENSOR_MAX_BUFFERED", str(12 * 1024 * 1024)))),
            memory_limit=max(1 << 20, int(e.get("SENSOR_MEMORY_LIMIT", str(256 * 1024 * 1024)))),
            sessions_per_sec_per_ip=num("SENSOR_SESSIONS_PER_SEC_PER_IP", "2"),
            global_sessions_per_sec=num("SENSOR_GLOBAL_SESSIONS_PER_SEC", "50"),
            global_events_per_sec=num("SENSOR_GLOBAL_EVENTS_PER_SEC", "200"),
            priority_events_per_sec=num("SENSOR_PRIORITY_EVENTS_PER_SEC", "300"),
            disconnect_events_per_sec=num("SENSOR_DISCONNECT_EVENTS_PER_SEC", "60"),
        )

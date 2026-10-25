"""Runtime configuration, read from environment variables.

``REDIS_HOST``, ``REDIS_PORT``, ``REDIS_USER`` and ``REDIS_PASSWORD`` belong to the event
publisher (the Redis *stream* server), so the tunables of the sensor itself use the
``SENSOR_`` prefix. Only ``REDIS_PUBLIC_PORT`` follows the shared naming scheme.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

from redis_sensor.identity import valid_version


@dataclass(frozen=True)
class Config:
    """All tunables of the sensor. Defaults are safe for an internet-facing deployment."""

    host: str = "0.0.0.0"  # noqa: S104 - listens inside a container
    port: int = 6379
    public_port: int = 6379  # dst_port reported in events, port reported by INFO
    version: str = ""  # "7.2" or "7.2.5"; empty: 7.2.x with a patch derived from the secret
    data_dir: str = "/data"
    max_connections: int = 200
    max_per_ip: int = 8
    first_data_timeout: float = 15.0  # nmap waits several seconds before its second probe
    idle_timeout: float = 45.0
    max_session: float = 240.0
    write_timeout: float = 10.0
    max_commands: int = 3000  # per connection
    max_bytes_in: int = 4 * 1024 * 1024  # per connection
    max_buffered: int = 32 * 1024 * 1024  # parser buffers of all connections together
    memory_limit: int = 256 * 1024 * 1024  # used when the cgroup reports no limit
    # Per-session event quotas (events beyond them are counted and reported at disconnect).
    quota_noisy: int = 20
    quota_commands: int = 50
    quota_priority: int = 100
    quota_logins: int = 50
    quota_downloads: int = 20
    quota_session_total: int = 300
    cpu_steps_per_sec_per_conn: float = 50_000.0  # glob/scan work units (see cpu.py)
    cpu_steps_per_sec_per_ip: float = 200_000.0
    cpu_steps_per_sec: float = 500_000.0
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
        version = e.get("SENSOR_REDIS_VERSION", "").strip()
        if version and not valid_version(version):
            raise ValueError("SENSOR_REDIS_VERSION must look like 7.2 or 7.2.5")

        def num(name: str, default: str) -> float:
            return float(e.get(name, default))

        return cls(
            port=int(e.get("SENSOR_PORT", "6379")),
            public_port=int(e.get("REDIS_PUBLIC_PORT", "6379")),
            version=version,
            data_dir=e.get("SENSOR_DATA_DIR", "/data"),
            max_connections=max(1, int(e.get("SENSOR_MAX_CONNECTIONS", "200"))),
            max_per_ip=max(1, int(e.get("SENSOR_MAX_PER_IP", "8"))),
            first_data_timeout=num("SENSOR_FIRST_DATA_TIMEOUT", "15"),
            idle_timeout=num("SENSOR_IDLE_TIMEOUT", "45"),
            max_session=num("SENSOR_MAX_SESSION", "240"),
            write_timeout=num("SENSOR_WRITE_TIMEOUT", "10"),
            max_commands=max(1, int(e.get("SENSOR_MAX_COMMANDS", "3000"))),
            max_bytes_in=max(1024, int(e.get("SENSOR_MAX_BYTES_IN", str(4 * 1024 * 1024)))),
            max_buffered=max(1024, int(e.get("SENSOR_MAX_BUFFERED", str(32 * 1024 * 1024)))),
            memory_limit=max(1 << 20, int(e.get("SENSOR_MEMORY_LIMIT", str(256 * 1024 * 1024)))),
            cpu_steps_per_sec_per_conn=num("SENSOR_CPU_STEPS_PER_CONN", "50000"),
            cpu_steps_per_sec_per_ip=num("SENSOR_CPU_STEPS_PER_IP", "200000"),
            cpu_steps_per_sec=num("SENSOR_CPU_STEPS_PER_SEC", "500000"),
            sessions_per_sec_per_ip=num("SENSOR_SESSIONS_PER_SEC_PER_IP", "2"),
            global_sessions_per_sec=num("SENSOR_GLOBAL_SESSIONS_PER_SEC", "50"),
            global_events_per_sec=num("SENSOR_GLOBAL_EVENTS_PER_SEC", "200"),
            priority_events_per_sec=num("SENSOR_PRIORITY_EVENTS_PER_SEC", "300"),
            disconnect_events_per_sec=num("SENSOR_DISCONNECT_EVENTS_PER_SEC", "60"),
        )

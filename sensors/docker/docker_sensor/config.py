"""Runtime configuration, read from environment variables."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

_HOSTNAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")


def _valid_hostname(value: str) -> bool:
    return 0 < len(value) <= 63 and value[0] != "-" and all(c in _HOSTNAME_CHARS for c in value)


def _valid_dotted(value: str, parts: int) -> bool:
    items = value.split(".")
    return len(items) == parts and all(i.isascii() and i.isdigit() and len(i) <= 3 for i in items)


@dataclass(frozen=True)
class Config:
    """All tunables of the sensor. Defaults are safe for an internet-facing deployment."""

    host: str = "0.0.0.0"  # noqa: S104 - listens inside a container
    port: int = 2375
    public_port: int = 2375  # dst_port reported in events
    hostname: str = "srv-app02"
    data_dir: str = "/data"

    # Identity of the fake daemon: Docker Engine 27.3 on Ubuntu 24.04, API 1.47.
    engine_version: str = "27.3.1"
    api_version: str = "1.47"
    min_api_version: str = "1.24"

    # Abuse resistance
    max_connections: int = 150
    max_per_ip: int = 8
    request_line_limit: int = 8190
    head_limit: int = 32 * 1024  # request line + headers
    max_headers: int = 64
    body_cap: int = 256 * 1024  # body bytes kept in memory for parsing
    body_total_max: int = 8 * 1024 * 1024  # bodies are read (and hashed) up to this size
    first_byte_timeout: float = 30.0
    head_timeout: float = 20.0
    body_timeout: float = 10.0  # one read
    body_min_rate: int = 500  # bytes/s once the body has been running for 5 s
    body_total_timeout: float = 60.0
    keepalive_timeout: float = 15.0
    max_requests_per_conn: int = 200
    max_connection_age: float = 300.0
    write_timeout: float = 10.0
    events_hold: float = 60.0  # GET /events stays open this long, like the real stream
    held_streams: int = 40  # open GET /events streams, sensor-wide
    held_streams_per_ip: int = 2
    stream_delay: float = 0.04  # pause between the lines of a streamed answer
    memory_budget: int = 96 * 1024 * 1024
    memory_limit: int = 256 * 1024 * 1024  # used when the cgroup has no memory limit
    memory_refuse: float = 0.70
    memory_shed: float = 0.85
    conn_rate: float = 5.0  # new connections per second per IP
    conn_burst: float = 20.0
    json_max_depth: int = 24
    # CPU seconds per second of event-loop time: the sensor has 0.5 CPU, so the global rate
    # leaves headroom for I/O. Empty buckets make a connection wait, never fail.
    cpu_global_rate: float = 0.35
    cpu_global_burst: float = 0.25
    cpu_ip_rate: float = 0.10
    cpu_ip_burst: float = 0.2
    cpu_conn_rate: float = 0.05
    cpu_conn_burst: float = 0.1
    state_ips: int = 512  # source IPs whose created containers / execs are remembered
    state_per_ip: int = 8
    state_execs: int = 16
    state_bytes: int = 8 * 1024 * 1024  # all remembered state together (LRU eviction)
    state_ttl: float = 3600.0

    # Events
    events_per_sec: float = 20.0
    events_burst: float = 100.0
    event_queue_size: int = 5000
    event_queue_bytes: int = 4 * 1024 * 1024
    global_events_per_sec: float = 200.0
    important_per_ip_rate: float = 20.0
    important_per_ip_burst: float = 200.0
    quiet_loopback: bool = True  # no events for 127.0.0.1 (the container healthcheck)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Config:
        e = os.environ if env is None else env
        hostname = e.get("DOCKER_HOSTNAME", "srv-app02")
        if not _valid_hostname(hostname):
            raise ValueError("DOCKER_HOSTNAME must be a plain host label")
        engine = e.get("DOCKER_ENGINE_VERSION", "27.3.1")
        if not _valid_dotted(engine, 3) or not engine.startswith("27."):
            raise ValueError("DOCKER_ENGINE_VERSION must look like 27.3.1")
        return cls(
            port=int(e.get("DOCKER_PORT", "2375")),
            public_port=int(e.get("DOCKER_PUBLIC_PORT", "2375")),
            hostname=hostname,
            data_dir=e.get("DOCKER_DATA_DIR", "/data"),
            engine_version=engine,
            max_connections=max(1, int(e.get("DOCKER_MAX_CONNECTIONS", "150"))),
            max_per_ip=max(1, int(e.get("DOCKER_MAX_PER_IP", "8"))),
            memory_budget=max(1, int(e.get("DOCKER_MEMORY_BUDGET_MB", "96"))) * 1024 * 1024,
            memory_limit=max(32, int(e.get("DOCKER_MEMORY_LIMIT_MB", "256"))) * 1024 * 1024,
            conn_rate=float(e.get("DOCKER_CONN_RATE", "5")),
            conn_burst=float(e.get("DOCKER_CONN_BURST", "20")),
            events_per_sec=float(e.get("DOCKER_EVENTS_PER_SEC", "20")),
            global_events_per_sec=float(e.get("DOCKER_GLOBAL_EVENTS_PER_SEC", "200")),
        )

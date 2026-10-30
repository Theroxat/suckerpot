"""Runtime configuration, read from environment variables."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

DSM_VERSION = "7.2.1-69057-11"  # one update below the fix (7.2.1-69057-12)


@dataclass(frozen=True)
class Config:
    """All tunables of the sensor. Defaults are safe for an internet-facing deployment."""

    host: str = "0.0.0.0"  # noqa: S104 - listens inside a container
    http_port: int = 5000
    https_port: int = 5001
    http_public_port: int = 5000  # dst_port reported in events, and in redirects
    https_public_port: int = 5001
    data_dir: str = "/data"
    http_redirect: bool = False  # redirect the HTTP port to HTTPS (DSM's "Automatically redirect")

    dsm_version: str = DSM_VERSION

    # Abuse resistance
    max_connections: int = 200
    max_per_ip: int = 8
    request_line_limit: int = 8190
    head_limit: int = 16 * 1024  # request line + headers
    max_headers: int = 64
    body_cap: int = 128 * 1024  # body bytes kept in memory for parsing
    body_total_max: int = 4 * 1024 * 1024  # bodies are read (and hashed) up to this size
    first_byte_timeout: float = 30.0
    head_timeout: float = 15.0
    body_timeout: float = 10.0  # one read
    body_min_rate: int = 500  # bytes/s once the body has been running for 5 s
    body_total_timeout: float = 45.0
    keepalive_timeout: float = 15.0
    tls_handshake_timeout: float = 4.0
    tls_hello_timeout: float = 2.0  # time to deliver a complete ClientHello record
    max_requests_per_conn: int = 100
    max_connection_age: float = 180.0
    write_timeout: float = 10.0
    memory_budget: int = 80 * 1024 * 1024
    memory_limit: int = 160 * 1024 * 1024  # used when the cgroup has no memory limit
    memory_refuse: float = 0.70
    memory_shed: float = 0.85
    conn_rate: float = 5.0  # new connections per second per IP
    conn_burst: float = 20.0
    req_rate: float = 20.0  # requests per second per IP
    req_burst: float = 100.0
    tls_per_sec: float = 40.0  # TLS handshakes per second, sensor-wide
    tls_burst: float = 80.0
    tls_ip_rate: float = 1.0  # TLS handshakes per second per source IP
    tls_ip_burst: float = 5.0
    tls_reserve_rate: float = 5.0  # extra sensor-wide share for IPs with no recent handshakes
    tls_reserve_burst: float = 10.0
    tls_max_inflight: int = 64  # handshakes in progress at once
    tls_max_per_ip: int = 3  # handshakes in progress per source IP
    login_fail_limit: int = 12  # failures per IP before DSM answers "IP blocked" (407)
    login_fail_window: float = 300.0
    login_state_ips: int = 2048
    api_max_params: int = 64
    # CPU seconds per second of event-loop time (the sensor has 0.5 CPU).
    cpu_global_rate: float = 0.35
    cpu_global_burst: float = 0.25
    cpu_ip_rate: float = 0.10
    cpu_ip_burst: float = 0.2
    cpu_conn_rate: float = 0.05
    cpu_conn_burst: float = 0.1

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
        http_port = int(e.get("SYNOLOGY_HTTP_PORT", "5000"))
        https_port = int(e.get("SYNOLOGY_HTTPS_PORT", "5001"))
        return cls(
            http_port=http_port,
            https_port=https_port,
            http_public_port=int(e.get("SYNOLOGY_HTTP_PUBLIC_PORT", str(http_port))),
            https_public_port=int(e.get("SYNOLOGY_HTTPS_PUBLIC_PORT", str(https_port))),
            data_dir=e.get("SYNOLOGY_DATA_DIR", "/data"),
            http_redirect=e.get("SYNOLOGY_HTTP_REDIRECT", "false").lower() in ("1", "true", "yes"),
            max_connections=max(1, int(e.get("SYNOLOGY_MAX_CONNECTIONS", "200"))),
            max_per_ip=max(1, int(e.get("SYNOLOGY_MAX_PER_IP", "8"))),
            memory_limit=max(32, int(e.get("SYNOLOGY_MEMORY_LIMIT_MB", "160"))) * 1024 * 1024,
            memory_budget=max(1, int(e.get("SYNOLOGY_MEMORY_BUDGET_MB", "80"))) * 1024 * 1024,
            conn_rate=float(e.get("SYNOLOGY_CONN_RATE", "5")),
            conn_burst=float(e.get("SYNOLOGY_CONN_BURST", "20")),
            events_per_sec=float(e.get("SYNOLOGY_EVENTS_PER_SEC", "20")),
            global_events_per_sec=float(e.get("SYNOLOGY_GLOBAL_EVENTS_PER_SEC", "200")),
        )

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
    http_port: int = 8080
    https_port: int = 8443
    http_public_port: int = 80  # dst_port reported in events and shown in error pages
    https_public_port: int = 443
    hostname: str = "srv-web01"
    data_dir: str = "/data"

    # Identity of the fake stack. Ubuntu 24.04 ships Apache 2.4.58 and PHP 8.3.6; the PHP
    # build is below 8.3.36 so it looks vulnerable to PHP2Shell.
    server_token: str = "Apache/2.4.58 (Ubuntu)"  # noqa: S105 - a Server header, not a secret
    php_version: str = "8.3.6"
    expose_php: bool = True  # X-Powered-By on PHP responses (off in stock Ubuntu)
    wp_version: str = "6.8.1"
    pma_version: str = "5.2.1"
    upload_progress_name: str = "PHP_SESSION_UPLOAD_PROGRESS"

    # Abuse resistance
    max_connections: int = 200
    max_per_ip: int = 10
    max_tls_connections: int = 64  # TLS connections cost several times more memory
    request_line_limit: int = 8190
    header_line_limit: int = 8190
    max_headers: int = 100
    max_header_bytes: int = 128 * 1024
    body_cap: int = 1024 * 1024
    analysis_cap: int = 64 * 1024  # body bytes kept in memory for parsing and detection
    first_byte_timeout: float = 60.0
    header_timeout: float = 20.0
    header_timeout_max: float = 40.0
    body_timeout: float = 10.0
    body_min_rate: int = 500
    body_total_timeout: float = 120.0
    keepalive_timeout: float = 5.0
    keepalive_max: int = 100
    max_connection_age: float = 600.0
    write_timeout: float = 30.0
    write_chunk_timeout: float = 10.0  # each 64 KB chunk must drain in this time (min rate)
    write_chunk: int = 64 * 1024
    handshake_timeout: float = 10.0
    memory_budget: int = 96 * 1024 * 1024
    memory_limit: int = 256 * 1024 * 1024  # used when the cgroup has no memory limit
    memory_refuse: float = 0.70  # fraction of the limit: refuse new connections
    memory_shed: float = 0.85  # fraction of the limit: abort the most expensive connections
    conn_rate: float = 5.0  # new connections per second per IP (checked before any TLS work)
    conn_burst: float = 20.0

    # Events
    events_per_sec: float = 20.0
    events_burst: float = 100.0
    event_queue_size: int = 5000
    event_queue_bytes: int = 4 * 1024 * 1024  # JSON size of the queued events
    global_events_per_sec: float = 200.0
    quiet_loopback: bool = True  # no events for 127.0.0.1 (the container healthcheck)
    xmlrpc_max_calls: int = 200
    important_per_ip_rate: float = 20.0
    important_per_ip_burst: float = 200.0

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Config:
        e = os.environ if env is None else env
        hostname = e.get("WEB_HOSTNAME", "srv-web01")
        if not _valid_hostname(hostname):
            raise ValueError("WEB_HOSTNAME must be a plain host label")
        php = e.get("WEB_PHP_VERSION", "8.3.6")
        parts = php.split(".")
        if (
            len(parts) != 3
            or parts[:2] != ["8", "3"]
            or not parts[2].isdigit()
            or not 0 <= int(parts[2]) < 36
        ):
            raise ValueError("WEB_PHP_VERSION must be 8.3.N with N below 36 (the vulnerable range)")
        token = e.get("WEB_SERVER_TOKEN", "Apache/2.4.58 (Ubuntu)")
        if not token.startswith("Apache/2.4.") or len(token) > 80 or not token.isprintable():
            raise ValueError("WEB_SERVER_TOKEN must look like 'Apache/2.4.N (Ubuntu)'")
        wp = e.get("WEB_WP_VERSION", "6.8.1")
        if not _valid_dotted(wp, 3):
            raise ValueError("WEB_WP_VERSION must look like 6.8.1")
        pma = e.get("WEB_PMA_VERSION", "5.2.1")
        if not _valid_dotted(pma, 3):
            raise ValueError("WEB_PMA_VERSION must look like 5.2.1")
        field = e.get("WEB_UPLOAD_PROGRESS_NAME", "PHP_SESSION_UPLOAD_PROGRESS")
        if not field or len(field) > 64 or not field.isascii() or not field.isprintable():
            raise ValueError("WEB_UPLOAD_PROGRESS_NAME must be a short printable ASCII name")
        return cls(
            http_port=int(e.get("WEB_HTTP_PORT", "8080")),
            https_port=int(e.get("WEB_HTTPS_PORT", "8443")),
            http_public_port=int(e.get("WEB_HTTP_PUBLIC_PORT", "80")),
            https_public_port=int(e.get("WEB_HTTPS_PUBLIC_PORT", "443")),
            hostname=hostname,
            data_dir=e.get("WEB_DATA_DIR", "/data"),
            server_token=token,
            php_version=php,
            expose_php=e.get("WEB_EXPOSE_PHP", "true").lower() in ("1", "true", "yes", "on"),
            wp_version=wp,
            pma_version=pma,
            upload_progress_name=field,
            max_connections=max(1, int(e.get("WEB_MAX_CONNECTIONS", "200"))),
            max_per_ip=max(1, int(e.get("WEB_MAX_PER_IP", "10"))),
            max_tls_connections=max(1, int(e.get("WEB_MAX_TLS_CONNECTIONS", "64"))),
            memory_budget=max(1, int(e.get("WEB_MEMORY_BUDGET_MB", "96"))) * 1024 * 1024,
            memory_limit=max(32, int(e.get("WEB_MEMORY_LIMIT_MB", "256"))) * 1024 * 1024,
            conn_rate=float(e.get("WEB_CONN_RATE", "5")),
            conn_burst=float(e.get("WEB_CONN_BURST", "20")),
            events_per_sec=float(e.get("WEB_EVENTS_PER_SEC", "20")),
            write_chunk_timeout=float(e.get("WEB_WRITE_CHUNK_TIMEOUT", "10")),
            global_events_per_sec=float(e.get("WEB_GLOBAL_EVENTS_PER_SEC", "200")),
        )

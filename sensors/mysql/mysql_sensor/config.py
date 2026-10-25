"""Runtime configuration, read from environment variables.

Tunables are ``SENSOR_*`` variables (``SENSOR_PORT``, ``SENSOR_MYSQL_VERSION``, ...). The older
``MYSQL_*`` spelling is still read when the ``SENSOR_*`` one is absent. ``MYSQL_PUBLIC_PORT``
(set by compose from the host port) and the ``REDIS_*`` publisher variables keep their names.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field

_HOST_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
DEFAULT_ACCOUNTS = "root:,root:root,admin:admin,mysql:mysql"
DEFAULT_VERSION = "8.0.43-0ubuntu0.24.04.2"
PLUGINS = ("mysql_native_password", "caching_sha2_password")
MAX_ACCOUNTS = 64
MAX_PASSWORD_BYTES = 128


def _bool(raw: str) -> bool:
    return raw.strip().lower() in ("1", "true", "yes", "on")


def valid_hostname(name: str) -> bool:
    return 0 < len(name) <= 32 and not name.startswith("-") and set(name) <= _HOST_CHARS


def parse_accounts(raw: str) -> dict[str, tuple[bytes, ...]]:
    """``user:password`` pairs separated by commas; an empty password is allowed.

    The same user may appear several times with different passwords. Passwords containing a
    comma are not supported.
    """
    accounts: dict[str, list[bytes]] = {}
    count = 0
    for item in raw.split(","):
        if not item.strip() or ":" not in item:
            continue
        user, _, password = item.partition(":")
        user = user.strip()
        pw = password.encode("utf-8")[:MAX_PASSWORD_BYTES]
        if not user or count >= MAX_ACCOUNTS:
            continue
        bucket = accounts.setdefault(user, [])
        if pw not in bucket:
            bucket.append(pw)
            count += 1
    return {u: tuple(p) for u, p in accounts.items()}


def _env(e: Mapping[str, str], name: str, default: str, legacy: str | None = None) -> str:
    """``SENSOR_<name>`` first, then the legacy ``MYSQL_<name>`` (or ``legacy``) name."""
    for key in (f"SENSOR_{name}", legacy or f"MYSQL_{name}"):
        if key in e:
            return e[key]
    return default


@dataclass(frozen=True)
class Config:
    """All tunables of the sensor. Defaults are safe for an internet-facing deployment."""

    host: str = "0.0.0.0"  # noqa: S104 - listens inside a container
    port: int = 3306
    public_port: int = 3306  # dst_port reported in events
    version: str = DEFAULT_VERSION
    hostname: str = ""  # empty: derived from the per-deployment secret
    data_dir: str = "/data"
    default_plugin: str = "caching_sha2_password"
    accounts: Mapping[str, tuple[bytes, ...]] = field(
        default_factory=lambda: parse_accounts(DEFAULT_ACCOUNTS)
    )
    clear_password_switch: bool = False  # ask clients for mysql_clear_password (PAM-like)
    enable_tls: bool = True
    max_connections: int = 200
    max_per_ip: int = 8
    handshake_timeout: float = 10.0  # waiting for the client's HandshakeResponse
    packet_timeout: float = 10.0  # base time to receive one packet once it started
    min_rate: int = 16 * 1024  # bytes/s granted on top of packet_timeout for large packets
    max_packet_extra: float = 60.0  # cap of the extra time min_rate grants to huge packets
    write_timeout: float = 10.0
    idle_timeout: float = 120.0  # between two commands
    max_session: float = 600.0  # hard cap on one connection
    max_packet: int = 64 * 1024 * 1024  # emulated max_allowed_packet (the 8.0 default)
    max_handshake_packet: int = 64 * 1024  # larger first packets are not MySQL clients
    max_input_bytes: int = 8 * 1024 * 1024  # read from one client, all packets together
    max_output_bytes: int = 4 * 1024 * 1024  # sent to one client
    max_commands: int = 1000
    max_auth_attempts: int = 3
    capture_bytes: int = 16 * 1024  # bytes of one query that are kept and analysed
    conn_cost: int = 192 * 1024  # budgeted memory per connection (measured under abuse: ~175 KiB)
    memory_budget: int = 64 * 1024 * 1024  # 200 x (conn_cost + pending output) fits
    memory_limit: int = 256 * 1024 * 1024  # fallback when cgroup limits are not visible
    output_cap: int = 64 * 1024  # pending output bytes (built + in the transport) per connection
    tls_per_sec_per_ip: float = 5.0
    tls_burst_per_ip: float = 20.0
    tls_global_per_sec: float = 30.0  # TLS handshakes started per second, all sources
    tls_global_burst: float = 60.0
    max_tls_handshakes: int = 16
    rsa_per_sec_per_ip: float = 3.0
    rsa_burst_per_ip: float = 10.0
    rsa_per_sec: float = 30.0  # RSA decryptions (full caching_sha2 auth) overall
    connections_per_sec_per_ip: float = 25.0  # new connections per source, before the handshake
    connections_burst_per_ip: float = 50.0
    refusal_delay: float = 1.0  # a rate-limited connection waits this long before its 1129
    sessions_per_sec_per_ip: float = 2.0
    global_sessions_per_sec: float = 50.0
    global_events_per_sec: float = 200.0  # hard ceiling for every event but the aggregates
    routine_events_per_sec: float = 100.0  # share of the ceiling routine events may use
    important_events_per_sec_per_ip: float = 10.0  # logins, flagged queries, downloads
    important_events_burst_per_ip: float = 50.0
    disconnect_events_per_sec: float = 40.0
    session_command_events: int = 60  # plain command events recorded per connection
    session_important_events: int = 100  # flagged commands + logins per connection
    session_download_events: int = 10
    event_queue_size: int = 5000
    important_queue_size: int = 1000
    summary_interval: float = 60.0
    quiet_loopback: bool = True  # no events for 127.0.0.1 / ::1 (the container healthcheck)
    # CPU. A "step" is one row examined; a full scan of the biggest fake table is about 5,300.
    query_steps: int = 6000  # work budget of one COM_QUERY, all its statements together
    cpu_steps_per_sec_conn: float = 20_000.0
    cpu_steps_burst_conn: float = 12_000.0
    cpu_steps_per_sec_ip: float = 30_000.0
    cpu_steps_burst_ip: float = 18_000.0
    cpu_steps_per_sec_all: float = 60_000.0
    cpu_steps_burst_all: float = 36_000.0
    cpu_max_delay: float = 5.0  # a longer wait for CPU tokens closes the connection instead
    sleep_per_query: float = 10.0  # seconds of SLEEP() honoured in one COM_QUERY
    sleep_per_connection: float = 30.0

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Config:
        e = os.environ if env is None else env
        hostname = _env(e, "HOSTNAME", "").strip().lower()
        if hostname and not valid_hostname(hostname):
            raise ValueError("SENSOR_HOSTNAME must be a plain host name (letters, digits, '-')")
        plugin = _env(e, "DEFAULT_PLUGIN", "caching_sha2_password").strip()
        if plugin not in PLUGINS:
            raise ValueError(f"SENSOR_DEFAULT_PLUGIN must be one of {PLUGINS}")
        version = _env(e, "MYSQL_VERSION", DEFAULT_VERSION, "MYSQL_VERSION").strip()
        if not version.startswith("8.0.") or not version.isascii() or len(version) > 40:
            raise ValueError("SENSOR_MYSQL_VERSION must be an ASCII 8.0.x version string")

        def num(name: str, default: float) -> float:
            return float(_env(e, name, str(default)))

        return cls(
            port=int(num("PORT", 3306)),
            public_port=int(e.get("MYSQL_PUBLIC_PORT", "3306")),
            version=version,
            hostname=hostname,
            data_dir=_env(e, "DATA_DIR", "/data"),
            default_plugin=plugin,
            accounts=parse_accounts(_env(e, "MYSQL_ACCOUNTS", DEFAULT_ACCOUNTS, "MYSQL_ACCOUNTS")),
            clear_password_switch=_bool(_env(e, "CLEAR_PASSWORD_SWITCH", "false")),
            enable_tls=_bool(_env(e, "ENABLE_TLS", "true")),
            max_connections=max(1, int(num("MAX_CONNECTIONS", 200))),
            max_per_ip=max(1, int(num("MAX_PER_IP", 8))),
            handshake_timeout=num("HANDSHAKE_TIMEOUT", 10),
            idle_timeout=num("IDLE_TIMEOUT", 120),
            max_session=num("MAX_SESSION", 600),
            max_auth_attempts=max(1, int(num("MAX_AUTH_ATTEMPTS", 3))),
            max_commands=max(1, int(num("MAX_COMMANDS", 1000))),
            memory_limit=int(num("MEMORY_LIMIT", 256 * 1024 * 1024)),
            sessions_per_sec_per_ip=num("SESSIONS_PER_SEC_PER_IP", 2),
            global_sessions_per_sec=num("GLOBAL_SESSIONS_PER_SEC", 50),
            global_events_per_sec=num("GLOBAL_EVENTS_PER_SEC", 200),
            routine_events_per_sec=num("ROUTINE_EVENTS_PER_SEC", 100),
            important_events_per_sec_per_ip=num("IMPORTANT_EVENTS_PER_SEC_PER_IP", 10),
            disconnect_events_per_sec=num("DISCONNECT_EVENTS_PER_SEC", 40),
            connections_per_sec_per_ip=num("CONNECTIONS_PER_SEC_PER_IP", 25),
            tls_per_sec_per_ip=num("TLS_PER_SEC_PER_IP", 5),
            tls_burst_per_ip=num("TLS_BURST_PER_IP", 20),
            tls_global_per_sec=num("TLS_GLOBAL_PER_SEC", 30),
            max_tls_handshakes=max(1, int(num("MAX_TLS_HANDSHAKES", 16))),
            rsa_per_sec=num("RSA_PER_SEC", 30),
            rsa_per_sec_per_ip=num("RSA_PER_SEC_PER_IP", 3),
            query_steps=max(100, int(num("QUERY_STEPS", 6000))),
        )

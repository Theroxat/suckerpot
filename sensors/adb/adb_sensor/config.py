"""Runtime configuration, read from environment variables."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}$")
BUSYBOX_MODES = ("auto", "yes", "no")
MAX_MAXDATA = 256 * 1024


@dataclass(frozen=True)
class Config:
    """All tunables of the sensor. Defaults are safe for an internet-facing deployment."""

    host: str = "0.0.0.0"  # noqa: S104 - listens inside a container
    port: int = 5555
    public_port: int = 5555  # dst_port reported in events (the port attackers connect to)
    data_dir: str = "/data"
    hostname: str = ""  # reserved: the Android shell hostname is derived from the profile
    busybox: str = "auto"  # auto: decided by the deployment secret; yes / no
    root_shell: bool = True  # misconfigured boxes run adbd as root (ro.secure=0)
    maxdata: int = MAX_MAXDATA  # advertised in CNXN; payloads above it close the connection
    max_connections: int = 100
    max_per_ip: int = 5
    handshake_timeout: float = 20.0  # from connect to the first valid CNXN
    message_timeout: float = 30.0  # one message (header + payload) must complete within this
    idle_timeout: float = 300.0
    max_session: float = 1800.0
    write_timeout: float = 10.0
    max_streams: int = 8  # concurrent streams per connection
    max_streams_total: int = 200  # OPENs per connection, ever
    max_input_bytes: int = 24 * 1024 * 1024  # per connection, push/install payloads included
    max_hash_bytes: int = 16 * 1024 * 1024  # pushed/installed bytes hashed per connection
    max_stub_bytes: int = 8 * 1024  # bytes of a pushed file kept in the (in-memory) fake fs
    max_output_per_line: int = 64 * 1024
    max_session_output: int = 2 * 1024 * 1024
    max_fs_bytes: int = 1024 * 1024
    max_fs_nodes: int = 2000
    max_commands: int = 2000
    max_line: int = 4096
    line_budget: float = 0.15
    shell_cpu_share: float = 0.3  # shell CPU-seconds per wall second, all sessions together
    shell_cpu_burst: float = 0.2
    memory_budget: int = 112 * 1024 * 1024
    command_delay: bool = True
    events_per_sec: float = 20.0
    events_burst: float = 40.0
    event_queue_size: int = 5000
    noisy_events_per_sec: float = 5.0
    global_events_per_sec: float = 200.0
    conn_rate_per_ip: float = 1.0  # new connections per second per source IP (token bucket)
    conn_burst_per_ip: float = 10.0
    summary_interval: float = 60.0
    quiet_loopback: bool = True  # no events for 127.0.0.1 (the container healthcheck)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Config:
        e = os.environ if env is None else env

        def g(name: str, default: str) -> str:
            """SENSOR_<NAME>, falling back to the older ADB_<NAME>."""
            return e.get(f"SENSOR_{name}", e.get(f"ADB_{name}", default))

        hostname = g("HOSTNAME", "")
        if hostname and not _HOSTNAME_RE.match(hostname):
            raise ValueError("ADB_HOSTNAME must be a plain host label")
        busybox = g("BUSYBOX", "auto").lower()
        if busybox not in BUSYBOX_MODES:
            raise ValueError(f"ADB_BUSYBOX must be one of {', '.join(BUSYBOX_MODES)}")
        if "honeypot" in hostname.lower() or "suckerpot" in hostname.lower():
            raise ValueError("ADB_HOSTNAME must not give the sensor away")
        return cls(
            port=int(g("PORT", "5555")),
            public_port=int(g("PUBLIC_PORT", "5555")),
            data_dir=g("DATA_DIR", "/data"),
            hostname=hostname,
            busybox=busybox,
            root_shell=g("ROOT_SHELL", "true").lower() not in ("0", "false", "no"),
            maxdata=min(MAX_MAXDATA, max(4096, int(g("MAXDATA", str(MAX_MAXDATA))))),
            max_connections=max(1, int(g("MAX_CONNECTIONS", "100"))),
            max_per_ip=max(1, int(g("MAX_PER_IP", "5"))),
            handshake_timeout=float(g("HANDSHAKE_TIMEOUT", "20")),
            message_timeout=float(g("MESSAGE_TIMEOUT", "30")),
            idle_timeout=float(g("IDLE_TIMEOUT", "300")),
            max_session=float(g("MAX_SESSION", "1800")),
            max_streams=max(1, int(g("MAX_STREAMS", "8"))),
            max_streams_total=max(1, int(g("MAX_STREAMS_TOTAL", "200"))),
            max_input_bytes=max(1, int(g("MAX_INPUT_MB", "24"))) * 1024 * 1024,
            max_hash_bytes=max(1, int(g("MAX_HASH_MB", "16"))) * 1024 * 1024,
            max_commands=max(1, int(g("MAX_COMMANDS", "2000"))),
            line_budget=float(g("LINE_BUDGET", "0.15")),
            shell_cpu_share=min(0.9, max(0.05, float(g("SHELL_CPU_SHARE", "0.3")))),
            memory_budget=max(1, int(g("MEMORY_BUDGET_MB", "112"))) * 1024 * 1024,
            events_per_sec=float(g("EVENTS_PER_SEC", "20")),
            global_events_per_sec=float(g("GLOBAL_EVENTS_PER_SEC", "200")),
            conn_rate_per_ip=max(0.01, float(g("CONN_RATE_PER_IP", "1"))),
            conn_burst_per_ip=max(1.0, float(g("CONN_BURST_PER_IP", "10"))),
            summary_interval=max(5.0, float(g("SUMMARY_INTERVAL", "60"))),
        )

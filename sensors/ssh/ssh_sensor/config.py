"""Runtime configuration, read from environment variables."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

DEFAULT_BANNER = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14"
DEFAULT_CREDENTIALS = (
    "root:root,root:123456,root:password,admin:admin,ubuntu:ubuntu,pi:raspberry,user:user"
)
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}$")


def parse_credentials(raw: str) -> frozenset[tuple[str, str]]:
    """Parse ``user:pass,user:pass``. The password may contain ``:`` (split on the first one)."""
    pairs: set[tuple[str, str]] = set()
    for item in raw.split(","):
        item = item.strip()
        if not item or ":" not in item:
            continue
        user, _, password = item.partition(":")
        if user:
            pairs.add((user, password))
    return frozenset(pairs)


def _fraction(raw: str, lo: float, hi: float) -> float:
    return min(hi, max(lo, float(raw)))


@dataclass(frozen=True)
class Config:
    """All tunables of the sensor. Defaults are safe for an internet-facing deployment."""

    host: str = "0.0.0.0"  # noqa: S104 - listens inside a container
    port: int = 2222
    public_port: int = 22  # dst_port reported in events (the port attackers connect to)
    banner: str = DEFAULT_BANNER
    hostname: str = "srv-web01"
    hostkey_dir: str = "/data/host_keys"
    accept_credentials: frozenset[tuple[str, str]] = field(
        default_factory=lambda: parse_credentials(DEFAULT_CREDENTIALS), repr=False
    )
    accept_random_prob: float = 0.0
    max_auth_attempts: int = 6
    auth_fail_delay: tuple[float, float] = (0.4, 1.2)
    max_connections: int = 200
    max_per_ip: int = 5
    login_timeout: float = 30.0
    idle_timeout: float = 300.0
    max_session: float = 1800.0
    max_line: int = 4096
    max_output_per_line: int = 64 * 1024
    max_session_output: int = 2 * 1024 * 1024
    max_fs_bytes: int = 1024 * 1024
    max_fs_nodes: int = 2000
    events_per_sec: float = 20.0
    events_burst: float = 40.0
    event_queue_size: int = 5000
    fake_ip: str = ""
    command_delay: bool = True
    max_channels: int = 2
    max_commands: int = 5000
    max_refused_requests: int = 20
    line_budget: float = 0.15
    memory_budget: int = 48 * 1024 * 1024
    global_events_per_sec: float = 200.0
    conn_rate_per_ip: float = 1.0  # new connections per second per source IP (token bucket)
    conn_burst_per_ip: float = 10.0
    summary_interval: float = 60.0  # seconds between per-IP connection summary events
    noisy_events_per_sec: float = 5.0
    # SSH channel flow control: what a client may send before the shell has read it. Every
    # channel buffers at most about twice this (asyncssh channel + stream buffers).
    channel_window: int = 32 * 1024
    max_pktsize: int = 32 * 1024

    @property
    def max_pending_input(self) -> int:
        """Unread input per channel beyond which the session is closed (backstop)."""
        return 4 * self.channel_window + self.max_pktsize

    # process memory guard (cgroup memory.current / memory.max, else RSS / memory_limit)
    memory_limit: int = 256 * 1024 * 1024
    memory_pressure: float = 0.70  # refuse new sessions, stop reading the biggest channels
    memory_critical: float = 0.85  # close the biggest sessions
    memory_share_per_ip: float = 0.25  # share of memory_budget one source IP may hold
    # shell CPU-seconds per wall second, all sessions together (fair across source IPs)
    shell_cpu_share: float = 0.3
    shell_cpu_burst: float = 0.2
    # event byte budgets (approximate JSON size of the event data)
    ip_event_bytes_per_sec: float = 20_000.0
    ip_event_bytes_burst: float = 1_000_000.0
    global_event_bytes_per_sec: float = 200_000.0
    global_event_bytes_burst: float = 2_000_000.0
    event_queue_bytes: int = 8 * 1024 * 1024
    # inbound SSH traffic (bytes read from sockets): every packet costs a decryption, so tiny
    # packets in a flood cost CPU however small the data is. Over budget, the connection's
    # socket is not read for a while (TCP pushes back on the client).
    inbound_bytes_per_sec: float = 256 * 1024.0  # sensor-wide
    inbound_bytes_burst: float = 1024 * 1024.0
    inbound_conn_bytes_per_sec: float = 32 * 1024.0  # per connection
    inbound_conn_bytes_burst: float = 256 * 1024.0
    recv_buffer: int = 64 * 1024  # SO_RCVBUF of the listening socket (inherited)
    stats_interval: float = 60.0  # seconds between "stats" log lines
    os_version: str = "24.04.4"
    kernel: str = "6.8.0-100-generic"
    kernel_build: str = "#100-Ubuntu SMP PREEMPT_DYNAMIC Tue Sep  8 15:11:32 UTC 2026"
    quiet_loopback: bool = True  # no events for 127.0.0.1 (the container healthcheck)

    @property
    def software_version(self) -> str:
        """The part of the banner after ``SSH-2.0-`` (what asyncssh wants)."""
        return self.banner.removeprefix("SSH-2.0-")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Config:
        e = os.environ if env is None else env
        hostname = e.get("SSH_HOSTNAME", "srv-web01")
        if not _HOSTNAME_RE.match(hostname):
            raise ValueError("SSH_HOSTNAME must be a plain host label")
        banner = e.get("SSH_BANNER", DEFAULT_BANNER)
        if not banner.startswith("SSH-2.0-") or len(banner) > 100 or not banner.isprintable():
            raise ValueError("SSH_BANNER must look like 'SSH-2.0-<software>'")
        prob = float(e.get("SSH_ACCEPT_RANDOM_PROB", "0.0"))
        if not 0.0 <= prob <= 1.0:
            raise ValueError("SSH_ACCEPT_RANDOM_PROB must be within [0, 1]")
        return cls(
            port=int(e.get("SSH_PORT", "2222")),
            public_port=int(e.get("SSH_PUBLIC_PORT", "22")),
            banner=banner,
            hostname=hostname,
            hostkey_dir=e.get("SSH_HOSTKEY_DIR", "/data/host_keys"),
            accept_credentials=parse_credentials(
                e.get("SSH_ACCEPT_CREDENTIALS", DEFAULT_CREDENTIALS)
            ),
            accept_random_prob=prob,
            max_auth_attempts=max(1, int(e.get("SSH_MAX_AUTH_ATTEMPTS", "6"))),
            max_connections=max(1, int(e.get("SSH_MAX_CONNECTIONS", "200"))),
            max_per_ip=max(1, int(e.get("SSH_MAX_PER_IP", "5"))),
            login_timeout=float(e.get("SSH_LOGIN_TIMEOUT", "30")),
            idle_timeout=float(e.get("SSH_IDLE_TIMEOUT", "300")),
            max_session=float(e.get("SSH_MAX_SESSION", "1800")),
            max_line=max(64, int(e.get("SSH_MAX_LINE", "4096"))),
            events_per_sec=float(e.get("SSH_EVENTS_PER_SEC", "20")),
            fake_ip=e.get("SSH_FAKE_IP", ""),
            max_commands=max(1, int(e.get("SSH_MAX_COMMANDS", "5000"))),
            line_budget=float(e.get("SSH_LINE_BUDGET", "0.15")),
            memory_budget=max(1, int(e.get("SSH_MEMORY_BUDGET_MB", "48"))) * 1024 * 1024,
            global_events_per_sec=float(e.get("SSH_GLOBAL_EVENTS_PER_SEC", "200")),
            conn_rate_per_ip=max(0.01, float(e.get("SSH_CONN_RATE_PER_IP", "1"))),
            conn_burst_per_ip=max(1.0, float(e.get("SSH_CONN_BURST_PER_IP", "10"))),
            summary_interval=max(5.0, float(e.get("SSH_SUMMARY_INTERVAL", "60"))),
            stats_interval=max(5.0, float(e.get("SSH_STATS_INTERVAL", "60"))),
            inbound_bytes_per_sec=max(
                16 * 1024.0, float(e.get("SSH_INBOUND_KB_PER_SEC", "256")) * 1024
            ),
            inbound_conn_bytes_per_sec=max(
                4 * 1024.0, float(e.get("SSH_INBOUND_CONN_KB_PER_SEC", "32")) * 1024
            ),
            channel_window=min(1 << 20, max(8, int(e.get("SSH_CHANNEL_WINDOW_KB", "32")))) * 1024,
            memory_limit=max(32, int(e.get("SSH_MEMORY_LIMIT_MB", "256"))) * 1024 * 1024,
            memory_pressure=_fraction(e.get("SSH_MEMORY_PRESSURE", "0.70"), 0.3, 0.95),
            memory_critical=_fraction(e.get("SSH_MEMORY_CRITICAL", "0.85"), 0.35, 0.98),
            memory_share_per_ip=_fraction(e.get("SSH_MEMORY_SHARE_PER_IP", "0.25"), 0.01, 1.0),
            shell_cpu_share=_fraction(e.get("SSH_SHELL_CPU_SHARE", "0.3"), 0.05, 0.9),
            shell_cpu_burst=_fraction(e.get("SSH_SHELL_CPU_BURST", "0.2"), 0.05, 2.0),
            ip_event_bytes_per_sec=max(1000.0, float(e.get("SSH_IP_EVENT_BYTES_PER_SEC", "20000"))),
            ip_event_bytes_burst=max(16_000.0, float(e.get("SSH_IP_EVENT_BYTES_BURST", "1000000"))),
            global_event_bytes_per_sec=max(
                10_000.0, float(e.get("SSH_GLOBAL_EVENT_BYTES_PER_SEC", "200000"))
            ),
            global_event_bytes_burst=max(
                100_000.0, float(e.get("SSH_GLOBAL_EVENT_BYTES_BURST", "2000000"))
            ),
            os_version=e.get("SSH_OS_VERSION", "24.04.4"),
            kernel=e.get("SSH_KERNEL", "6.8.0-100-generic"),
            kernel_build=e.get(
                "SSH_KERNEL_BUILD", "#100-Ubuntu SMP PREEMPT_DYNAMIC Tue Sep  8 15:11:32 UTC 2026"
            ),
        )

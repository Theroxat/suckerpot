"""Runtime configuration, read from environment variables."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

# The classic Mirai dictionary, trimmed. "user:pass" pairs; the password may contain ':'.
DEFAULT_CREDENTIALS = (
    "root:xc3511,root:vizxv,root:admin,admin:admin,root:888888,root:default,"
    "root:123456,support:support,root:root,user:user,admin:1234"
)
PERSONALITIES = ("dvr", "router")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}$")


def parse_credentials(raw: str) -> frozenset[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for item in raw.split(","):
        item = item.strip()
        if not item or ":" not in item:
            continue
        user, _, password = item.partition(":")
        if user:
            pairs.add((user, password))
    return frozenset(pairs)


def unescape(text: str) -> str:
    """Turn the two-character sequences ``\\r`` and ``\\n`` of an env value into controls."""
    return text.replace("\\r", "\r").replace("\\n", "\n")


@dataclass(frozen=True)
class Config:
    """All tunables of the sensor. Defaults are safe for an internet-facing deployment."""

    host: str = "0.0.0.0"  # noqa: S104 - listens inside a container
    port: int = 2323
    public_port: int = 23  # dst_port reported in events (the port attackers connect to)
    personality: str = "dvr"
    hostname: str = ""  # empty: derived from the profile secret
    login_prompt: str = "{hostname} login: "
    prelogin_banner: str = ""
    motd: str = ""  # empty: the personality's BusyBox banner
    data_dir: str = "/data"
    accept_credentials: frozenset[tuple[str, str]] = field(
        default_factory=lambda: parse_credentials(DEFAULT_CREDENTIALS), repr=False
    )
    accept_random_prob: float = 0.0
    max_auth_attempts: int = 6
    auth_fail_delay: tuple[float, float] = (3.0, 3.0)  # BusyBox login's FAIL_DELAY
    max_empty_logins: int = 10
    max_connections: int = 200
    max_per_ip: int = 8
    login_timeout: float = 60.0
    idle_timeout: float = 300.0
    max_session: float = 1800.0
    write_timeout: float = 10.0
    max_line: int = 4096
    max_input_bytes: int = 1024 * 1024  # per connection, negotiation included
    max_output_per_line: int = 64 * 1024
    max_session_output: int = 2 * 1024 * 1024
    max_fs_bytes: int = 1024 * 1024
    max_fs_nodes: int = 2000
    max_commands: int = 2000
    line_budget: float = 0.15
    shell_cpu_share: float = 0.3  # shell CPU-seconds per wall second, all sessions together
    shell_cpu_burst: float = 0.2
    memory_budget: int = 48 * 1024 * 1024
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
        hostname = e.get("TELNET_HOSTNAME", "")
        if hostname and not _HOSTNAME_RE.match(hostname):
            raise ValueError("TELNET_HOSTNAME must be a plain host label")
        personality = e.get("TELNET_PERSONALITY", "dvr")
        if personality not in PERSONALITIES:
            raise ValueError(f"TELNET_PERSONALITY must be one of {', '.join(PERSONALITIES)}")
        prob = float(e.get("TELNET_ACCEPT_RANDOM_PROB", "0.0"))
        if not 0.0 <= prob <= 1.0:
            raise ValueError("TELNET_ACCEPT_RANDOM_PROB must be within [0, 1]")
        prompt = unescape(e.get("TELNET_LOGIN_PROMPT", "{hostname} login: "))
        banner = unescape(e.get("TELNET_PRELOGIN_BANNER", ""))
        motd = unescape(e.get("TELNET_MOTD", ""))
        for text in (prompt, banner, motd):
            if len(text) > 2048:
                raise ValueError("telnet banner texts are limited to 2048 characters")
        low = f"{prompt}{banner}{motd}{hostname}".lower()
        if "honeypot" in low or "suckerpot" in low:
            raise ValueError("banner texts must not give the sensor away")
        return cls(
            port=int(e.get("TELNET_PORT", "2323")),
            public_port=int(e.get("TELNET_PUBLIC_PORT", "23")),
            personality=personality,
            hostname=hostname,
            login_prompt=prompt,
            prelogin_banner=banner,
            motd=motd,
            data_dir=e.get("TELNET_DATA_DIR", "/data"),
            accept_credentials=parse_credentials(
                e.get("TELNET_ACCEPT_CREDENTIALS", DEFAULT_CREDENTIALS)
            ),
            accept_random_prob=prob,
            max_auth_attempts=max(1, int(e.get("TELNET_MAX_AUTH_ATTEMPTS", "6"))),
            max_connections=max(1, int(e.get("TELNET_MAX_CONNECTIONS", "200"))),
            max_per_ip=max(1, int(e.get("TELNET_MAX_PER_IP", "8"))),
            login_timeout=float(e.get("TELNET_LOGIN_TIMEOUT", "60")),
            idle_timeout=float(e.get("TELNET_IDLE_TIMEOUT", "300")),
            max_session=float(e.get("TELNET_MAX_SESSION", "1800")),
            max_line=max(64, int(e.get("TELNET_MAX_LINE", "4096"))),
            max_commands=max(1, int(e.get("TELNET_MAX_COMMANDS", "2000"))),
            line_budget=float(e.get("TELNET_LINE_BUDGET", "0.15")),
            shell_cpu_share=min(0.9, max(0.05, float(e.get("TELNET_SHELL_CPU_SHARE", "0.3")))),
            memory_budget=max(1, int(e.get("TELNET_MEMORY_BUDGET_MB", "48"))) * 1024 * 1024,
            events_per_sec=float(e.get("TELNET_EVENTS_PER_SEC", "20")),
            global_events_per_sec=float(e.get("TELNET_GLOBAL_EVENTS_PER_SEC", "200")),
            conn_rate_per_ip=max(0.01, float(e.get("TELNET_CONN_RATE_PER_IP", "1"))),
            conn_burst_per_ip=max(1.0, float(e.get("TELNET_CONN_BURST_PER_IP", "10"))),
            summary_interval=max(5.0, float(e.get("TELNET_SUMMARY_INTERVAL", "60"))),
        )

"""Collector and analyzer settings, read from the environment."""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

type Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _int(env: Mapping[str, str], key: str, default: int, lo: int, hi: int) -> int:
    try:
        value = int(env.get(key, "") or default)
    except ValueError:
        value = default
    return max(lo, min(hi, value))


def _flag(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _split(value: str) -> list[str]:
    return [p.strip() for p in value.split(",") if p.strip()]


def _networks(items: list[str]) -> tuple[Network, ...]:
    nets: list[Network] = []
    for item in items:
        try:
            nets.append(ipaddress.ip_network(item.strip("[]"), strict=False))
        except ValueError:
            continue
    return tuple(nets)


@dataclass(frozen=True)
class CollectorSettings:
    enabled: bool = False
    poll_s: int = 15
    max_bytes: int = 16 * 1024 * 1024
    timeout_s: int = 60
    connect_timeout_s: int = 10
    max_redirects: int = 3
    concurrency: int = 2
    host_interval_s: float = 10.0
    hourly_quota: int = 60
    daily_quota: int = 500
    refetch_hours: int = 24
    max_depth: int = 2
    quarantine_dir: Path = Path("/quarantine")
    quarantine_max_mb: int = 2048
    retention_days: int = 90
    rules_dir: Path = Path("/app/rules/yara")
    heartbeat_path: Path = Path("/tmp/heartbeat")  # noqa: S108  (tmpfs inside the container)
    analyzer_timeout_s: int = 60
    analyzer_memory_mb: int = 384
    deny_nets: tuple[Network, ...] = ()
    deny_hosts: tuple[str, ...] = field(default=())

    @property
    def quarantine_max_bytes(self) -> int:
        return self.quarantine_max_mb * 1024 * 1024

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> CollectorSettings:
        e = os.environ if env is None else env
        nets = _split(e.get("COLLECTOR_DENY_CIDRS", ""))
        # The VPN's own resolver and endpoint are never fetch targets.
        nets += _split(e.get("VPN_WG_DNS", ""))
        nets += _split(e.get("VPN_WG_ENDPOINT_IP", ""))
        names = [h.strip().lower().strip(".") for h in e.get("API_ALLOWED_HOSTS", "").split(",")]
        names += [h.strip().lower().strip(".") for h in e.get("INDICATORS_IGNORE", "").split(",")]
        for origin in e.get("API_ALLOWED_ORIGINS", "").split(","):
            try:
                names.append((urlsplit(origin.strip()).hostname or "").lower())
            except ValueError:
                continue
        # Ignore-list entries that are addresses or CIDR blocks go to the network list.
        net_extra = _networks([n for n in names if n and _is_net(n)])
        hosts = tuple(dict.fromkeys(n for n in names if n and n != "*" and not _is_net(n)))[:128]
        return cls(
            enabled=_flag(e.get("COLLECTOR_ENABLED", "false")),
            poll_s=_int(e, "COLLECTOR_POLL_S", 15, 1, 3600),
            max_bytes=_int(e, "COLLECTOR_MAX_BYTES", 16 * 1024 * 1024, 1024, 256 * 1024 * 1024),
            timeout_s=_int(e, "COLLECTOR_TIMEOUT_S", 60, 5, 600),
            connect_timeout_s=_int(e, "COLLECTOR_CONNECT_TIMEOUT_S", 10, 1, 120),
            max_redirects=_int(e, "COLLECTOR_MAX_REDIRECTS", 3, 0, 10),
            concurrency=_int(e, "COLLECTOR_CONCURRENCY", 2, 1, 16),
            host_interval_s=float(_int(e, "COLLECTOR_HOST_INTERVAL_S", 10, 0, 3600)),
            hourly_quota=_int(e, "COLLECTOR_HOURLY_QUOTA", 60, 1, 100000),
            daily_quota=_int(e, "COLLECTOR_DAILY_QUOTA", 500, 1, 1000000),
            refetch_hours=_int(e, "COLLECTOR_REFETCH_HOURS", 24, 1, 24 * 365),
            max_depth=_int(e, "COLLECTOR_MAX_DEPTH", 2, 0, 5),
            quarantine_dir=Path(e.get("QUARANTINE_DIR", "") or "/quarantine"),
            quarantine_max_mb=_int(e, "QUARANTINE_MAX_MB", 2048, 1, 10_000_000),
            retention_days=_int(e, "QUARANTINE_RETENTION_DAYS", 90, 1, 3650),
            rules_dir=Path(e.get("RULES_DIR", "") or "/app/rules/yara"),
            heartbeat_path=Path(e.get("HEARTBEAT_PATH", "") or "/tmp/heartbeat"),  # noqa: S108
            analyzer_timeout_s=_int(e, "ANALYZER_TIMEOUT_S", 60, 1, 600),
            analyzer_memory_mb=_int(e, "ANALYZER_MEMORY_MB", 384, 64, 4096),
            deny_nets=_networks(nets) + net_extra,
            deny_hosts=hosts,
        )


def _is_net(entry: str) -> bool:
    try:
        ipaddress.ip_network(entry.strip("[]"), strict=False)
    except ValueError:
        return False
    return True

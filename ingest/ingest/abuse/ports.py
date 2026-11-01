"""Public port and protocol name of an event.

Events carry the port the sensor listens on inside its container; a report must name the port the
source actually connected to. The mapping follows the publishing in ``docker-compose.yml``: the
``*_HOST_PORT`` variables are passed to ingest and read here, with the compose defaults when
unset. A sensor name is never put in a report: the protocol is given instead.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal

# (sensor, container port) -> (environment variable, default public port, protocol name)
_TABLE: dict[tuple[str, int], tuple[str, int, str]] = {
    ("ssh", 2222): ("SSH_HOST_PORT", 22, "ssh"),
    ("telnet", 2323): ("TELNET_HOST_PORT", 23, "telnet"),
    ("web", 8080): ("HTTP_HOST_PORT", 80, "http"),
    ("web", 8443): ("HTTPS_HOST_PORT", 443, "https"),
    ("rdp", 3389): ("RDP_HOST_PORT", 3389, "rdp"),
    ("redis", 6379): ("REDIS_HOST_PORT", 6379, "redis"),
    ("docker", 2375): ("DOCKER_HOST_PORT", 2375, "docker"),
    ("mysql", 3306): ("MYSQL_HOST_PORT", 3306, "mysql"),
    ("mssql", 1433): ("MSSQL_HOST_PORT", 1433, "mssql"),
    ("adb", 5555): ("ADB_HOST_PORT", 5555, "adb"),
    ("smb", 4450): ("SMB_HOST_PORT", 445, "smb"),
    ("sip", 5060): ("SIP_HOST_PORT", 5060, "sip"),
    ("synology", 5000): ("SYNOLOGY_HTTP_HOST_PORT", 5000, "http"),
    ("synology", 5001): ("SYNOLOGY_HTTPS_HOST_PORT", 5001, "https"),
}
_SENSOR_SERVICE = {
    "ssh": "ssh", "telnet": "telnet", "adb": "adb", "web": "http", "docker": "docker",
    "synology": "http", "redis": "redis", "mysql": "mysql", "mssql": "mssql",
    "rdp": "rdp", "smb": "smb", "sip": "sip",
}  # fmt: skip


def _port(raw: str | None, default: int) -> int:
    try:
        value = int((raw or "").strip())
    except ValueError:
        return default
    return value if 0 < value < 65536 else default


@dataclass(frozen=True, slots=True)
class PortMap:
    """Published ports; the default is the compose default for every sensor."""

    published: Mapping[tuple[str, int], int] = field(
        default_factory=lambda: {k: v[1] for k, v in _TABLE.items()}
    )

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> PortMap:
        e = os.environ if env is None else env
        return cls({k: _port(e.get(v[0]), v[1]) for k, v in _TABLE.items()})

    def public_port(self, sensor: str, dst_port: int) -> int:
        return self.published.get((sensor, dst_port), dst_port)

    def service_of(self, sensor: str, dst_port: int) -> str:
        entry = _TABLE.get((sensor, dst_port))
        return entry[2] if entry else _SENSOR_SERVICE.get(sensor, "tcp")


def protocol_of(sensor: str) -> Literal["tcp", "udp"]:
    return "udp" if sensor == "sip" else "tcp"

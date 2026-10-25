"""The single source of truth for sensor names.

Must match ``SensorName`` in ``sensors/common`` (the API does not depend on that package, so a
unit test checks the two stay in sync when it is importable).
"""

from __future__ import annotations

from typing import Annotated, Any, Literal, get_args

from fastapi import Query
from pydantic import BeforeValidator

SensorName = Literal[
    "ssh", "telnet", "web", "rdp", "redis", "docker", "mysql", "adb", "mssql", "smb", "sip"
]
SENSORS: tuple[str, ...] = get_args(SensorName)

SENSOR_LABELS: dict[str, str] = {
    "ssh": "SSH",
    "telnet": "Telnet",
    "web": "Web",
    "rdp": "RDP",
    "redis": "Redis",
    "docker": "Docker",
    "mysql": "MySQL",
    "adb": "ADB",
    "mssql": "MSSQL",
    "smb": "SMB",
    "sip": "SIP",
}


def split_sensors(value: Any) -> Any:
    """Accept ``sensor=a&sensor=b`` and ``sensor=a,b``; dedupe, keep order; empty is no filter."""
    if value is None:
        return None
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, list | tuple):
        return value
    out: list[Any] = []
    for item in items:
        for part in item.split(",") if isinstance(item, str) else [item]:
            part = part.strip() if isinstance(part, str) else part
            if part != "" and part not in out:
                out.append(part)
    return out or None


SensorFilter = Annotated[list[SensorName] | None, BeforeValidator(split_sensors), Query()]

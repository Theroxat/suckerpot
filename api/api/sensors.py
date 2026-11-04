"""The single source of truth for sensor names.

Must match ``SensorName`` in ``sensors/common`` (the API does not depend on that package, so a
unit test checks the two stay in sync when it is importable).
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal, get_args

from fastapi import Query
from pydantic import BeforeValidator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db import EventRow

SensorName = Literal[
    "ssh",
    "telnet",
    "web",
    "rdp",
    "redis",
    "docker",
    "mysql",
    "adb",
    "mssql",
    "smb",
    "sip",
    "synology",
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
    "synology": "Synology NAS",
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


def latest_event_statement(since: datetime) -> Any:
    """One row, one ``max(ts)`` sub-select per known sensor.

    Each sub-select is a backward scan of the ``(sensor, ts)`` index that stops at the newest
    row, so it costs milliseconds however many events the window holds. A ``GROUP BY sensor``
    over the same window reads every row (seconds at ~1M events a day).
    """
    return select(
        *(
            select(func.max(EventRow.ts))
            .where(EventRow.sensor == name, EventRow.ts >= since)
            .scalar_subquery()
            .label(name)
            for name in SENSORS
        )
    )


async def latest_event_per_sensor(db: AsyncSession, since: datetime) -> dict[str, datetime]:
    """Newest event time per known sensor since ``since``; sensors with none are absent."""
    row = (await db.execute(latest_event_statement(since))).one()
    return {name: ts for name, ts in zip(SENSORS, row, strict=True) if ts is not None}

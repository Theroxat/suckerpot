"""Pydantic response models."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, ConfigDict

# asyncpg returns ipaddress objects for inet columns.
IpStr = Annotated[str, BeforeValidator(str)]


class SessionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    session_id: str
    sensor: str
    src_ip: IpStr
    src_port: int
    dst_port: int
    started_at: datetime
    ended_at: datetime | None
    last_event_at: datetime
    event_count: int
    login_attempts: int
    login_success: bool
    commands: int
    downloads: int
    http_requests: int
    country: str | None
    city: str | None
    asn: int | None
    org: str | None
    abuse_score: int | None
    known_scanner: bool | None
    tags: list[str]


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
    sensor: str
    session_id: str
    type: str
    src_ip: IpStr
    src_port: int
    dst_port: int
    data: dict[str, Any]
    country: str | None
    city: str | None
    asn: int | None
    org: str | None
    abuse_score: int | None
    known_scanner: bool | None
    tags: list[str]


class SessionPage(BaseModel):
    items: list[SessionOut]
    next_cursor: str | None


class EventPage(BaseModel):
    items: list[EventOut]
    next_cursor: str | None


class SensorCounts(BaseModel):
    events: int
    sessions: int


class StatsSummary(BaseModel):
    window_hours: int
    events: int
    sessions: int
    unique_ips: int
    sessions_with_commands: int
    download_attempts: int
    by_sensor: dict[str, SensorCounts]


class Health(BaseModel):
    status: str
    db: str


class LiveEvent(BaseModel):
    """Compact event for the live feed (no raw ``data``; ``summary`` is a one-line story)."""

    id: int
    ts: datetime
    sensor: str
    session_id: str
    type: str
    src_ip: IpStr
    src_port: int
    dst_port: int
    summary: str
    country: str | None
    city: str | None
    asn: int | None
    org: str | None
    abuse_score: int | None
    known_scanner: bool | None
    tags: list[str]


class LiveStats(BaseModel):
    window_seconds: int
    events_last_minute: int
    sessions_last_minute: int
    by_sensor: dict[str, SensorCounts]


class RecentEvents(BaseModel):
    items: list[LiveEvent]

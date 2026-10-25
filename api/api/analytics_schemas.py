"""Pydantic response models for the analytics endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from api.schemas import IpStr, SessionOut

BucketName = Literal["5m", "1h", "1d"]
TopField = Literal[
    "country",
    "asn",
    "org",
    "username",
    "password",
    "command",
    "url",
    "user_agent",
    "tag",
    "src_ip",
]


class SensorBreakdown(BaseModel):
    ssh: int = 0
    telnet: int = 0
    web: int = 0
    rdp: int = 0
    redis: int = 0
    docker: int = 0
    mysql: int = 0
    adb: int = 0
    mssql: int = 0
    smb: int = 0
    sip: int = 0


class TimeseriesPoint(BaseModel):
    ts: datetime
    events: SensorBreakdown
    sessions: SensorBreakdown


class Timeseries(BaseModel):
    bucket: BucketName
    since: datetime
    until: datetime
    points: list[TimeseriesPoint]


class TopItem(BaseModel):
    value: str
    count: int
    share: float
    first_seen: datetime
    last_seen: datetime


class TopStats(BaseModel):
    field: TopField
    total: int
    items: list[TopItem]


class HeatmapCell(BaseModel):
    dow: int
    hour: int
    events: int


class Heatmap(BaseModel):
    since: datetime
    until: datetime
    cells: list[HeatmapCell]


class Attacker(BaseModel):
    ip: IpStr
    first_seen: datetime
    last_seen: datetime
    sessions: int
    events: int
    sensors: list[str]
    login_attempts: int
    login_success: int
    commands: int
    downloads: int
    country: str | None
    city: str | None
    asn: int | None
    org: str | None
    abuse_score: int | None
    known_scanner: bool | None
    tags: list[str]


class AttackerPage(BaseModel):
    items: list[Attacker]
    next_cursor: str | None


class ValueCount(BaseModel):
    value: str
    count: int


class DayCount(BaseModel):
    day: str
    events: int


class AttackerDetail(BaseModel):
    attacker: Attacker
    recent_sessions: list[SessionOut]
    top_usernames: list[ValueCount]
    top_commands: list[ValueCount]
    timeline: list[DayCount]


class AsnItem(BaseModel):
    asn: int
    org: str | None
    country: str | None
    ips: int
    sessions: int
    events: int
    last_seen: datetime


class AsnList(BaseModel):
    items: list[AsnItem]

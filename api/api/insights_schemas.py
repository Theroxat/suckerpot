"""Response models for the insights and site-settings endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

InsightKind = Literal["surge", "new_value", "campaign", "exploit", "success", "geo_shift"]
Severity = Literal["info", "notice", "warning", "severe"]


class Evidence(BaseModel):
    metric: str
    current: int
    previous: int
    ratio: float


class Insight(BaseModel):
    id: str
    kind: InsightKind
    severity: Severity
    sentence: str
    evidence: Evidence
    link: str


class InsightList(BaseModel):
    generated_at: datetime
    items: list[Insight]


class SiteHome(BaseModel):
    lat: float
    lon: float
    label: str


class SiteSettings(BaseModel):
    home: SiteHome

"""Insights (deterministic one-sentence findings) and the site-settings endpoint."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException
from pydantic import AwareDatetime

from api import analytics_queries as q
from api.analytics_queries import WindowError
from api.deps import DbSession
from api.insights_queries import gather_facts
from api.insights_rules import build_insights
from api.insights_schemas import InsightList, SiteHome, SiteSettings

router = APIRouter()

DEFAULT_HOME = (46.8, 8.2, "Switzerland")  # country-level centroid, never a precise location
MAX_LABEL = 64


@router.get("/insights", response_model=InsightList)
async def get_insights(
    db: DbSession,
    since: AwareDatetime | None = None,
    until: AwareDatetime | None = None,
) -> InsightList:
    now = datetime.now(UTC)
    try:
        window = q.resolve_window(since, until, default=timedelta(days=7), now=now)
    except WindowError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    facts = await gather_facts(db, window.since, window.until)
    return InsightList(generated_at=now, items=build_insights(facts, now))


def _float_env(name: str, default: float, low: float, high: float) -> float:
    try:
        value = float(os.environ.get(name, ""))
    except ValueError:
        return default
    return value if low <= value <= high else default


def site_home_from_env() -> SiteHome:
    lat = _float_env("SITE_HOME_LAT", DEFAULT_HOME[0], -90.0, 90.0)
    lon = _float_env("SITE_HOME_LON", DEFAULT_HOME[1], -180.0, 180.0)
    label = "".join(c for c in os.environ.get("SITE_HOME_LABEL", "") if c.isprintable()).strip()
    # One decimal place (about 11 km): coarse on purpose, the globe only needs a country.
    return SiteHome(
        lat=round(lat, 1), lon=round(lon, 1), label=label[:MAX_LABEL] or DEFAULT_HOME[2]
    )


@router.get("/settings/site", response_model=SiteSettings)
async def get_site_settings() -> SiteSettings:
    return SiteSettings(home=site_home_from_env())

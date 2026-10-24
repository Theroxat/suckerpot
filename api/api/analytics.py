"""Analytics endpoints: time series, top-N, heatmap, attacker profiles and ASNs (read-only)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Path, Query
from pydantic import AfterValidator, AwareDatetime

from api import analytics_queries as q
from api.analytics_queries import Window, WindowError
from api.analytics_schemas import (
    AsnList,
    AttackerDetail,
    AttackerPage,
    BucketName,
    Heatmap,
    SensorName,
    Timeseries,
    TopField,
    TopStats,
)
from api.cursor import InvalidCursorError
from api.deps import DbSession
from api.schemas import SessionOut

router = APIRouter()

MAX_LIMIT = 200
Limit = Annotated[int, Query(ge=1, le=MAX_LIMIT)]
Cursor = Annotated[str | None, Query(max_length=512)]
TagFilter = Annotated[str, Query(pattern=r"^[a-z0-9-]{1,32}$")]
CountryFilter = Annotated[str, Query(pattern=r"^[A-Za-z]{2}$")]
AsnFilter = Annotated[int, Query(ge=0, le=4294967295)]
IpPrefix = Annotated[str, Query(pattern=r"^[0-9A-Fa-f:.]{1,45}$")]


def _normalize_ip(value: str) -> str:
    try:
        addr: IPv4Address | IPv6Address = ip_address(value)
    except ValueError as exc:
        raise ValueError("invalid IP address") from exc
    return str(addr)


IpPath = Annotated[str, Path(max_length=45), AfterValidator(_normalize_ip)]


def _window(since: datetime | None, until: datetime | None, *, default_days: int = 1) -> Window:
    try:
        return q.resolve_window(since, until, default=timedelta(days=default_days))
    except WindowError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/stats/timeseries", response_model=Timeseries)
async def stats_timeseries(
    db: DbSession,
    bucket: BucketName = "1h",
    since: AwareDatetime | None = None,
    until: AwareDatetime | None = None,
    sensor: SensorName | None = None,
) -> Timeseries:
    window = _window(since, until)
    try:
        q.check_point_count(window, bucket)
    except WindowError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    points = await q.timeseries(db, bucket, window, sensor)
    return Timeseries(bucket=bucket, since=window.since, until=window.until, points=points)


@router.get("/stats/top", response_model=TopStats)
async def stats_top(
    db: DbSession,
    field: TopField,
    since: AwareDatetime | None = None,
    until: AwareDatetime | None = None,
    sensor: SensorName | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 10,
) -> TopStats:
    window = _window(since, until)
    total, items = await q.top(db, field, window, sensor, limit)
    return TopStats(field=field, total=total, items=items)


@router.get("/stats/heatmap", response_model=Heatmap)
async def stats_heatmap(
    db: DbSession,
    since: AwareDatetime | None = None,
    until: AwareDatetime | None = None,
    sensor: SensorName | None = None,
) -> Heatmap:
    window = _window(since, until, default_days=7)
    cells = await q.heatmap(db, window, sensor)
    return Heatmap(since=window.since, until=window.until, cells=cells)


@router.get("/attackers", response_model=AttackerPage)
async def list_attackers(
    db: DbSession,
    sort: Literal["last_seen", "sessions", "events", "first_seen"] = "last_seen",
    order: Literal["asc", "desc"] = "desc",
    cursor: Cursor = None,
    limit: Limit = 50,
    country: CountryFilter | None = None,
    asn: AsnFilter | None = None,
    sensor: SensorName | None = None,
    tag: TagFilter | None = None,
    prefix: Annotated[IpPrefix | None, Query(alias="q")] = None,
) -> AttackerPage:
    try:
        items, next_cursor = await q.list_attackers(
            db,
            sort=sort,
            order=order,
            limit=limit,
            cursor=cursor,
            country=country,
            asn=asn,
            sensor=sensor,
            tag=tag,
            q=prefix,
        )
    except InvalidCursorError as exc:
        raise HTTPException(status_code=400, detail="invalid cursor") from exc
    return AttackerPage(items=items, next_cursor=next_cursor)


@router.get("/attackers/{ip}", response_model=AttackerDetail)
async def get_attacker(ip: IpPath, db: DbSession) -> AttackerDetail:
    attacker = await q.get_attacker(db, ip)
    if attacker is None:
        raise HTTPException(status_code=404, detail="attacker not found")
    sessions = await q.recent_sessions(db, ip)
    return AttackerDetail(
        attacker=attacker,
        recent_sessions=[SessionOut.model_validate(r, from_attributes=True) for r in sessions],
        top_usernames=await q.top_values(db, "username", ip),
        top_commands=await q.top_values(db, "command", ip),
        timeline=await q.ip_timeline(db, ip),
    )


@router.get("/asns", response_model=AsnList)
async def list_asns(
    db: DbSession,
    sort: Literal["sessions", "ips", "events"] = "sessions",
    limit: Limit = 50,
    since: AwareDatetime | None = None,
) -> AsnList:
    if since is not None:
        try:
            since = since.astimezone(UTC)
        except (OverflowError, ValueError) as exc:
            raise HTTPException(status_code=422, detail="timestamp out of range") from exc
    return AsnList(items=await q.list_asns(db, sort, limit, since))

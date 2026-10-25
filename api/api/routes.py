"""REST endpoints (read-only). All SQL uses SQLAlchemy constructs with bound parameters."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Query, Response
from pydantic import AfterValidator, AwareDatetime
from sqlalchemy import func, select, tuple_
from suckerpot_db.models import EnrichmentQuotaRow, EnrichmentStatusRow, EventRow, SessionRow

from api.analytics_queries import session_has_value
from api.cursor import (
    InvalidCursorError,
    event_cursor,
    parse_event_cursor,
    parse_session_cursor,
    session_cursor,
)
from api.deps import DbSession
from api.live import fetch_recent
from api.schemas import (
    EnrichmentSettings,
    EventOut,
    EventPage,
    GeoFile,
    GeoipStatus,
    Health,
    RecentEvents,
    ReputationProvider,
    SensorCounts,
    SessionOut,
    SessionPage,
    StatsSummary,
)
from api.sensors import SensorFilter

router = APIRouter()
health_router = APIRouter()

MAX_LIMIT = 200
SessionId = Annotated[str, Path(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]{1,64}$")]
Limit = Annotated[int, Query(ge=1, le=MAX_LIMIT)]
Cursor = Annotated[str | None, Query(max_length=512)]
TagFilter = Annotated[str, Query(pattern=r"^[a-z0-9-]{1,32}$")]
CountryFilter = Annotated[str, Query(pattern=r"^[A-Za-z]{2}$")]
AsnFilter = Annotated[int, Query(ge=0, le=4294967295)]
ValueFilter = Annotated[str, Query(min_length=1, max_length=256)]


def _normalize_ip(value: str) -> str:
    try:
        addr: IPv4Address | IPv6Address = ip_address(value)
    except ValueError as exc:
        raise ValueError("invalid IP address") from exc
    return str(addr)


SrcIp = Annotated[str, AfterValidator(_normalize_ip)]


def _utc_or_422(value: datetime) -> datetime:
    try:
        return value.astimezone(UTC)
    except (OverflowError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="timestamp out of range") from exc


@health_router.get("/healthz", response_model=Health)
async def healthz(session: DbSession, response: Response) -> Health:
    try:
        await session.execute(select(1))
    except Exception:
        response.status_code = 503
        return Health(status="degraded", db="error")
    return Health(status="ok", db="ok")


@router.get("/events/recent", response_model=RecentEvents)
async def recent_events(session: DbSession, limit: Limit = 50) -> RecentEvents:
    """The latest events, newest first (REST equivalent of the WebSocket backfill)."""
    return RecentEvents(items=await fetch_recent(session, limit))


@router.get("/sessions", response_model=SessionPage)
async def list_sessions(
    session: DbSession,
    limit: Limit = 50,
    cursor: Cursor = None,
    sensor: SensorFilter = None,
    src_ip: Annotated[SrcIp | None, Query()] = None,
    since: AwareDatetime | None = None,
    until: AwareDatetime | None = None,
    tag: TagFilter | None = None,
    country: CountryFilter | None = None,
    asn: AsnFilter | None = None,
    username: ValueFilter | None = None,
    password: ValueFilter | None = None,
    command: ValueFilter | None = None,
    url: ValueFilter | None = None,
) -> SessionPage:
    stmt = select(SessionRow)
    if sensor is not None:
        stmt = stmt.where(SessionRow.sensor.in_(sensor))
    if src_ip is not None:
        stmt = stmt.where(SessionRow.src_ip == src_ip)
    if tag is not None:
        stmt = stmt.where(SessionRow.tags.contains([tag]))
    if country is not None:
        stmt = stmt.where(SessionRow.country == country.upper())
    if asn is not None:
        stmt = stmt.where(SessionRow.asn == asn)
    for name, val in (
        ("username", username),
        ("password", password),
        ("command", command),
        ("url", url),
    ):
        if val is not None:
            stmt = stmt.where(session_has_value(name, val))
    if since is not None:
        stmt = stmt.where(SessionRow.started_at >= _utc_or_422(since))
    if until is not None:
        stmt = stmt.where(SessionRow.started_at < _utc_or_422(until))
    if cursor is not None:
        try:
            c_ts, c_id = parse_session_cursor(cursor)
        except InvalidCursorError as exc:
            raise HTTPException(status_code=400, detail="invalid cursor") from exc
        stmt = stmt.where(tuple_(SessionRow.started_at, SessionRow.session_id) < (c_ts, c_id))
    stmt = stmt.order_by(SessionRow.started_at.desc(), SessionRow.session_id.desc()).limit(
        limit + 1
    )
    rows = list((await session.scalars(stmt)).all())
    page, more = rows[:limit], len(rows) > limit
    return SessionPage(
        items=[_session_out(r) for r in page],
        next_cursor=session_cursor(page[-1].started_at, page[-1].session_id) if more else None,
    )


def _session_out(row: SessionRow) -> SessionOut:
    return SessionOut.model_validate(row, from_attributes=True)


@router.get("/sessions/{session_id}", response_model=SessionOut)
async def get_session_detail(session_id: SessionId, session: DbSession) -> SessionOut:
    row = await session.get(SessionRow, session_id)
    if row is None:
        raise HTTPException(status_code=404, detail="session not found")
    return _session_out(row)


@router.get("/sessions/{session_id}/events", response_model=EventPage)
async def list_session_events(
    session_id: SessionId,
    session: DbSession,
    limit: Limit = 100,
    cursor: Cursor = None,
) -> EventPage:
    stmt = select(EventRow).where(EventRow.session_id == session_id)
    if cursor is not None:
        try:
            c_ts, c_id = parse_event_cursor(cursor)
        except InvalidCursorError as exc:
            raise HTTPException(status_code=400, detail="invalid cursor") from exc
        stmt = stmt.where(tuple_(EventRow.ts, EventRow.id) > (c_ts, c_id))
    stmt = stmt.order_by(EventRow.ts.asc(), EventRow.id.asc()).limit(limit + 1)
    rows = list((await session.scalars(stmt)).all())
    if not rows and cursor is None and await session.get(SessionRow, session_id) is None:
        raise HTTPException(status_code=404, detail="session not found")
    page, more = rows[:limit], len(rows) > limit
    return EventPage(
        items=[EventOut.model_validate(r, from_attributes=True) for r in page],
        next_cursor=event_cursor(page[-1].ts, page[-1].id) if more else None,
    )


@router.get("/stats/summary", response_model=StatsSummary)
async def stats_summary(session: DbSession) -> StatsSummary:
    since = datetime.now(UTC) - timedelta(hours=24)

    ev_by_sensor = (
        await session.execute(
            select(EventRow.sensor, func.count())
            .where(EventRow.ts >= since)
            .group_by(EventRow.sensor)
        )
    ).all()
    downloads = await session.scalar(
        select(func.count()).where(EventRow.ts >= since, EventRow.type == "download_attempt")
    )
    ses_by_sensor = (
        await session.execute(
            select(SessionRow.sensor, func.count())
            .where(SessionRow.started_at >= since)
            .group_by(SessionRow.sensor)
        )
    ).all()
    unique_ips = await session.scalar(
        select(func.count(func.distinct(SessionRow.src_ip))).where(SessionRow.started_at >= since)
    )
    with_cmds = await session.scalar(
        select(func.count()).where(SessionRow.started_at >= since, SessionRow.commands > 0)
    )

    by_sensor: dict[str, SensorCounts] = {}
    for name, n in ev_by_sensor:
        by_sensor.setdefault(name, SensorCounts(events=0, sessions=0)).events = n
    for name, n in ses_by_sensor:
        by_sensor.setdefault(name, SensorCounts(events=0, sessions=0)).sessions = n
    return StatsSummary(
        window_hours=24,
        events=sum(n for _, n in ev_by_sensor),
        sessions=sum(n for _, n in ses_by_sensor),
        unique_ips=unique_ips or 0,
        sessions_with_commands=with_cmds or 0,
        download_attempts=downloads or 0,
        by_sensor=dict(sorted(by_sensor.items())),
    )


DBIP_ATTRIBUTION = "IP geolocation by DB-IP.com (https://db-ip.com), CC BY 4.0"
MAXMIND_ATTRIBUTION = (
    "This product includes GeoLite2 data created by MaxMind (https://www.maxmind.com)"
)


@router.get("/settings/enrichment", response_model=EnrichmentSettings)
async def enrichment_settings(session: DbSession) -> EnrichmentSettings:
    """Provider status, GeoIP database age and today's quota usage (no secrets)."""
    status = {r.name: r for r in (await session.scalars(select(EnrichmentStatusRow))).all()}
    today = datetime.now(UTC).date()
    used = {
        r.provider: r.used
        for r in (
            await session.scalars(select(EnrichmentQuotaRow).where(EnrichmentQuotaRow.day == today))
        ).all()
    }
    now = datetime.now(UTC)

    geo_row = status.get("geoip")
    d = geo_row.detail if geo_row else {}
    provider = str(d.get("provider", "unknown"))
    files: dict[str, GeoFile] = {}
    for kind, info in (d.get("files") or {}).items():
        try:
            updated = datetime.fromisoformat(info["updated_at"])
            files[str(kind)] = GeoFile(
                file=str(info["file"]),
                bytes=int(info["bytes"]),
                updated_at=updated,
                age_days=round((now - updated).total_seconds() / 86400, 1),
            )
        except (KeyError, ValueError, TypeError):
            continue
    attribution = {"dbip": DBIP_ATTRIBUTION, "maxmind": MAXMIND_ATTRIBUTION}.get(provider)
    geoip = GeoipStatus(
        provider=provider,
        available=bool(d.get("available", False)),
        files=files,
        last_error=d.get("last_error"),
        refresh_days=d.get("refresh_days"),
        attribution=attribution,
    )

    def rep(name: str) -> ReputationProvider:
        row = status.get(name)
        det = row.detail if row else {}
        return ReputationProvider(
            configured=bool(det.get("configured", False)),
            daily_quota=det.get("daily_quota"),
            used_today=used.get(name, 0),
            disabled=det.get("disabled"),
            paused=bool(det.get("paused", False)),
            last_error=det.get("last_error"),
        )

    reported = max((r.updated_at for r in status.values()), default=None)
    return EnrichmentSettings(
        geoip=geoip, abuseipdb=rep("abuseipdb"), greynoise=rep("greynoise"), reported_at=reported
    )

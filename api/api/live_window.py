"""The Live page's window: what the sensors saw in the last N minutes, aggregated in the database.

``GET /api/v1/live/window`` seeds the Live map, the stats strip and the leader rankings. The
browser used to compute them from its WebSocket buffer (a few hundred events), which covers only
a few minutes when traffic is busy; this endpoint answers for the whole window instead. The
page then adds the events that arrive over the WebSocket on top of it, counting only those with
an id above ``last_event_id`` so nothing is counted twice.

Every query is bounded: a ``ts`` range on the events hypertable (chunk exclusion), a GROUP BY and
a LIMIT. Result sizes are capped (countries, addresses, networks), whatever the traffic.
"""

from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel
from sqlalchemy import ColumnElement, and_, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.models import EventRow

from api.benign import IncludeBenign, visible_events
from api.deps import DbSession
from api.sensors import SensorFilter

router = APIRouter(tags=["live"])

DEFAULT_MINUTES = 15
MAX_MINUTES = 60
MAX_COUNTRIES = 80
MAX_LEADERS = 10
STATEMENT_TIMEOUT_MS = 3000
CACHE_SECONDS = 10.0
MAX_CACHED = 64
CacheKey = tuple[int, tuple[str, ...], bool]


class WindowCountry(BaseModel):
    country: str
    events: int
    ips: int
    #: The busiest address of this country in the window.
    top_ip: str
    #: How many events that address sent in the window.
    top_ip_events: int
    last_ts: datetime
    by_sensor: dict[str, int]


class WindowAddress(BaseModel):
    ip: str
    events: int
    country: str | None
    asn: int | None
    org: str | None
    last_ts: datetime
    by_sensor: dict[str, int]


class WindowNetwork(BaseModel):
    asn: int
    events: int
    ips: int
    country: str | None
    org: str | None
    last_ts: datetime
    by_sensor: dict[str, int]


class WindowSensorCounts(BaseModel):
    events: int
    sessions: int


class LiveWindow(BaseModel):
    as_of: datetime
    window_minutes: int
    #: Newest event id at ``as_of`` (any sensor). Live events with a higher id are not in here.
    last_event_id: int
    events: int
    #: Events in the window with no known country: not drawable on the map.
    unlocated: int
    events_last_minute: int
    sessions_last_minute: int
    #: Events and sessions of the last minute per sensor (same shape as the WebSocket stats).
    last_minute_by_sensor: dict[str, WindowSensorCounts]
    #: Events of the whole window per sensor.
    by_sensor: dict[str, int]
    countries: list[WindowCountry]
    addresses: list[WindowAddress]
    networks: list[WindowNetwork]


def _split(
    rows: list[tuple[object, str, int]],
) -> dict[object, dict[str, int]]:
    out: dict[object, dict[str, int]] = defaultdict(dict)
    for key, sensor, n in rows:
        out[key][sensor] = n
    return out


def _cache(request: Request) -> dict[CacheKey, tuple[float, LiveWindow]]:
    cache: dict[CacheKey, tuple[float, LiveWindow]] | None = getattr(
        request.app.state, "live_window_cache", None
    )
    if cache is None:
        cache = {}
        request.app.state.live_window_cache = cache
    return cache


@router.get("/live/window", response_model=LiveWindow)
async def live_window(
    request: Request,
    session: DbSession,
    minutes: Annotated[int, Query(ge=1, le=MAX_MINUTES)] = DEFAULT_MINUTES,
    sensor: SensorFilter = None,
    include_benign: IncludeBenign = False,
) -> LiveWindow:
    """The window for every open Live page, computed at most once per few seconds per variant."""
    key: CacheKey = (minutes, tuple(sorted(sensor or ())), include_benign)
    cache = _cache(request)
    hit = cache.get(key)
    if hit is not None and time.monotonic() - hit[0] < CACHE_SECONDS:
        return hit[1]
    # One snapshot and one time limit for the whole route (must be the first statements).
    await session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"))
    await session.execute(text(f"SET LOCAL statement_timeout = {STATEMENT_TIMEOUT_MS}"))
    result = await _compute(session, minutes, sensor, include_benign)
    now = time.monotonic()
    for k in [k for k, (t, _) in cache.items() if now - t >= CACHE_SECONDS]:
        del cache[k]
    if len(cache) < MAX_CACHED:
        cache[key] = (now, result)
    return result


async def _compute(
    session: AsyncSession,
    minutes: int,
    sensor: Sequence[str] | None,
    include_benign: bool,
) -> LiveWindow:
    now = datetime.now(UTC)
    since = now - timedelta(minutes=minutes)
    minute_ago = now - timedelta(minutes=1)
    e = EventRow
    where: list[ColumnElement[bool]] = [e.ts > since, e.ts <= now, *visible_events(include_benign)]
    if sensor:
        where.append(e.sensor.in_(sensor))
    ip = func.host(e.src_ip)
    in_minute = e.ts > minute_ago

    # Per sensor: window events, and events and sessions of the last minute.
    sensor_rows = (
        await session.execute(
            select(
                e.sensor,
                func.count(),
                func.count().filter(in_minute),
                func.count(func.distinct(e.session_id)).filter(in_minute),
            )
            .where(*where)
            .group_by(e.sensor)
            .limit(32)
        )
    ).all()
    by_sensor = {s: n for s, n, _, _ in sensor_rows}
    last_minute = {s: WindowSensorCounts(events=m, sessions=q) for s, _, m, q in sensor_rows if m}
    total = sum(by_sensor.values())

    # The rest of the totals, and the newest id, in the same statement and snapshot.
    unlocated, sessions_last_minute, last_id = (
        await session.execute(
            select(
                func.count().filter(e.country.is_(None)),
                func.count(func.distinct(e.session_id)).filter(in_minute),
                select(func.max(e.id)).where(e.ts > since, e.ts <= now).scalar_subquery(),
            ).where(*where)
        )
    ).one()

    # --- countries
    country_rows = (
        await session.execute(
            select(
                e.country,
                func.count().label("n"),
                func.count(func.distinct(e.src_ip)),
                func.max(e.ts),
            )
            .where(*where, e.country.is_not(None))
            .group_by(e.country)
            .order_by(func.count().desc(), e.country)
            .limit(MAX_COUNTRIES)
        )
    ).all()
    countries: list[WindowCountry] = []
    if country_rows:
        codes = [r[0] for r in country_rows]
        c_sensor = _split(
            [
                (c, s, n)
                for c, s, n in (
                    await session.execute(
                        select(e.country, e.sensor, func.count())
                        .where(*where, e.country.in_(codes))
                        .group_by(e.country, e.sensor)
                    )
                ).all()
            ]
        )
        per_ip = (
            select(
                e.country.label("country"),
                ip.label("ip"),
                func.count().label("n"),
                func.row_number()
                .over(partition_by=e.country, order_by=(func.count().desc(), ip))
                .label("rn"),
            )
            .where(*where, e.country.in_(codes))
            .group_by(e.country, ip)
            .subquery()
        )
        top_ips = {
            c: (i, n)
            for c, i, n in (
                await session.execute(
                    select(per_ip.c.country, per_ip.c.ip, per_ip.c.n).where(per_ip.c.rn == 1)
                )
            ).all()
        }
        countries = [
            WindowCountry(
                country=str(c),
                events=n,
                ips=ips,
                top_ip=str(top_ips.get(c, ("", 0))[0]),
                top_ip_events=top_ips.get(c, ("", 0))[1],
                last_ts=last,
                by_sensor=c_sensor.get(c, {}),
            )
            for c, n, ips, last in country_rows
        ]

    # --- addresses
    ip_rows = (
        await session.execute(
            select(
                ip.label("ip"),
                func.count().label("n"),
                func.max(e.country),
                func.max(e.asn),
                func.max(e.org),
                func.max(e.ts),
            )
            .where(*where)
            .group_by(ip)
            .order_by(func.count().desc(), ip)
            .limit(MAX_LEADERS)
        )
    ).all()
    addresses: list[WindowAddress] = []
    if ip_rows:
        a_sensor = _split(
            [
                (i, s, n)
                for i, s, n in (
                    await session.execute(
                        select(ip, e.sensor, func.count())
                        .where(*where, ip.in_([r[0] for r in ip_rows]))
                        .group_by(ip, e.sensor)
                    )
                ).all()
            ]
        )
        addresses = [
            WindowAddress(
                ip=str(i),
                events=n,
                country=c,
                asn=a,
                org=o,
                last_ts=last,
                by_sensor=a_sensor.get(i, {}),
            )
            for i, n, c, a, o, last in ip_rows
        ]

    # --- networks
    net_rows = (
        await session.execute(
            select(
                e.asn,
                func.count().label("n"),
                func.count(func.distinct(e.src_ip)),
                func.max(e.country),
                func.max(e.org),
                func.max(e.ts),
            )
            .where(*where, e.asn.is_not(None))
            .group_by(e.asn)
            .order_by(func.count().desc(), e.asn)
            .limit(MAX_LEADERS)
        )
    ).all()
    networks: list[WindowNetwork] = []
    if net_rows:
        n_sensor = _split(
            [
                (a, s, n)
                for a, s, n in (
                    await session.execute(
                        select(e.asn, e.sensor, func.count())
                        .where(and_(*where), e.asn.in_([r[0] for r in net_rows]))
                        .group_by(e.asn, e.sensor)
                    )
                ).all()
            ]
        )
        networks = [
            WindowNetwork(
                asn=a,
                events=n,
                ips=ips,
                country=c,
                org=o,
                last_ts=last,
                by_sensor=n_sensor.get(a, {}),
            )
            for a, n, ips, c, o, last in net_rows
        ]

    return LiveWindow(
        as_of=now,
        window_minutes=minutes,
        last_event_id=int(last_id or 0),
        events=total,
        unlocated=unlocated,
        events_last_minute=sum(c.events for c in last_minute.values()),
        sessions_last_minute=sessions_last_minute,
        last_minute_by_sensor=last_minute,
        by_sensor=by_sensor,
        countries=countries,
        addresses=addresses,
        networks=networks,
    )

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

from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import BaseModel
from sqlalchemy import ColumnElement, and_, func, select
from suckerpot_db.models import EventRow

from api.benign import IncludeBenign, visible_events
from api.deps import DbSession
from api.sensors import SensorFilter

router = APIRouter(tags=["live"])

DEFAULT_MINUTES = 15
MAX_MINUTES = 60
MAX_COUNTRIES = 80
MAX_LEADERS = 10


class WindowCountry(BaseModel):
    country: str
    events: int
    ips: int
    #: The busiest address of this country in the window.
    top_ip: str
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


@router.get("/live/window", response_model=LiveWindow)
async def live_window(
    session: DbSession,
    minutes: Annotated[int, Query(ge=1, le=MAX_MINUTES)] = DEFAULT_MINUTES,
    sensor: SensorFilter = None,
    include_benign: IncludeBenign = False,
) -> LiveWindow:
    now = datetime.now(UTC)
    since = now - timedelta(minutes=minutes)
    minute_ago = now - timedelta(minutes=1)
    e = EventRow
    where: list[ColumnElement[bool]] = [e.ts > since, e.ts <= now, *visible_events(include_benign)]
    if sensor:
        where.append(e.sensor.in_(sensor))
    ip = func.host(e.src_ip)

    last_id = (
        await session.execute(select(func.max(e.id)).where(e.ts > since, e.ts <= now))
    ).scalar_one_or_none() or 0

    total, unlocated = (
        await session.execute(
            select(
                func.count(),
                func.count().filter(e.country.is_(None)),
            ).where(*where)
        )
    ).one()

    sensor_rows = (
        await session.execute(
            select(e.sensor, func.count()).where(*where).group_by(e.sensor).limit(32)
        )
    ).all()
    by_sensor = {s: n for s, n in sensor_rows}

    minute_rows = (
        await session.execute(
            select(e.sensor, func.count(), func.count(func.distinct(e.session_id)))
            .where(*where, e.ts > minute_ago)
            .group_by(e.sensor)
            .limit(32)
        )
    ).all()
    last_minute = {s: WindowSensorCounts(events=n, sessions=q) for s, n, q in minute_rows}
    sessions_last_minute = (
        await session.execute(
            select(func.count(func.distinct(e.session_id))).where(*where, e.ts > minute_ago)
        )
    ).scalar_one()

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
                func.row_number()
                .over(partition_by=e.country, order_by=(func.count().desc(), ip))
                .label("rn"),
            )
            .where(*where, e.country.in_(codes))
            .group_by(e.country, ip)
            .subquery()
        )
        top_ips = {
            c: i
            for c, i in (
                await session.execute(select(per_ip.c.country, per_ip.c.ip).where(per_ip.c.rn == 1))
            ).all()
        }
        countries = [
            WindowCountry(
                country=str(c),
                events=n,
                ips=ips,
                top_ip=str(top_ips.get(c, "")),
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
        last_event_id=int(last_id),
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

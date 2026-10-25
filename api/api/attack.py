"""MITRE ATT&CK endpoints (M15): the technique catalogue and the technique-by-day matrix.

Read-only. The catalogue is a few dozen curated techniques (bounded at 400 by the loader in
ingest), so the matrix is one bounded response; the catalogue list is still keyset-paged.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from suckerpot_db.models import AttackTechniqueRow, TechniqueDailyRow

from api.cursor import InvalidCursorError, decode_cursor, encode_cursor
from api.deps import DbSession
from api.sensors import SensorFilter

router = APIRouter(tags=["attack"])

MAX_LIMIT = 400
MAX_DAYS = 365
STAGES: tuple[str, ...] = (
    "recon",
    "access",
    "execution",
    "persistence",
    "tool_transfer",
    "objective",
)
STAGE_RANK = {s: i for i, s in enumerate(STAGES)}
#: Plain-English label of each stage, in story order.
STAGE_LABELS = {
    "recon": "Looking around",
    "access": "Getting in",
    "execution": "Running code",
    "persistence": "Staying in",
    "tool_transfer": "Bringing tools",
    "objective": "The goal",
}
#: What the technique means, as a verb phrase after "they". Falls back to the technique name.
PLAIN: dict[str, str] = {
    "T1595": "scanned the machine for open services",
    "T1595.002": "probed for well-known vulnerable pages",
    "T1046": "looked for other services to talk to",
    "T1082": "checked the system's details",
    "T1033": "checked which user they were",
    "T1083": "browsed files and folders",
    "T1057": "listed the running programs",
    "T1016": "looked at the network settings",
    "T1087.001": "read the list of local accounts",
    "T1190": "exploited a flaw in a public service",
    "T1133": "used a remote-access service that faces the internet",
    "T1078": "logged in with a password that worked",
    "T1210": "exploited a flaw in a network service",
    "T1110": "guessed passwords",
    "T1110.001": "guessed passwords one by one",
    "T1110.003": "tried a few passwords on many accounts",
    "T1110.004": "tried passwords stolen from other sites",
    "T1059": "ran commands",
    "T1059.004": "typed shell commands",
    "T1059.006": "ran a Python script",
    "T1610": "started a container",
    "T1611": "tried to break out of a container",
    "T1053.003": "set up a scheduled job to come back",
    "T1098.004": "planted their own SSH key",
    "T1136.001": "created a new account",
    "T1505.003": "planted a web shell",
    "T1105": "downloaded a tool onto the machine",
    "T1071.001": "talked to a control server over web traffic",
    "T1570": "moved a tool to another machine",
    "T1496": "used the machine to mine cryptocurrency",
    "T1486": "locked or ransomed data",
    "T1657": "tried to turn the service into a money-making scam",
    "T1499": "tried to knock the service offline",
}


def plain_phrase(technique_id: str, name: str) -> str:
    return PLAIN.get(technique_id, name[:1].lower() + name[1:])


class TechniqueOut(BaseModel):
    id: str
    name: str
    tactic: str
    stage: str
    stage_label: str
    url: str
    plain: str
    sessions: int
    events: int
    sources: int
    last_day: date | None


class TechniquePage(BaseModel):
    days: int
    items: list[TechniqueOut]
    next_cursor: str | None


class MatrixRow(BaseModel):
    id: str
    name: str
    tactic: str
    stage: str
    url: str
    plain: str
    total_sessions: int
    total_events: int
    counts: list[int]  # sessions per day, aligned with ``days``


class MatrixStage(BaseModel):
    stage: str
    label: str


class Matrix(BaseModel):
    since: date
    until: date
    days: list[date]
    stages: list[MatrixStage]
    rows: list[MatrixRow]


def _window(days: int) -> tuple[date, date]:
    until = datetime.now(UTC).date()
    return until - timedelta(days=days - 1), until


@router.get("/attack/techniques", response_model=TechniquePage)
async def list_techniques(
    db: DbSession,
    days: Annotated[int, Query(ge=1, le=MAX_DAYS)] = 30,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = 200,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    sensor: SensorFilter = None,
) -> TechniquePage:
    """The catalogue with what was seen in the last ``days`` days (all of it, quiet ones too)."""
    since, until = _window(days)
    d = TechniqueDailyRow
    activity = select(
        d.technique.label("technique"),
        func.sum(d.sessions).label("sessions"),
        func.sum(d.events).label("events"),
        func.sum(d.sources).label("sources"),
        func.max(d.day).label("last_day"),
    ).where(d.day >= since, d.day <= until)
    if sensor is not None:
        activity = activity.where(d.sensor.in_(sensor))
    sub = activity.group_by(d.technique).subquery("a")
    t = AttackTechniqueRow
    stmt = select(
        t.id,
        t.name,
        t.tactic,
        t.stage,
        t.url,
        func.coalesce(sub.c.sessions, 0).label("sessions"),
        func.coalesce(sub.c.events, 0).label("events"),
        func.coalesce(sub.c.sources, 0).label("sources"),
        sub.c.last_day,
    ).join(sub, sub.c.technique == t.id, isouter=True)
    if cursor is not None:
        try:
            values = decode_cursor(cursor)
            after = values[0] if len(values) == 1 and isinstance(values[0], str) else None
        except InvalidCursorError as exc:
            raise HTTPException(status_code=400, detail="invalid cursor") from exc
        if after is None:
            raise HTTPException(status_code=400, detail="invalid cursor")
        stmt = stmt.where(t.id > after)
    rows = (await db.execute(stmt.order_by(t.id).limit(limit + 1))).all()
    page, more = rows[:limit], len(rows) > limit
    items = [
        TechniqueOut(
            id=r.id,
            name=r.name,
            tactic=r.tactic,
            stage=r.stage,
            stage_label=STAGE_LABELS.get(r.stage, r.stage),
            url=r.url,
            plain=plain_phrase(r.id, r.name),
            sessions=int(r.sessions),
            events=int(r.events),
            sources=int(r.sources),
            last_day=r.last_day,
        )
        for r in page
    ]
    return TechniquePage(
        days=days, items=items, next_cursor=encode_cursor([page[-1].id]) if more else None
    )


@router.get("/attack/matrix", response_model=Matrix)
async def attack_matrix(
    db: DbSession,
    days: Annotated[int, Query(ge=1, le=MAX_DAYS)] = 30,
    sensor: SensorFilter = None,
) -> Matrix:
    """Sessions per technique per day (UTC), only techniques seen in the window.

    Bounded: at most one row per catalogue entry and one cell per day.
    """
    since, until = _window(days)
    d = TechniqueDailyRow
    stmt = (
        select(
            d.technique,
            d.day,
            func.sum(d.sessions).label("sessions"),
            func.sum(d.events).label("events"),
        )
        .where(d.day >= since, d.day <= until)
        .group_by(d.technique, d.day)
    )
    if sensor is not None:
        stmt = stmt.where(d.sensor.in_(sensor))
    cells = (await db.execute(stmt)).all()
    ids = sorted({c.technique for c in cells})
    catalogue = {
        t.id: t
        for t in (
            await db.scalars(select(AttackTechniqueRow).where(AttackTechniqueRow.id.in_(ids)))
        ).all()
    }
    day_list = [since + timedelta(days=i) for i in range(days)]
    index = {day: i for i, day in enumerate(day_list)}
    counts: dict[str, list[int]] = {tid: [0] * days for tid in ids}
    events: dict[str, int] = dict.fromkeys(ids, 0)
    for c in cells:
        counts[c.technique][index[c.day]] += int(c.sessions)
        events[c.technique] += int(c.events)
    rows = [
        MatrixRow(
            id=tid,
            name=catalogue[tid].name,
            tactic=catalogue[tid].tactic,
            stage=catalogue[tid].stage,
            url=catalogue[tid].url,
            plain=plain_phrase(tid, catalogue[tid].name),
            total_sessions=sum(counts[tid]),
            total_events=events[tid],
            counts=counts[tid],
        )
        for tid in ids
        if tid in catalogue
    ]
    rows.sort(key=lambda r: (STAGE_RANK.get(r.stage, 99), -r.total_sessions, r.id))
    return Matrix(
        since=since,
        until=until,
        days=day_list,
        stages=[MatrixStage(stage=s, label=STAGE_LABELS[s]) for s in STAGES],
        rows=rows,
    )

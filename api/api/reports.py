"""Weekly report endpoints (M18).

The report is built by ingest, stored as escaped HTML and served here under a strict
Content-Security-Policy: no script, no external resource, only its own inline style. It can be
shown in a sandboxed frame and printed to PDF from the browser.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Path, Query, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from suckerpot_db import WeeklyReportRow

from api import reauth
from api.cursor import InvalidCursorError, decode_cursor, encode_cursor
from api.deps import DbSession

router = APIRouter(tags=["reports"])

MAX_LIMIT = 52
WEEK = Annotated[str, Path(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")]
REPORT_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; "
    "frame-ancestors 'self'; sandbox"
)


class ReportItem(BaseModel):
    week_start: date
    week_end: str | None
    headline: str | None
    sessions: int
    sources: int
    malware: int
    change_pct: int | None
    created_at: datetime


class ReportPage(BaseModel):
    items: list[ReportItem]
    next_cursor: str | None


class Report(BaseModel):
    week_start: date
    created_at: datetime
    summary: dict[str, Any]


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _item(row: WeeklyReportRow) -> ReportItem:
    s: dict[str, Any] = row.summary if isinstance(row.summary, dict) else {}
    t: dict[str, Any] = s["totals"] if isinstance(s.get("totals"), dict) else {}
    return ReportItem(
        week_start=row.week_start,
        week_end=s.get("week_end") if isinstance(s.get("week_end"), str) else None,
        headline=s.get("headline") if isinstance(s.get("headline"), str) else None,
        sessions=_int(t.get("sessions")) or 0,
        sources=_int(t.get("sources")) or 0,
        malware=_int(t.get("malware")) or 0,
        change_pct=_int(t.get("change_pct")),
        created_at=row.created_at,
    )


@router.get("/reports", response_model=ReportPage)
async def list_reports(
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = 12,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
) -> Response:
    stmt = select(WeeklyReportRow).order_by(WeeklyReportRow.week_start.desc()).limit(limit + 1)
    if cursor:
        try:
            after = date.fromisoformat(str(decode_cursor(cursor)[0]))
        except (InvalidCursorError, ValueError, IndexError):
            return reauth.error(400, "Invalid cursor.", "bad_cursor")
        stmt = stmt.where(WeeklyReportRow.week_start < after)
    rows = list((await session.scalars(stmt)).all())
    more = len(rows) > limit
    rows = rows[:limit]
    nxt = encode_cursor([rows[-1].week_start.isoformat()]) if more and rows else None
    return JSONResponse(
        ReportPage(items=[_item(r) for r in rows], next_cursor=nxt).model_dump(mode="json")
    )


async def _get(session: DbSession, week: str) -> WeeklyReportRow | None:
    try:
        day = date.fromisoformat(week)
    except ValueError:
        return None
    return await session.get(WeeklyReportRow, day)


@router.get("/reports/{week}", response_model=Report)
async def get_report(week: WEEK, session: DbSession) -> Response:
    row = await _get(session, week)
    if row is None:
        return reauth.error(404, "Report not found.", "not_found")
    return JSONResponse(
        Report(
            week_start=row.week_start, created_at=row.created_at, summary=row.summary
        ).model_dump(mode="json")
    )


@router.get("/reports/{week}/html", response_class=HTMLResponse)
async def get_report_html(week: WEEK, session: DbSession) -> Response:
    """The printable page. Served with its own CSP, which the global header middleware keeps."""
    row = await _get(session, week)
    if row is None:
        return reauth.error(404, "Report not found.", "not_found")
    return HTMLResponse(
        row.html,
        headers={
            "Content-Security-Policy": REPORT_CSP,
            "Cache-Control": "private, no-store",
            "Content-Disposition": f'inline; filename="weekly-report-{row.week_start}.html"',
        },
    )

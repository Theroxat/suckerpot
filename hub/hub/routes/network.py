"""GET /v1/network: the daily summary computed by the worker (design M29 section 7.1)."""

from __future__ import annotations

from datetime import date

from fastapi import APIRouter, Request
from pydantic import ValidationError
from sqlalchemy import select
from starlette.responses import Response
from suckerpot_netproto import models

from ..auth import authenticate, reply
from ..context import get_ctx
from ..models import NetworkSummaryRow

router = APIRouter()


def empty_summary(today: date) -> models.NetworkSummary:
    return models.NetworkSummary(
        generated_day=today.isoformat(),
        totals=models.NetworkTotals(
            members=0,
            active_7d=0,
            countries=0,
            confirmed_30d=0,
            reported_30d=0,
            taken_down_30d=0,
            median_days_to_takedown=None,
        ),
        weekly=[],
        countries=[],
        members=[],
    )


@router.get("/network")
async def network(request: Request) -> Response:
    ctx = get_ctx(request)
    async with ctx.sessionmaker() as session:
        await authenticate(request, ctx, session)
        row = (
            await session.execute(select(NetworkSummaryRow).where(NetworkSummaryRow.id == 1))
        ).scalar_one_or_none()
    try:
        summary = (
            models.NetworkSummary.model_validate(row.data) if row else empty_summary(ctx.today())
        )
    except ValidationError:  # a malformed cache never reaches a node
        summary = empty_summary(ctx.today())
    return reply(request, ctx, 200, summary.model_dump(mode="json"))

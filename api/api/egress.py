"""Egress status for the Settings page (read-only).

Ingest and the collector publish their gate state to ``enrichment_status`` (rows ``egress`` and
``egress_collector``). This route only reads it. The exit address is shown to administrators and
never to viewers; the route does not guess it, it only repeats what the gate recorded.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.models import EnrichmentQuotaRow, EnrichmentStatusRow, SampleRow

from api.auth import current_principal
from api.deps import DbSession

router = APIRouter(tags=["settings"])

DEFAULT_DAILY_QUOTA = 500
DEFAULT_QUARANTINE_MB = 2048


class EgressGate(BaseModel):
    state: Literal["open", "closed"]
    reason: str | None
    checked_at: datetime | None


class Quota(BaseModel):
    used: int
    limit: int


class QuarantineUse(BaseModel):
    used_bytes: int
    max_bytes: int


class Egress(BaseModel):
    ingest: EgressGate
    collector: EgressGate
    exit_ip_allowed: bool | None
    exit_ip: str | None
    collector_quota: Quota
    quarantine: QuarantineUse


def _int_env(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, ""))
    except ValueError:
        return default
    return value if value > 0 else default


def _checked_at(detail: dict[str, Any]) -> datetime | None:
    raw = detail.get("checked_at")
    if not isinstance(raw, str):
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _gate(detail: dict[str, Any] | None) -> EgressGate:
    """A missing row means no check has run yet: closed, reason ``no_status``."""
    if not detail:
        return EgressGate(state="closed", reason="no_status", checked_at=None)
    is_open = detail.get("open") is True
    reason = detail.get("reason")
    return EgressGate(
        state="open" if is_open else "closed",
        reason=None if is_open or not isinstance(reason, str) else reason[:64],
        checked_at=_checked_at(detail),
    )


async def _details(db: AsyncSession) -> dict[str, dict[str, Any]]:
    rows = await db.execute(
        select(EnrichmentStatusRow.name, EnrichmentStatusRow.detail).where(
            EnrichmentStatusRow.name.in_(("egress", "egress_collector"))
        )
    )
    return {r.name: r.detail for r in rows}


@router.get("/egress", response_model=Egress)
async def get_egress(request: Request, db: DbSession) -> Egress:
    details = await _details(db)
    ingest = details.get("egress")
    ingest_gate = _gate(ingest)
    collector_gate = _gate(details.get("egress_collector"))
    allowed: bool | None = None
    if ingest_gate.state == "open":
        allowed = True
    elif ingest_gate.reason == "ip_not_allowed":
        allowed = False
    principal = await current_principal(request)
    ip = ingest.get("egress_ip") if ingest else None
    exit_ip = (
        ip[:64] if isinstance(ip, str) and principal is not None and principal.is_admin else None
    )
    used = await db.scalar(
        select(EnrichmentQuotaRow.used).where(
            EnrichmentQuotaRow.provider == "collector",
            EnrichmentQuotaRow.day == datetime.now(UTC).date(),
        )
    )
    stored = await db.scalar(
        select(func.coalesce(func.sum(SampleRow.size), 0)).where(SampleRow.stored)
    )
    return Egress(
        ingest=ingest_gate,
        collector=collector_gate,
        exit_ip_allowed=allowed,
        exit_ip=exit_ip,
        collector_quota=Quota(
            used=used or 0, limit=_int_env("COLLECTOR_DAILY_QUOTA", DEFAULT_DAILY_QUOTA)
        ),
        quarantine=QuarantineUse(
            used_bytes=int(stored or 0),
            max_bytes=_int_env("QUARANTINE_MAX_MB", DEFAULT_QUARANTINE_MB) * 1024 * 1024,
        ),
    )

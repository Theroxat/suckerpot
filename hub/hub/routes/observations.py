"""POST /v1/observations: one batch per node and day."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from starlette.responses import Response
from suckerpot_netproto import ProtoError, buckets, models, sign

from ..auth import MAX_BODY_OBSERVATIONS, authenticate, reply
from ..context import get_ctx
from ..models import Batch, Observation
from ..never import Never

router = APIRouter()
CHUNK = 2000


def _merge(into: dict[str, Any], row: dict[str, Any]) -> None:
    for key in ("services", "activity", "tags", "families"):
        into[key] = sorted(set(into.get(key) or []) | set(row.get(key) or []))
    into["fetched"] = bool(into.get("fetched")) or bool(row.get("fetched"))
    into["file_type"] = into.get("file_type") or row.get("file_type")
    for key in ("sessions", "attempts"):
        values = [v for v in (into.get(key), row.get(key)) if v is not None]
        into[key] = max(values) if values else None


def build_rows(
    batch: models.ObservationBatch, never: Never
) -> tuple[list[dict[str, Any]], dict[str, int], dict[str, int]]:
    """Observation rows for a batch, items accepted per list and rejections by reason."""
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    accepted = {"sources": 0, "payloads": 0, "c2": 0, "files": 0}
    rejected: dict[str, int] = {}

    def reject(reason: str) -> None:
        rejected[reason] = rejected.get(reason, 0) + 1

    def put(kind: str, value: str, **fields: Any) -> None:
        row = {
            "kind": kind,
            "value": value,
            "services": [],
            "activity": [],
            "tags": [],
            "families": [],
            "sessions": None,
            "attempts": None,
            "fetched": False,
            "file_type": None,
            **fields,
        }
        existing = rows.get((kind, value))
        if existing is None:
            rows[(kind, value)] = row
        else:
            _merge(existing, row)

    for s in batch.sources:
        if never.has_ip(s.ip):
            reject("never_listed")
            continue
        put(
            "ip",
            s.ip,
            services=s.services,
            activity=s.activity,
            tags=s.tags,
            sessions=s.sessions,
            attempts=s.attempts,
        )
        accepted["sources"] += 1
    for p in batch.payloads:
        fam = [p.family] if p.family else []
        put(
            "url",
            p.url_b,
            activity=["download"],
            families=fam,
            fetched=p.fetched,
            file_type=p.file_type,
        )
        if p.host_ip is not None:
            if not never.has_ip(p.host_ip):
                put(
                    "ip",
                    p.host_ip,
                    activity=["download"],
                    tags=["malware-drop"],
                    families=fam,
                    fetched=p.fetched,
                )
        elif p.host_b is not None:
            put("domain", p.host_b, activity=["download"], families=fam, fetched=p.fetched)
        if p.sha256 is not None:
            if never.has_hash(p.sha256):
                reject("never_listed")
                continue
            put(
                "sha256",
                p.sha256,
                activity=["download"],
                families=fam,
                fetched=p.fetched,
                file_type=p.file_type,
            )
        accepted["payloads"] += 1
    for c in batch.c2:
        fam = [c.family] if c.family else []
        if c.ip is not None:
            if never.has_ip(c.ip):
                reject("never_listed")
                continue
            put("c2_ip", f"{c.ip}:{c.port}", families=fam)
        elif c.domain_b is not None:
            put("c2_domain", c.domain_b, families=fam)
        accepted["c2"] += 1
    for f in batch.files:
        if never.has_hash(f.sha256):
            reject("never_listed")
            continue
        put("sha256", f.sha256, families=[f.family] if f.family else [], file_type=f.file_type)
        accepted["files"] += 1
    return list(rows.values()), accepted, rejected


@router.post("/observations")
async def observations(request: Request) -> Response:
    ctx = get_ctx(request)
    async with ctx.sessionmaker() as session:
        caller, body = await authenticate(request, ctx, session, limit=MAX_BODY_OBSERVATIONS)
        batch = models.parse_body(
            models.ObservationBatch,
            body,
            max_bytes=MAX_BODY_OBSERVATIONS,
            allow_documentation=ctx.settings.allow_documentation,
        )
        day = buckets.parse_day(batch.day)
        code = buckets.check_batch_day(day, ctx.today())
        if code is not None:
            raise ProtoError(code)
        batch_id = sign.b64u_decode(batch.batch_id)
        existing = (
            await session.execute(
                select(Batch.batch_id).where(Batch.node_id == caller.node_id, Batch.day == day)
            )
        ).scalar_one_or_none()
        if existing is not None:
            if existing == batch_id:
                return reply(
                    request,
                    ctx,
                    200,
                    {
                        "accepted": dict.fromkeys(("sources", "payloads", "c2", "files"), 0),
                        "rejected": {},
                        "duplicate": True,
                    },
                )
            raise ProtoError("invalid_payload", "day already submitted")
        never = await ctx.never.get(session)
        rows, accepted, rejected = build_rows(batch, never)
        cap = ctx.settings.new_values_per_day
        if len(rows) > cap:
            rejected["cap"] = len(rows) - cap
            rows = rows[:cap]
        if caller.suspended:
            # Never told: the answer looks normal, nothing is stored.
            return reply(
                request, ctx, 200, {"accepted": accepted, "rejected": rejected, "duplicate": False}
            )
        try:
            session.add(Batch(node_id=caller.node_id, day=day, batch_id=batch_id))
            await session.flush()
            for i in range(0, len(rows), CHUNK):
                chunk = [{**r, "node_id": caller.node_id, "day": day} for r in rows[i : i + CHUNK]]
                await session.execute(pg_insert(Observation).values(chunk).on_conflict_do_nothing())
            await session.commit()
        except IntegrityError:
            await session.rollback()
            raise ProtoError("invalid_payload", "day already submitted") from None
    out = models.BatchAccepted(accepted=accepted, rejected=rejected, duplicate=False)
    return reply(request, ctx, 200, out.model_dump(mode="json"))

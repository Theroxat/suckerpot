"""GET /v1/info (unsigned)."""

from __future__ import annotations

from fastapi import APIRouter, Request
from starlette.responses import Response
from suckerpot_netproto import ProtoError, models
from suckerpot_netproto.enums import PROTOCOL

from ..auth import MAX_BODY_DEFAULT, MAX_BODY_OBSERVATIONS, bind_unsigned, reply
from ..context import get_ctx
from .enrol import current_difficulty

router = APIRouter()


@router.get("/info")
async def info(request: Request) -> Response:
    ctx = get_ctx(request)
    bind_unsigned(request)
    wait = ctx.address_limiter.check_unsigned(request)
    if wait:
        raise ProtoError("rate_limited", str(wait))
    difficulty = current_difficulty(ctx, request)
    s = ctx.settings
    body = models.InfoResponse(
        protocols=[PROTOCOL],
        hub_key=ctx.hub_key,
        pow=models.PowInfo(algorithm="sha256-leading-zero-bits", difficulty=difficulty),
        limits=models.Limits(
            max_observations_bytes=MAX_BODY_OBSERVATIONS,
            max_body_bytes=MAX_BODY_DEFAULT,
            max_sources=models.MAX_SOURCES,
            max_payloads=models.MAX_PAYLOADS,
            max_c2=models.MAX_C2,
            max_files=models.MAX_FILES,
            max_reveals=models.MAX_REVEALS,
            max_rechecks=models.MAX_RECHECKS,
        ),
        thresholds=models.Thresholds(min_nodes=s.min_nodes, min_age_days=s.node_min_age_days),
        today=ctx.today().isoformat(),
    )
    return reply(request, ctx, 200, body.model_dump(mode="json"))

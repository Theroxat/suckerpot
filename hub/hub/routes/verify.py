"""GET /v1/verify/reveals, GET /v1/verify/tasks and POST /v1/verify/results (design M32 6.2).

Reveals are open to every member; tasks and results need the ``verifier`` role (a suspended node
never has it). Nothing here carries a node id, a fingerprint or an address in an answer.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import Response
from suckerpot_netproto import ProtoError, models

from .. import verify
from ..auth import Caller, authenticate, reply
from ..context import get_ctx

router = APIRouter()

DEFAULT_LIMIT = 10


def _limit(raw: str | None) -> int:
    if raw is None:
        return DEFAULT_LIMIT
    if not raw.isdigit() or not 1 <= int(raw) <= models.MAX_VERIFY_TASKS:
        raise ProtoError("invalid_payload", "limit")
    return int(raw)


async def _require_verifier(session: AsyncSession, caller: Caller) -> None:
    if caller.suspended or not await verify.is_verifier(session, caller.node_id):
        raise ProtoError("not_verifier")


@router.get("/verify/reveals")
async def reveals(request: Request) -> Response:
    ctx = get_ctx(request)
    async with ctx.sessionmaker() as session:
        caller, _ = await authenticate(request, ctx, session)
        refs = (
            []
            if caller.suspended
            else await verify.reveal_refs(session, ctx.settings, caller.node_id, ctx.today())
        )
    out = models.VerifyRevealsResponse(
        items=[models.VerifyRevealRef(kind="url", value_b=b) for b in refs]
    )
    return reply(request, ctx, 200, out.model_dump(mode="json"))


@router.get("/verify/tasks")
async def tasks(request: Request) -> Response:
    ctx = get_ctx(request)
    async with ctx.sessionmaker() as session:
        caller, _ = await authenticate(request, ctx, session)
        limit = _limit(request.query_params.get("limit"))
        await _require_verifier(session, caller)
        leased = await verify.lease_tasks(session, ctx.settings, caller.node_id, ctx.now(), limit)
        await session.commit()
    out = models.VerifyTasksResponse(
        tasks=[
            models.VerifyTask(id=t.id, url=t.url, lease_until=verify.utc_stamp(t.lease_until))
            for t in leased
        ]
    )
    return reply(request, ctx, 200, out.model_dump(mode="json"))


@router.post("/verify/results")
async def results(request: Request) -> Response:
    ctx = get_ctx(request)
    async with ctx.sessionmaker() as session:
        caller, body = await authenticate(request, ctx, session)
        req = models.parse_body(models.VerifyResultsRequest, body)
        await _require_verifier(session, caller)
        accepted = rejected = 0
        if ctx.settings.verify_enabled:
            for item in req.items:
                stored = await verify.record_result(
                    session,
                    ctx.settings,
                    caller.node_id,
                    verify.ResultItem(
                        item.id, item.outcome, item.sha256, item.size, item.file_type, item.family
                    ),
                    ctx.now(),
                )
                if stored:
                    accepted += 1
                else:
                    rejected += 1
        else:
            rejected = len(req.items)
        await session.commit()
    return reply(request, ctx, 200, {"accepted": accepted, "rejected": rejected})

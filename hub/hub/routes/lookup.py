"""GET /v1/lookup?value=...: is one value on a public list? (design M30 section 9.1).

The answer is one word: ``listed``, ``removed`` (taken off lately because it expired or was taken
down) or ``not_listed``. It carries no sighting dates, categories, node counts or list names.
A value that was delisted or excluded answers ``not_listed``. The client address is used only by
the in-memory rate limiter.
"""

from __future__ import annotations

import ipaddress
from datetime import timedelta

from fastapi import APIRouter, Request
from sqlalchemy import text
from starlette.responses import Response
from suckerpot_netproto import ProtoError, blind
from suckerpot_netproto.feeds.models import check_domain, check_ip_global

from ..auth import reply
from ..context import AppContext, get_ctx

router = APIRouter()

REMOVED_WINDOW_DAYS = 30
MAX_VALUE = 253


def normalize_value(raw: str, *, allow_documentation: bool) -> str:
    """The canonical single address or exact host name, or ``ProtoError('invalid_payload')``."""
    value = raw.strip()
    if not value or len(value) > MAX_VALUE or not value.isascii():
        raise ProtoError("invalid_payload")
    try:
        try:
            return check_ip_global(
                str(ipaddress.ip_address(value)), allow_documentation=allow_documentation
            )
        except ValueError:
            pass
        return check_domain(blind.canonical_domain(value))
    except ValueError as exc:
        raise ProtoError("invalid_payload") from exc


def limit_unsigned(request: Request, ctx: AppContext) -> None:
    wait = ctx.address_limiter.blocked(request) or ctx.address_limiter.check_unsigned(request)
    if wait:
        raise ProtoError("rate_limited", str(wait))


@router.get("/lookup")
async def lookup(request: Request, value: str = "") -> Response:
    ctx = get_ctx(request)
    limit_unsigned(request, ctx)
    canonical = normalize_value(value, allow_documentation=ctx.settings.allow_documentation)
    since = ctx.today() - timedelta(days=REMOVED_WINDOW_DAYS)
    async with ctx.sessionmaker() as session:
        rows = (
            await session.execute(
                text(
                    "SELECT DISTINCT CASE WHEN state = 'listed' THEN 'listed' ELSE 'removed' END "
                    "FROM feed_entries WHERE value = :v AND (state = 'listed' OR "
                    "(state = 'removed' AND removed_reason IN ('expired', 'taken_down') "
                    "AND removed_day >= :since))"
                ),
                {"v": canonical, "since": since},
            )
        ).all()
    found = {r[0] for r in rows}
    status = "listed" if "listed" in found else "removed" if found else "not_listed"
    return reply(request, ctx, 200, {"value": canonical, "status": status})

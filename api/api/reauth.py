"""Re-authentication for sensitive changes: the signed-in account's own password, once more.

Used by the provider keys (M11) and the user management routes (M14). On top of the session
cookie and CSRF token, a change must come from the right origin, pass the re-authentication rate
limit (which also draws on the login's global budget) and carry the account's current password.
Five wrong passwords in a row end the session.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from api import accounts
from api import auth as auth_mod
from api.auth import LoginBusy, Principal, current_principal, same_origin

audit = logging.getLogger("api.audit")

REAUTH_SCOPE = "reauth"


def error(status: int, detail: str, code: str, headers: dict[str, str] | None = None) -> Response:
    return JSONResponse({"detail": detail, "code": code}, status_code=status, headers=headers)


async def _password_ok(
    service: auth_mod.AuthService, request: Request, principal: Principal, password: str
) -> bool:
    if principal.is_owner or principal.user_id is None:
        return await service.check_credentials(principal.username, password)
    factory = auth_mod._session_factory(request.app)
    if factory is None:
        await service.check_hash(None, password)
        return False
    async with factory() as db:
        row = await accounts.get_by_id(db, principal.user_id)
    return await service.check_hash(row.password_hash if row else None, password)


async def guard(
    request: Request, password: str | None, what: str = "change"
) -> tuple[Principal | None, Response | None]:
    """Origin, rate limit and re-authentication. Returns (principal, error response or None)."""
    service: auth_mod.AuthService = request.app.state.auth
    try:
        principal = await current_principal(request)
    except (SQLAlchemyError, OSError):
        return None, error(503, "Service unavailable", "unavailable")
    actor = principal.username if principal else "unknown"
    if not service.settings.disabled and not same_origin(request):
        return principal, error(403, "Cross-origin request refused", "origin")
    if principal is None and not service.settings.disabled:
        return None, error(401, "Not authenticated", "unauthenticated")
    if password is None or service.settings.disabled or principal is None:
        return principal, None
    ip = service.client_ip(request)
    retry = service.rate_limited(ip, REAUTH_SCOPE)
    if retry is not None:
        return principal, error(
            429, "Too many attempts", "rate_limited", {"Retry-After": str(retry)}
        )
    try:
        ok = await _password_ok(service, request, principal, password)
    except LoginBusy:
        return principal, error(429, "Too many attempts", "rate_limited", {"Retry-After": "2"})
    except (SQLAlchemyError, OSError):
        return principal, error(503, "Service unavailable", "unavailable")
    if not ok:
        service.record_failure(ip, REAUTH_SCOPE)
        audit.warning("%s refused: wrong password actor=%s ip=%s", what, actor, ip[:64])
        await asyncio.sleep(auth_mod.FAILURE_DELAY_S)
        if service.reauth_failed(principal.session):
            audit.warning("session revoked after repeated wrong passwords actor=%s", actor)
            return principal, error(
                401, "Signed out after too many wrong passwords.", "session_revoked"
            )
        return principal, error(403, "The password is incorrect.", "reauth_failed")
    service.reauth_ok(principal.session)
    return principal, None

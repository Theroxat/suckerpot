"""Enrichment API keys managed from the Settings page.

Keys are write-only: they are encrypted with AES-256-GCM (``suckerpot_db.secretbox``) before they
reach the database, and no response, log line or error ever contains one. Only the source, the
last four characters and the update time are shown back.

Every change needs, on top of the session cookie and the CSRF token that guard all unsafe
requests, the admin password again ("re-authentication"), checked with argon2 and rate limited
like the login. The API has no internet access, so "Test key" only leaves a request in the
database: ingest makes the one real call and writes the outcome into ``enrichment_status``.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, FastAPI, Path, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db import (
    EnrichmentStatusRow,
    ProviderSecretRow,
    ProviderTestRequestRow,
)
from suckerpot_db.secretbox import (
    ENV_VAR,
    PROVIDERS,
    SecretBox,
    SecretError,
    ValidationError,
    box_from_env,
    last4,
    validate_credential,
)

from api import auth as auth_mod
from api.auth import LoginBusy, same_origin
from api.deps import DbSession

router = APIRouter(tags=["settings"])
audit = logging.getLogger("api.audit")
log = logging.getLogger(__name__)

REAUTH_SCOPE = "reauth"
TEST_COOLDOWN = timedelta(seconds=20)

ProviderName = Annotated[str, Path(pattern="^(abuseipdb|greynoise|maxmind)$")]


class SetKeyBody(BaseModel):
    key: str = Field(max_length=256, repr=False)
    account_id: str | None = Field(default=None, max_length=32)
    password: str = Field(max_length=1024, repr=False)


class RemoveKeyBody(BaseModel):
    password: str = Field(max_length=1024, repr=False)


class KeyStored(BaseModel):
    provider: str
    source: str
    last4: str
    updated_at: datetime


class TestRequested(BaseModel):
    provider: str
    requested_at: datetime


def load_box() -> tuple[SecretBox | None, str | None]:
    """The encryption box from the environment, plus why it is unavailable (if it is)."""
    try:
        box = box_from_env()
    except SecretError as exc:
        log.error("%s is unusable (%s): editing keys in Settings is disabled", ENV_VAR, exc)
        return None, f"{ENV_VAR} is set but not usable. Check it in .env."
    if box is None:
        return None, f"Set {ENV_VAR} in .env to enable editing keys here."
    return box, None


def _error(status: int, detail: str, code: str, headers: dict[str, str] | None = None) -> Response:
    return JSONResponse({"detail": detail, "code": code}, status_code=status, headers=headers)


async def _guard(request: Request, password: str | None) -> tuple[str, Response | None]:
    """Origin, rate limit and re-authentication. Returns (actor, error response or None)."""
    service: auth_mod.AuthService = request.app.state.auth
    info = service.validate(service.session_token(request.scope))
    actor = info.username if info else "unknown"
    if not service.settings.disabled and not same_origin(request):
        return actor, _error(403, "Cross-origin request refused", "origin")
    if password is None or service.settings.disabled:
        return actor, None
    ip = service.client_ip(request)
    retry = service.rate_limited(ip, REAUTH_SCOPE)
    if retry is not None:
        return actor, _error(429, "Too many attempts", "rate_limited", {"Retry-After": str(retry)})
    try:
        ok = await service.check_credentials(actor, password)
    except LoginBusy:
        return actor, _error(429, "Too many attempts", "rate_limited", {"Retry-After": "2"})
    if not ok:
        audit.warning("provider key change refused: wrong password actor=%s ip=%s", actor, ip[:64])
        await asyncio.sleep(auth_mod.FAILURE_DELAY_S)
        return actor, _error(403, "The password is incorrect.", "reauth_failed")
    return actor, None


def _disabled_response(request: Request) -> Response:
    reason: str = request.app.state.secret_box_reason or "Key editing is disabled."
    return _error(503, reason, "editing_disabled")


@router.put("/settings/providers/{provider}", response_model=KeyStored)
async def set_key(
    provider: ProviderName, body: SetKeyBody, request: Request, session: DbSession
) -> Response:
    box: SecretBox | None = request.app.state.secret_box
    if box is None:
        return _disabled_response(request)
    try:
        credential = validate_credential(provider, body.key, body.account_id)
    except ValidationError as exc:
        return _error(422, str(exc), "invalid_key")
    actor, refused = await _guard(request, body.password)
    if refused is not None:
        return refused
    ciphertext, nonce = box.encrypt(provider, credential)
    now = datetime.now(UTC)
    values: dict[str, Any] = {
        "ciphertext": ciphertext,
        "nonce": nonce,
        "last4": last4(credential.key),
        "updated_at": now,
        "updated_by": actor,
    }
    stmt = insert(ProviderSecretRow).values(provider=provider, **values)
    await session.execute(stmt.on_conflict_do_update(index_elements=["provider"], set_=values))
    await session.commit()
    audit.info("provider key set provider=%s actor=%s at=%s", provider, actor, now.isoformat())
    return JSONResponse(
        KeyStored(
            provider=provider, source="settings", last4=values["last4"], updated_at=now
        ).model_dump(mode="json")
    )


@router.delete("/settings/providers/{provider}", status_code=204)
async def remove_key(
    provider: ProviderName, body: RemoveKeyBody, request: Request, session: DbSession
) -> Response:
    if request.app.state.secret_box is None:
        return _disabled_response(request)
    actor, refused = await _guard(request, body.password)
    if refused is not None:
        return refused
    await session.execute(delete(ProviderSecretRow).where(ProviderSecretRow.provider == provider))
    await session.commit()
    audit.info(
        "provider key removed provider=%s actor=%s at=%s", provider, actor, datetime.now(UTC)
    )
    return Response(status_code=204)


async def _configured(session: AsyncSession, provider: str) -> bool:
    if await session.get(ProviderSecretRow, provider) is not None:
        return True
    status = await session.get(EnrichmentStatusRow, provider)
    return bool(status and status.detail.get("configured"))


@router.post("/settings/providers/{provider}/test", status_code=202, response_model=TestRequested)
async def request_test(provider: ProviderName, request: Request, session: DbSession) -> Response:
    """Ask ingest to spend one quota unit on a real call with the current key."""
    actor, refused = await _guard(request, None)
    if refused is not None:
        return refused
    if not await _configured(session, provider):
        return _error(409, "There is no key to test for this provider.", "no_key")
    now = datetime.now(UTC)
    previous = await session.get(ProviderTestRequestRow, provider)
    if previous is not None and now - previous.requested_at < TEST_COOLDOWN:
        wait = int((TEST_COOLDOWN - (now - previous.requested_at)).total_seconds()) + 1
        return _error(429, "A test was just requested.", "cooldown", {"Retry-After": str(wait)})
    values: dict[str, Any] = {"requested_at": now, "requested_by": actor, "handled_at": None}
    stmt = insert(ProviderTestRequestRow).values(provider=provider, **values)
    await session.execute(stmt.on_conflict_do_update(index_elements=["provider"], set_=values))
    await session.commit()
    audit.info("provider key test requested provider=%s actor=%s", provider, actor)
    return JSONResponse(
        TestRequested(provider=provider, requested_at=now).model_dump(mode="json"), status_code=202
    )


async def validation_error_handler(_request: Request, exc: Exception) -> Response:
    """422 answers without the submitted values: a rejected key must not be echoed back."""
    raw = exc.errors() if isinstance(exc, RequestValidationError) else []
    errors = [{"loc": e.get("loc"), "msg": e.get("msg"), "type": e.get("type")} for e in raw]
    return JSONResponse({"detail": errors}, status_code=422)


def install(app: FastAPI) -> None:
    box, reason = load_box()
    app.state.secret_box = box
    app.state.secret_box_reason = reason
    app.add_exception_handler(RequestValidationError, validation_error_handler)


__all__ = ["PROVIDERS", "install", "router"]

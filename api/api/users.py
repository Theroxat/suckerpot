"""User management for administrators: ``/api/v1/users``.

Every route here needs an admin (``authorize`` / ``require_admin`` in ``api.authz``), the
admin's own password again (``api.reauth``, same rate limit as the provider keys) and writes an
audit entry in the same transaction as the change. An administrator cannot disable, demote,
reset or delete their own account (that would lock them out by mistake); the owner account of
``.env`` is not a row, so it cannot be touched from here at all.

A new account gets a strong temporary password that is returned once, in the response of the
request that created or reset it. Only its argon2 hash is stored, and it is never logged.
Whatever changes a user's access bumps ``session_version``, which ends their sessions.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db import UserRow

from api import accounts, audit, passwords
from api import auth as auth_mod
from api.audit import actor_id_of
from api.auth import LoginBusy, Principal
from api.authz import require_admin
from api.cursor import InvalidCursorError, decode_cursor, encode_cursor
from api.deps import DbSession
from api.reauth import error, guard

log = logging.getLogger(__name__)

router = APIRouter(tags=["users"])

USERNAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{2,31}$"
Role = Literal["admin", "viewer"]
UserId = Annotated[int, Path(ge=1, le=2**53)]
DEFAULT_LIMIT = 50
MAX_LIMIT = 200


class UserOut(BaseModel):
    id: int | None
    username: str
    display_name: str
    role: Role
    is_owner: bool
    disabled: bool
    must_change_password: bool
    locked_until: datetime | None
    created_at: datetime | None
    created_by: str | None
    last_login_at: datetime | None
    password_changed_at: datetime | None


class UserList(BaseModel):
    owner: UserOut
    items: list[UserOut]
    next_cursor: str | None


class Created(BaseModel):
    user: UserOut
    temporary_password: str = Field(repr=False)


class Reset(BaseModel):
    temporary_password: str = Field(repr=False)


class CreateBody(BaseModel):
    username: str = Field(pattern=USERNAME_PATTERN)
    display_name: str = Field(min_length=1, max_length=64)
    role: Role
    password: str = Field(max_length=1024, repr=False)


class PatchBody(BaseModel):
    role: Role | None = None
    disabled: bool | None = None
    display_name: str | None = Field(default=None, min_length=1, max_length=64)
    password: str = Field(max_length=1024, repr=False)


class PasswordOnly(BaseModel):
    password: str = Field(max_length=1024, repr=False)


def _out(row: UserRow) -> UserOut:
    now = datetime.now(UTC)
    return UserOut(
        id=row.id,
        username=row.username,
        display_name=row.display_name,
        role=row.role,  # type: ignore[arg-type]
        is_owner=False,
        disabled=row.disabled,
        must_change_password=row.must_change_password,
        locked_until=row.locked_until if accounts.is_locked(row, now) else None,
        created_at=row.created_at,
        created_by=row.created_by,
        last_login_at=row.last_login_at,
        password_changed_at=row.password_changed_at,
    )


def _service(request: Request) -> auth_mod.AuthService:
    service: auth_mod.AuthService = request.app.state.auth
    return service


def _owner(request: Request) -> UserOut:
    name = _service(request).settings.username
    return UserOut(
        id=None, username=name, display_name=name, role="admin", is_owner=True, disabled=False,
        must_change_password=False, locked_until=None, created_at=None, created_by=None,
        last_login_at=None, password_changed_at=None,
    )  # fmt: skip


def _no_store(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/users", response_model=UserList, dependencies=[Depends(require_admin)])
async def list_users(
    request: Request,
    db: DbSession,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> UserList:
    """The owner account first (read-only), then database users by id."""
    stmt = select(UserRow).order_by(UserRow.id).limit(limit + 1)
    if cursor:
        try:
            (last,) = decode_cursor(cursor)
            if not isinstance(last, int):
                raise ValueError
        except (InvalidCursorError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="invalid cursor") from exc
        stmt = stmt.where(UserRow.id > last)
    rows = list((await db.execute(stmt)).scalars())
    page, more = rows[:limit], len(rows) > limit
    return UserList(
        owner=_owner(request),
        items=[_out(r) for r in page],
        next_cursor=encode_cursor([page[-1].id]) if more and page else None,
    )


async def _locate(
    db: AsyncSession, user_id: int, admin: Principal | None, *, self_ok: bool = False
) -> tuple[UserRow | None, Response | None]:
    row = await accounts.get_by_id(db, user_id)
    if row is None:
        return None, error(404, "That user does not exist.", "not_found")
    if not self_ok and admin is not None and admin.user_id == row.id:
        return None, error(409, "You cannot do this to your own account.", "self_action")
    return row, None


def _busy() -> Response:
    return error(429, "Too many attempts", "rate_limited", {"Retry-After": "2"})


@router.post("/users", status_code=201, response_model=Created)
async def create_user(body: CreateBody, request: Request, db: DbSession) -> Response:
    admin, refused = await guard(request, body.password, "user management")
    if refused is not None or admin is None:
        return refused or error(401, "Not authenticated", "unauthenticated")
    service = _service(request)
    if service.is_owner_name(body.username) or body.username.lower() == (
        service.settings.username.lower()
    ):
        return error(409, "That username is already taken.", "username_taken")
    if await accounts.find_by_username(db, body.username) is not None:
        return error(409, "That username is already taken.", "username_taken")
    temporary = passwords.generate_temporary_password()
    try:
        hashed = await service.hash_password(temporary)
    except LoginBusy:
        return _busy()
    row = UserRow(
        username=body.username,
        display_name=body.display_name.strip(),
        role=body.role,
        password_hash=hashed,
        must_change_password=True,
        created_by=admin.username,
    )
    db.add(row)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        return error(409, "That username is already taken.", "username_taken")
    await audit.record(
        db, actor=admin.username, action="user.create", target=row.username,
        ip=service.client_ip(request), details={"role": row.role},
        actor_id=actor_id_of(admin), target_id=row.id,
    )  # fmt: skip
    await db.commit()
    await db.refresh(row)
    log.info("user created actor=%s role=%s", admin.username, row.role)
    payload = Created(user=_out(row), temporary_password=temporary).model_dump(mode="json")
    return _no_store(JSONResponse(payload, status_code=201))


@router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: UserId, body: PatchBody, request: Request, db: DbSession
) -> Response:
    if body.role is None and body.disabled is None and body.display_name is None:
        return error(422, "Nothing to change.", "empty_patch")
    admin, refused = await guard(request, body.password, "user management")
    if refused is not None or admin is None:
        return refused or error(401, "Not authenticated", "unauthenticated")
    row, problem = await _locate(db, user_id, admin)
    if problem is not None or row is None:
        return problem or error(404, "That user does not exist.", "not_found")
    ip = _service(request).client_ip(request)
    changes: list[tuple[str, dict[str, Any]]] = []
    revoke = False
    if body.role is not None and body.role != row.role:
        changes.append(("user.role", {"from": row.role, "to": body.role}))
        row.role = body.role
        revoke = True
    if body.disabled is not None and body.disabled != row.disabled:
        changes.append(("user.disable" if body.disabled else "user.enable", {}))
        row.disabled = body.disabled
        revoke = revoke or body.disabled
    if body.display_name is not None and body.display_name.strip() != row.display_name:
        changes.append(("user.rename", {}))
        row.display_name = body.display_name.strip()
    if revoke:
        row.session_version += 1
    for action, details in changes:
        await audit.record(
            db, actor=admin.username, action=action, target=row.username, ip=ip, details=details,
            actor_id=actor_id_of(admin), target_id=row.id,
        )  # fmt: skip
    await db.commit()
    await db.refresh(row)
    return JSONResponse(_out(row).model_dump(mode="json"))


@router.post("/users/{user_id}/reset-password", response_model=Reset)
async def reset_password(
    user_id: UserId, body: PasswordOnly, request: Request, db: DbSession
) -> Response:
    admin, refused = await guard(request, body.password, "user management")
    if refused is not None or admin is None:
        return refused or error(401, "Not authenticated", "unauthenticated")
    row, problem = await _locate(db, user_id, admin)
    if problem is not None or row is None:
        return problem or error(404, "That user does not exist.", "not_found")
    service = _service(request)
    temporary = passwords.generate_temporary_password()
    try:
        row.password_hash = await service.hash_password(temporary)
    except LoginBusy:
        return _busy()
    row.must_change_password = True
    row.password_changed_at = datetime.now(UTC)
    row.session_version += 1
    row.failed_logins = 0
    row.locked_until = None
    await audit.record(
        db, actor=admin.username, action="user.reset_password", target=row.username,
        ip=service.client_ip(request), actor_id=actor_id_of(admin), target_id=row.id,
    )  # fmt: skip
    service.clear_sources(row.id)
    await db.commit()
    return _no_store(JSONResponse({"temporary_password": temporary}))


@router.post("/users/{user_id}/unlock", response_model=UserOut)
async def unlock_user(
    user_id: UserId, body: PasswordOnly, request: Request, db: DbSession
) -> Response:
    admin, refused = await guard(request, body.password, "user management")
    if refused is not None or admin is None:
        return refused or error(401, "Not authenticated", "unauthenticated")
    row, problem = await _locate(db, user_id, admin, self_ok=True)
    if problem is not None or row is None:
        return problem or error(404, "That user does not exist.", "not_found")
    row.failed_logins = 0
    row.locked_until = None
    _service(request).clear_sources(row.id)
    await audit.record(
        db, actor=admin.username, action="user.unlock", target=row.username,
        ip=_service(request).client_ip(request),
        actor_id=actor_id_of(admin), target_id=row.id,
    )  # fmt: skip
    await db.commit()
    await db.refresh(row)
    return JSONResponse(_out(row).model_dump(mode="json"))


@router.post("/users/{user_id}/revoke-sessions", status_code=204)
async def revoke_sessions(
    user_id: UserId, body: PasswordOnly, request: Request, db: DbSession
) -> Response:
    admin, refused = await guard(request, body.password, "user management")
    if refused is not None or admin is None:
        return refused or error(401, "Not authenticated", "unauthenticated")
    row, problem = await _locate(db, user_id, admin, self_ok=True)
    if problem is not None or row is None:
        return problem or error(404, "That user does not exist.", "not_found")
    row.session_version += 1
    await audit.record(
        db, actor=admin.username, action="user.revoke_sessions", target=row.username,
        ip=_service(request).client_ip(request),
        actor_id=actor_id_of(admin), target_id=row.id,
    )  # fmt: skip
    await db.commit()
    return Response(status_code=204)


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    user_id: UserId, body: PasswordOnly, request: Request, db: DbSession
) -> Response:
    admin, refused = await guard(request, body.password, "user management")
    if refused is not None or admin is None:
        return refused or error(401, "Not authenticated", "unauthenticated")
    row, problem = await _locate(db, user_id, admin)
    if problem is not None or row is None:
        return problem or error(404, "That user does not exist.", "not_found")
    name, role, uid = row.username, row.role, row.id
    await db.delete(row)
    await audit.record(
        db, actor=admin.username, action="user.delete", target=name,
        ip=_service(request).client_ip(request), details={"role": role},
        actor_id=actor_id_of(admin), target_id=uid,
    )  # fmt: skip
    await db.commit()
    return Response(status_code=204)


__all__ = ["router"]

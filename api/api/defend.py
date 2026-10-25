"""Defend endpoints (M16): the scored blocklist, its overrides, exports and feed tokens.

Ingest scores indicators into ``blocklist_entries``; this module only reads them, plus the two
things an administrator manages: overrides (always allow / always block) and the bearer tokens of
the machine-readable feeds (``api.feeds``). Every write needs an admin (``api.authz``) and leaves
an audit entry; creating a feed token also asks for the account's password again.

Nothing here contacts anything: lists are text, built from rows already in the database.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import and_, func, or_, select, text, tuple_
from sqlalchemy.exc import IntegrityError
from suckerpot_db.blocklist_values import KINDS, normalize_value
from suckerpot_db.models import (
    BlocklistEntryRow as E,
)
from suckerpot_db.models import (
    BlocklistOverrideRow as O,
)
from suckerpot_db.models import EnrichmentStatusRow, FeedTokenRow

from api import audit, blocklist_rows, exports, feed_tokens
from api.audit import actor_id_of
from api.authz import require_admin
from api.cursor import InvalidCursorError, decode_cursor, encode_cursor
from api.deps import DbSession
from api.reauth import error, guard

router = APIRouter(tags=["defend"])

KindName = Literal["ip", "domain", "url", "hash"]
DEFAULT_LIMIT = 50
MAX_LIMIT = 200
MAX_ACTIVE_TOKENS = 20
MAX_OVERRIDES = 2000
TRUE_VALUES = {"1", "true", "yes", "on"}
CONTROL = {chr(c) for c in range(32)} | {chr(127)}


def feeds_enabled() -> bool:
    return os.environ.get("FEEDS_ENABLED", "false").strip().lower() in TRUE_VALUES


def _clean(value: str) -> str:
    value = value.strip()
    if CONTROL & set(value):
        raise ValueError("control characters are not allowed")
    return value


def _service(request: Request) -> Any:
    return request.app.state.auth


# -- schemas ----------------------------------------------------------------------------------


class EntryOut(BaseModel):
    kind: KindName
    value: str
    score: int
    reasons: list[str]
    first_seen: datetime
    last_seen: datetime
    sessions: int
    sources: int
    campaign_ids: list[int]
    benign: bool
    demo: bool
    override: Literal["allow", "block"] | None


class EntryPage(BaseModel):
    items: list[EntryOut]
    next_cursor: str | None


class KindTotals(BaseModel):
    kind: KindName
    total: int
    high: int  # score 70 and up
    listed: int  # score 50 and up: what the default feeds carry


class ReasonCount(BaseModel):
    reason: str
    count: int


class Summary(BaseModel):
    computed_at: datetime | None
    worker_enabled: bool | None
    feeds_enabled: bool
    kinds: list[KindTotals]
    top_reasons: list[ReasonCount]
    demo_entries: int
    overrides: int


class OverrideOut(BaseModel):
    id: int
    kind: KindName
    value: str
    action: Literal["allow", "block"]
    note: str | None
    created_by: str
    created_at: datetime
    expires_at: datetime | None


class OverridePage(BaseModel):
    items: list[OverrideOut]
    next_cursor: str | None


class OverrideBody(BaseModel):
    kind: KindName
    value: str = Field(min_length=1, max_length=512)
    action: Literal["allow", "block"]
    note: str | None = Field(default=None, max_length=256)
    expires_in_days: int | None = Field(default=None, ge=1, le=365)
    # Required while feeds are enabled: an override changes what firewalls receive.
    password: str | None = Field(default=None, max_length=1024, repr=False)

    @field_validator("value", "note")
    @classmethod
    def _no_control(cls, v: str | None) -> str | None:
        return None if v is None else _clean(v)


class TokenOut(BaseModel):
    id: int
    name: str
    hint: str
    kinds: list[KindName]
    min_score: int
    include_benign: bool
    created_by: str
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None
    last_used_ip: str | None
    use_count: int
    state: Literal["active", "revoked", "expired"]


class TokenPage(BaseModel):
    enabled: bool
    items: list[TokenOut]


def _default_kinds() -> list[KindName]:
    return ["ip"]


class TokenBody(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    kinds: list[KindName] = Field(default_factory=_default_kinds, min_length=1, max_length=4)
    min_score: int = Field(default=50, ge=0, le=100)
    include_benign: bool = False
    expires_in_days: int | None = Field(default=None, ge=1, le=730)
    password: str = Field(max_length=1024, repr=False)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        return _clean(v)


class TokenCreated(BaseModel):
    token: str = Field(repr=False)
    item: TokenOut


# -- helpers ----------------------------------------------------------------------------------


def _live(action: str) -> Any:
    return and_(O.action == action, or_(O.expires_at.is_(None), O.expires_at > func.now()))


def _like(q: str) -> str:
    escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _entry_out(e: E, override: str | None) -> EntryOut:
    return EntryOut(
        kind=e.kind,  # type: ignore[arg-type]
        value=e.value,
        score=e.score,
        reasons=list(e.reasons),
        first_seen=e.first_seen,
        last_seen=e.last_seen,
        sessions=e.sessions,
        sources=e.sources,
        campaign_ids=list(e.campaign_ids),
        benign=e.benign,
        demo=e.demo,
        override=override,  # type: ignore[arg-type]
    )


def _parse_entry_cursor(cursor: str) -> tuple[int, datetime, str, str]:
    try:
        score, seen, kind, value = decode_cursor(cursor)
        if not (isinstance(score, int) and isinstance(seen, str)):
            raise TypeError
        if not (isinstance(kind, str) and isinstance(value, str)):
            raise TypeError
        parsed = datetime.fromisoformat(seen)
        if parsed.tzinfo is None:
            raise ValueError
        return score, parsed.astimezone(UTC), kind, value
    except (InvalidCursorError, ValueError, TypeError, OverflowError) as exc:
        raise HTTPException(status_code=400, detail="invalid cursor") from exc


# -- blocklist --------------------------------------------------------------------------------


@router.get("/defend/summary", response_model=Summary)
async def summary(db: DbSession) -> Summary:
    """Totals per kind, the most common reasons and when ingest last recomputed the lists."""
    rows = (
        await db.execute(
            select(
                E.kind,
                func.count(),
                func.count().filter(E.score >= 70),
                func.count().filter(E.score >= 50),
                func.max(E.computed_at),
                func.count().filter(E.demo),
            )
            .where(E.benign.is_(False))
            .group_by(E.kind)
        )
    ).all()
    by_kind = {k: (t, h, ls) for k, t, h, ls, _c, _d in rows}
    computed = max((r[4] for r in rows), default=None)
    reasons = (
        await db.execute(
            text(
                "SELECT r AS reason, count(*) AS n FROM blocklist_entries, unnest(reasons) AS r "
                "WHERE NOT benign GROUP BY r ORDER BY n DESC, r LIMIT 8"
            )
        )
    ).all()
    status = (
        await db.execute(
            select(EnrichmentStatusRow.detail).where(EnrichmentStatusRow.name == "blocklist")
        )
    ).scalar()
    enabled = status.get("enabled") if isinstance(status, dict) else None
    overrides = (
        await db.execute(
            select(func.count())
            .select_from(O)
            .where(or_(O.expires_at.is_(None), O.expires_at > func.now()))
        )
    ).scalar() or 0
    return Summary(
        computed_at=computed,
        worker_enabled=enabled if isinstance(enabled, bool) else None,
        feeds_enabled=feeds_enabled(),
        kinds=[
            KindTotals(
                kind=k,
                total=by_kind.get(k, (0, 0, 0))[0],
                high=by_kind.get(k, (0, 0, 0))[1],
                listed=by_kind.get(k, (0, 0, 0))[2],
            )
            for k in KINDS
        ],
        top_reasons=[ReasonCount(reason=r, count=n) for r, n in reasons],
        demo_entries=sum(r[5] for r in rows),
        overrides=int(overrides),
    )


@router.get("/defend/blocklist", response_model=EntryPage)
async def list_entries(
    db: DbSession,
    kind: Annotated[KindName | None, Query()] = None,
    min_score: Annotated[int, Query(ge=0, le=100)] = 10,
    q: Annotated[str | None, Query(max_length=100)] = None,
    reason: Annotated[str | None, Query(pattern=r"^[a-z-]{1,32}$")] = None,
    include_benign: Annotated[bool, Query()] = False,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> EntryPage:
    """Scored entries, best first. Overrides show as ``override``; they never hide a row here."""
    override = (
        select(O.action)
        .where(
            O.kind == E.kind,
            O.value == E.value,
            or_(O.expires_at.is_(None), O.expires_at > func.now()),
        )
        .limit(1)
        .scalar_subquery()
    )
    stmt = (
        select(E, override.label("override"))
        .where(E.score >= min_score)
        .order_by(E.score.desc(), E.last_seen.desc(), E.kind.desc(), E.value.desc())
        .limit(limit + 1)
    )
    if kind:
        stmt = stmt.where(E.kind == kind)
    if q:
        stmt = stmt.where(E.value.ilike(_like(q.strip()), escape="\\"))
    if reason:
        stmt = stmt.where(E.reasons.contains([reason]))
    if not include_benign:
        stmt = stmt.where(E.benign.is_(False))
    if cursor:
        score, seen, ckind, cvalue = _parse_entry_cursor(cursor)
        stmt = stmt.where(
            tuple_(E.score, E.last_seen, E.kind, E.value) < (score, seen, ckind, cvalue)
        )
    rows = (await db.execute(stmt)).all()
    page = rows[:limit]
    last = page[-1][0] if page else None
    more = len(rows) > limit and last is not None
    return EntryPage(
        items=[_entry_out(e, o) for e, o in page],
        next_cursor=(
            encode_cursor([last.score, last.last_seen.isoformat(), last.kind, last.value])
            if more and last is not None
            else None
        ),
    )


@router.get("/defend/export")
async def export_list(
    db: DbSession,
    kind: Annotated[KindName, Query()],
    format: Annotated[exports.ExportFormat, Query()] = "txt",
    min_score: Annotated[int, Query(ge=0, le=100)] = 50,
    include_benign: Annotated[bool, Query()] = False,
    include_demo: Annotated[bool, Query()] = False,
) -> Response:
    """The list as a download: ``txt`` and ``alias`` (one value per line) or ``csv``."""
    if format == "alias" and kind != "ip":
        raise HTTPException(status_code=422, detail="alias lists hold IP addresses only")
    rows = await blocklist_rows.effective_rows(
        db, [kind], min_score=min_score, include_benign=include_benign, include_demo=include_demo,
        limit=exports.MAX_EXPORT_ROWS,
    )  # fmt: skip
    body, media = exports.render(format, kind, rows)
    return PlainTextResponse(
        body,
        media_type=media,
        headers={
            "Content-Disposition": f'attachment; filename="{exports.filename(kind, format)}"',
            "X-Entry-Count": str(len(rows)),
        },
    )


# -- overrides --------------------------------------------------------------------------------


def _override_out(o: O) -> OverrideOut:
    return OverrideOut(
        id=o.id,
        kind=o.kind,  # type: ignore[arg-type]
        value=o.value,
        action=o.action,  # type: ignore[arg-type]
        note=o.note,
        created_by=o.created_by,
        created_at=o.created_at,
        expires_at=o.expires_at,
    )


@router.get("/defend/overrides", response_model=OverridePage)
async def list_overrides(
    db: DbSession,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> OverridePage:
    stmt = select(O).order_by(O.id.desc()).limit(limit + 1)
    if cursor:
        try:
            (last_id,) = decode_cursor(cursor)
            if not isinstance(last_id, int):
                raise ValueError
        except (InvalidCursorError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="invalid cursor") from exc
        stmt = stmt.where(O.id < last_id)
    rows = list((await db.execute(stmt)).scalars())
    page = rows[:limit]
    more = len(rows) > limit and bool(page)
    return OverridePage(
        items=[_override_out(o) for o in page],
        next_cursor=encode_cursor([page[-1].id]) if more else None,
    )


@router.post("/defend/overrides", status_code=201, response_model=OverrideOut)
async def set_override(body: OverrideBody, request: Request, db: DbSession) -> Response:
    """Always allow or always block one value. Setting it again replaces the earlier decision."""
    if feeds_enabled() and not body.password:
        return error(403, "Enter your password to change what the feeds serve.", "reauth_required")
    principal, refused = await guard(request, body.password, "blocklist override")
    if refused is not None or principal is None:
        return refused or error(401, "Not authenticated", "unauthenticated")
    value = normalize_value(body.kind, body.value)
    if value is None:
        return error(422, "That is not a valid, blockable value for this kind.", "invalid_value")
    expires = (
        datetime.now(UTC) + timedelta(days=body.expires_in_days) if body.expires_in_days else None
    )
    row = (
        await db.execute(select(O).where(O.kind == body.kind, O.value == value))
    ).scalar_one_or_none()
    if row is None:
        count = (await db.execute(select(func.count()).select_from(O))).scalar() or 0
        if count >= MAX_OVERRIDES:
            return error(409, "Too many overrides. Remove some first.", "limit_reached")
        row = O(kind=body.kind, value=value, action=body.action, created_by=principal.username)
        db.add(row)
    row.action = body.action
    row.note = body.note or None
    row.expires_at = expires
    row.created_by = principal.username
    row.created_at = datetime.now(UTC)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        return error(409, "Another change got there first. Try again.", "conflict")
    await audit.record(
        db, actor=principal.username, action=f"blocklist.{body.action}",
        target=f"{body.kind}:{value}"[:120], ip=_service(request).client_ip(request),
        details={"expires_in_days": body.expires_in_days}, actor_id=actor_id_of(principal),
    )  # fmt: skip
    await db.commit()
    await db.refresh(row)
    return JSONResponse(_override_out(row).model_dump(mode="json"), status_code=201)


@router.delete("/defend/overrides/{override_id}", status_code=204)
async def delete_override(
    override_id: Annotated[int, Path(ge=1, le=2**53)], request: Request, db: DbSession
) -> Response:
    principal, refused = await guard(request, None, "blocklist override")
    if refused is not None or principal is None:
        return refused or error(401, "Not authenticated", "unauthenticated")
    row = await db.get(O, override_id)
    if row is None:
        return error(404, "That override does not exist.", "not_found")
    target = f"{row.kind}:{row.value}"[:120]
    await db.delete(row)
    await audit.record(
        db, actor=principal.username, action="blocklist.override_remove", target=target,
        ip=_service(request).client_ip(request), actor_id=actor_id_of(principal),
    )  # fmt: skip
    await db.commit()
    return Response(status_code=204)


# -- feed tokens ------------------------------------------------------------------------------


def _token_state(t: FeedTokenRow, now: datetime) -> Literal["active", "revoked", "expired"]:
    if t.revoked_at is not None:
        return "revoked"
    if t.expires_at is not None and t.expires_at <= now:
        return "expired"
    return "active"


def _token_out(t: FeedTokenRow) -> TokenOut:
    return TokenOut(
        id=t.id,
        name=t.name,
        hint=t.token_hint,
        kinds=list(t.kinds),  # type: ignore[arg-type]
        min_score=t.min_score,
        include_benign=t.include_benign,
        created_by=t.created_by,
        created_at=t.created_at,
        expires_at=t.expires_at,
        revoked_at=t.revoked_at,
        last_used_at=t.last_used_at,
        last_used_ip=t.last_used_ip,
        use_count=t.use_count,
        state=_token_state(t, datetime.now(UTC)),
    )


def _no_store(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/defend/feed-tokens", response_model=TokenPage, dependencies=[Depends(require_admin)])
async def list_tokens(db: DbSession) -> TokenPage:
    """The feed tokens (never the token text, only its first six characters). Admin only."""
    rows = (
        await db.execute(select(FeedTokenRow).order_by(FeedTokenRow.id.desc()).limit(MAX_LIMIT))
    ).scalars()
    return TokenPage(enabled=feeds_enabled(), items=[_token_out(t) for t in rows])


@router.post("/defend/feed-tokens", status_code=201, response_model=TokenCreated)
async def create_token(body: TokenBody, request: Request, db: DbSession) -> Response:
    """Create a token. The text is in this response only: it cannot be shown again."""
    principal, refused = await guard(request, body.password, "feed token")
    if refused is not None or principal is None:
        return refused or error(401, "Not authenticated", "unauthenticated")
    if not feeds_enabled():
        return error(409, "Feeds are switched off (FEEDS_ENABLED).", "feeds_disabled")
    now = datetime.now(UTC)
    active = (
        await db.execute(
            select(func.count())
            .select_from(FeedTokenRow)
            .where(
                FeedTokenRow.revoked_at.is_(None),
                or_(FeedTokenRow.expires_at.is_(None), FeedTokenRow.expires_at > now),
            )
        )
    ).scalar() or 0
    if active >= MAX_ACTIVE_TOKENS:
        return error(409, "Too many active tokens. Revoke one first.", "limit_reached")
    token, digest, hint = feed_tokens.new_token()
    row = FeedTokenRow(
        name=body.name,
        token_hash=digest,
        token_hint=hint,
        kinds=sorted(set(body.kinds)),
        min_score=body.min_score,
        include_benign=body.include_benign,
        created_by=principal.username,
        expires_at=now + timedelta(days=body.expires_in_days) if body.expires_in_days else None,
    )
    db.add(row)
    await db.flush()
    await audit.record(
        db, actor=principal.username, action="feed_token.create", target=body.name[:120],
        ip=_service(request).client_ip(request),
        details={"kinds": row.kinds, "min_score": row.min_score, "hint": hint},
        actor_id=actor_id_of(principal),
    )  # fmt: skip
    await db.commit()
    await db.refresh(row)
    payload = TokenCreated(token=token, item=_token_out(row)).model_dump(mode="json")
    return _no_store(JSONResponse(payload, status_code=201))


@router.post("/defend/feed-tokens/{token_id}/revoke", response_model=TokenOut)
async def revoke_token(
    token_id: Annotated[int, Path(ge=1, le=2**53)], request: Request, db: DbSession
) -> Response:
    """Stop a token from working at once. It needs no password: it only ever reduces access."""
    principal, refused = await guard(request, None, "feed token")
    if refused is not None or principal is None:
        return refused or error(401, "Not authenticated", "unauthenticated")
    row = await db.get(FeedTokenRow, token_id)
    if row is None:
        return error(404, "That token does not exist.", "not_found")
    if row.revoked_at is None:
        row.revoked_at = datetime.now(UTC)
        await audit.record(
            db, actor=principal.username, action="feed_token.revoke", target=row.name[:120],
            ip=_service(request).client_ip(request), details={"hint": row.token_hint},
            actor_id=actor_id_of(principal),
        )  # fmt: skip
        await db.commit()
        await db.refresh(row)
    return JSONResponse(_token_out(row).model_dump(mode="json"))


__all__ = ["router"]

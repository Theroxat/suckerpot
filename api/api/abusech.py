"""abuse.ch submission (M27, ``docs/design/m27.md`` sections 7 and 11): the owner's switch, the
Auth-Key, and the list of what was or may be submitted to URLhaus and ThreatFox.

Off by default, twice: the server flag ``ABUSECH_SUBMIT_ENABLED`` and the mode saved here (``off``,
``review`` or ``auto``). The API never talks to abuse.ch (it has no route out): it stores the
settings, approves a candidate (``candidate`` to ``pending``, a database trigger allows nothing
else) or cancels a pending row, and ingest does the rest. The Auth-Key is AES-GCM ciphertext: this
role writes it but its column grants cannot read it back, and no answer, log line or audit row
ever carries it. Settings are administrator only (GET included), writes ask for the password
again; the list is readable by both roles.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.secretbox import Credential, SecretBox, ValidationError, validate_credential

from api import audit as audit_db
from api import reauth
from api.abuse_core import env_flag, error, include_demo
from api.auth import Principal, current_principal
from api.authz import require_admin
from api.cursor import InvalidCursorError, decode_cursor, encode_cursor
from api.deps import DbSession

router = APIRouter(tags=["abusech"])
log = logging.getLogger("api.abusech")

KEY_AAD = "abusech_submission"  # a label, not a secret; bound to the ciphertext, ingest uses it too
MAX_SUBMIT = 20
URLHAUS_LINK_PREFIX = "https://urlhaus.abuse.ch/"
THREATFOX_LINK_PREFIX = "https://threatfox.abuse.ch/"
Mode = Literal["off", "review", "auto"]
Platform = Literal["urlhaus", "threatfox"]
STATUSES = (
    "candidate", "pending", "submitting", "submitted", "duplicate", "rejected", "failed",
    "cancelled", "skipped_known", "skipped_never_list", "guard_failed",
)  # fmt: skip

# ---- shapes ----------------------------------------------------------------------------------


class SubmissionSettings(BaseModel):
    mode: Mode
    threatfox_enabled: bool
    anonymous: bool
    auto_hold_minutes: int
    daily_cap: int
    key_set: bool
    key_last4: str | None = None
    server_enabled: bool
    submitted_today: int
    updated_at: datetime | None = None
    updated_by: str | None = None


class SettingsBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Mode = "off"
    threatfox_enabled: bool = False
    anonymous: bool = True
    auto_hold_minutes: int = Field(default=60, ge=10, le=1440)
    daily_cap: int = Field(default=20, ge=1, le=200)
    # The Auth-Key: omitted keeps the stored one. Write-only; never returned.
    key: str | None = Field(default=None, max_length=256, repr=False)
    current_password: str = Field(max_length=1024, repr=False)  # re-authentication


class PasswordBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(max_length=1024, repr=False)


class SubmissionOut(BaseModel):
    id: int
    platform: str
    ioc_type: str
    value: str
    status: str
    result_code: str | None = None
    lookup: str
    malware: str | None = None
    tags: list[str]
    reference: str | None = None  # an abuse.ch link built from a fixed prefix, or null
    auto: bool
    demo: bool
    created_at: datetime
    approved_at: datetime | None = None
    approved_by: str | None = None
    scheduled_at: datetime | None = None
    submitted_at: datetime | None = None
    done_at: datetime | None = None
    # Evidence from recorded sessions that showed the value (empty when none are linked).
    session_count: int = 0
    sensors: list[str] = Field(default_factory=list)
    last_seen: datetime | None = None


class SubmissionPage(BaseModel):
    items: list[SubmissionOut]
    next_cursor: str | None = None
    counts: dict[str, int]


class SubmitBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ids: list[int] = Field(min_length=1, max_length=MAX_SUBMIT)


class Submitted(BaseModel):
    approved: list[int]


class Cancelled(BaseModel):
    id: int
    status: str = "cancelled"


# ---- helpers ---------------------------------------------------------------------------------


def _actor(principal: Principal | None) -> str:
    return principal.username if principal else "anonymous"


def _client_ip(request: Request) -> str | None:
    return request.app.state.auth.client_ip(request)  # type: ignore[no-any-return]


def server_enabled() -> bool:
    return env_flag("ABUSECH_SUBMIT_ENABLED", False)


def link_of(reference: str | None) -> str | None:
    """Only a link that starts with a fixed abuse.ch prefix is ever shown."""
    if reference and reference.startswith((URLHAUS_LINK_PREFIX, THREATFOX_LINK_PREFIX)):
        return reference[:256]
    return None


def _no_store(model: BaseModel, status: int = 200) -> Response:
    return JSONResponse(
        model.model_dump(mode="json"), status_code=status, headers={"Cache-Control": "no-store"}
    )


PROFILE_COLUMNS = (
    "mode, threatfox_enabled, anonymous, auto_hold_minutes, daily_cap, key_set, key_last4, "
    "updated_at, updated_by"
)  # never the ciphertext or the nonce: the role cannot read them


async def _profile(db: AsyncSession) -> Any:
    return (
        await db.execute(text(f"SELECT {PROFILE_COLUMNS} FROM abusech_submission WHERE id = 1"))  # noqa: S608
    ).first()


async def _submitted_today(db: AsyncSession) -> int:
    """Rows that reached ``submitting`` today (UTC): what the daily cap counts."""
    return int(
        await db.scalar(
            text(
                "SELECT count(*) FROM abusech_submissions WHERE started_at >= "
                "(date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')"
            )
        )
        or 0
    )


async def _settings_out(db: AsyncSession) -> SubmissionSettings:
    row = await _profile(db)
    today = await _submitted_today(db)
    if row is None:
        return SubmissionSettings(
            mode="off", threatfox_enabled=False, anonymous=True, auto_hold_minutes=60,
            daily_cap=20, key_set=False, server_enabled=server_enabled(), submitted_today=today,
        )  # fmt: skip
    return SubmissionSettings(
        mode=row.mode,
        threatfox_enabled=row.threatfox_enabled,
        anonymous=row.anonymous,
        auto_hold_minutes=row.auto_hold_minutes,
        daily_cap=row.daily_cap,
        key_set=row.key_set,
        key_last4=row.key_last4,
        server_enabled=server_enabled(),
        submitted_today=today,
        updated_at=row.updated_at,
        updated_by=row.updated_by,
    )


# ---- settings (administrators only) ----------------------------------------------------------


@router.get(
    "/abusech/submission", response_model=SubmissionSettings, dependencies=[Depends(require_admin)]
)
async def get_settings(db: DbSession) -> Response:
    return _no_store(await _settings_out(db))


@router.put(
    "/abusech/submission", response_model=SubmissionSettings, dependencies=[Depends(require_admin)]
)
async def put_settings(body: SettingsBody, request: Request, db: DbSession) -> Response:
    if body.mode != "off" and not server_enabled():
        return error(
            422,
            "abuse.ch submission is disabled on this server (ABUSECH_SUBMIT_ENABLED).",
            "server_disabled",
        )
    old = await _profile(db)
    has_key = body.key is not None or (old is not None and bool(old.key_set))
    if body.mode == "auto" and not has_key:
        return error(422, "Automatic submission needs an abuse.ch Auth-Key.", "key_required")
    credential: Credential | None = None
    if body.key is not None:
        try:
            credential = validate_credential("abusech", body.key.strip(), None)
        except ValidationError as exc:
            return error(422, str(exc), "invalid_key")
        box: SecretBox | None = request.app.state.secret_box
        if box is None:
            reason: str = request.app.state.secret_box_reason or "Key storage is disabled."
            return error(503, reason, "editing_disabled")
    principal, refused = await reauth.guard(request, body.current_password, "abuse.ch settings")
    if refused is not None:
        return refused
    values: dict[str, Any] = {
        "mode": body.mode,
        "threatfox_enabled": body.threatfox_enabled,
        "anonymous": body.anonymous,
        "auto_hold_minutes": body.auto_hold_minutes,
        "daily_cap": body.daily_cap,
        "updated_by": _actor(principal)[:120],
    }
    changed = [
        k
        for k in ("mode", "threatfox_enabled", "anonymous", "auto_hold_minutes", "daily_cap")
        if old is None or getattr(old, k) != values[k]
    ]
    if credential is not None:
        ciphertext, nonce = box.encrypt(KEY_AAD, credential)  # type: ignore[union-attr]
        values |= {
            "key_ciphertext": ciphertext,
            "key_nonce": nonce,
            "key_last4": credential.key[-4:],
        }
        changed.append("key")
    if old is None:
        cols = ", ".join(values)
        marks = ", ".join(f":{k}" for k in values)
        await db.execute(
            text(f"INSERT INTO abusech_submission (id, {cols}) VALUES (1, {marks})"),  # noqa: S608
            values,
        )
    else:
        sets = ", ".join(f"{k} = :{k}" for k in values)
        await db.execute(
            text(f"UPDATE abusech_submission SET {sets}, updated_at = now() WHERE id = 1"),  # noqa: S608
            values,
        )
    await audit_db.record(
        db,
        actor=_actor(principal),
        action="abusech.settings.update",
        ip=_client_ip(request),
        details={"changed": changed, "mode": body.mode},  # names only, never values
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    return _no_store(await _settings_out(db))


@router.delete("/abusech/submission", status_code=204, dependencies=[Depends(require_admin)])
async def delete_settings(body: PasswordBody, request: Request, db: DbSession) -> Response:
    """Remove the key and switch submission off."""
    principal, refused = await reauth.guard(request, body.current_password, "abuse.ch key removal")
    if refused is not None:
        return refused
    await db.execute(
        text(
            "UPDATE abusech_submission SET key_ciphertext = NULL, key_nonce = NULL, "
            "key_last4 = NULL, mode = 'off', updated_at = now(), updated_by = :by WHERE id = 1"
        ),
        {"by": _actor(principal)[:120]},
    )
    await audit_db.record(
        db,
        actor=_actor(principal),
        action="abusech.settings.delete",
        ip=_client_ip(request),
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    return Response(status_code=204)


# ---- the list (both roles) -------------------------------------------------------------------


def to_out(row: Any) -> SubmissionOut:
    return SubmissionOut(
        id=row.id, platform=row.platform, ioc_type=row.ioc_type, value=row.value,
        status=row.status, result_code=row.result_code, lookup=row.lookup, malware=row.malware,
        tags=list(row.tags), reference=link_of(row.reference), auto=row.auto, demo=row.demo,
        created_at=row.created_at, approved_at=row.approved_at, approved_by=row.approved_by,
        scheduled_at=row.scheduled_at, submitted_at=row.submitted_at, done_at=row.done_at,
    )  # fmt: skip


EVIDENCE_SQL = """
SELECT a.id, count(DISTINCT s.session_id) AS session_count,
       COALESCE(array_agg(DISTINCT s.sensor) FILTER (WHERE s.sensor IS NOT NULL), '{}') AS sensors,
       max(i.last_seen) AS last_seen
FROM abusech_submissions a
LEFT JOIN fetch_targets f ON f.id = a.fetch_target_id
JOIN indicators i ON i.id = COALESCE(
    f.indicator_id,
    (SELECT x.id FROM indicators x
      WHERE (x.type = 'url' AND x.value = a.value)
         OR (a.platform = 'threatfox' AND x.type = 'ip' AND x.value = split_part(a.value, ':', 1))
      ORDER BY x.last_seen DESC LIMIT 1)
)
LEFT JOIN indicator_sessions s ON s.indicator_id = i.id
WHERE a.id = ANY(:ids)
GROUP BY a.id
"""


async def _evidence(db: AsyncSession, ids: list[int]) -> dict[int, Any]:
    """One bounded query for a whole page (at most 100 ids): never one query per row."""
    if not ids:
        return {}
    rows = (await db.execute(text(EVIDENCE_SQL), {"ids": ids})).all()
    return {r.id: r for r in rows}


@router.get("/abusech/submissions", response_model=SubmissionPage)
async def list_submissions(
    db: DbSession,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    status: Annotated[str | None, Query(max_length=200)] = None,
    platform: Annotated[Platform | None, Query()] = None,
    since: Annotated[datetime | None, Query()] = None,
) -> SubmissionPage | JSONResponse:
    base = ["(NOT demo OR :demo)"]
    params: dict[str, Any] = {"demo": include_demo()}
    if platform:
        base.append("platform = :platform")
        params["platform"] = platform
    if since:
        base.append("created_at >= :since")
        params["since"] = since if since.tzinfo else since.replace(tzinfo=UTC)
    counts_sql = (
        f"SELECT status, count(*) AS n FROM abusech_submissions WHERE {' AND '.join(base)} "  # noqa: S608
        "GROUP BY status"
    )
    counts = {s: 0 for s in STATUSES}
    for r in (await db.execute(text(counts_sql), params)).all():
        counts[r.status] = int(r.n)
    where = list(base)
    if status:
        wanted = [s.strip() for s in status.split(",") if s.strip()]
        if not wanted or any(s not in STATUSES for s in wanted):
            return error(422, "Unknown status.", "invalid_status")
        where.append("status = ANY(:statuses)")
        params["statuses"] = wanted
    if cursor:
        try:
            ts, last_id = decode_cursor(cursor)
            where.append("(created_at, id) < (:cts, :cid)")
            params["cts"] = datetime.fromisoformat(str(ts))
            params["cid"] = int(last_id)
        except (InvalidCursorError, ValueError, TypeError):
            return error(400, "Invalid cursor", "invalid_cursor")
    params["n"] = limit + 1
    sql = (
        f"SELECT * FROM abusech_submissions WHERE {' AND '.join(where)} "  # noqa: S608
        "ORDER BY created_at DESC, id DESC LIMIT :n"
    )
    rows = list((await db.execute(text(sql), params)).all())
    page = rows[:limit]
    nxt = (
        encode_cursor([page[-1].created_at.isoformat(), page[-1].id])
        if len(rows) > limit and page
        else None
    )
    evidence = await _evidence(db, [r.id for r in page])
    items = []
    for r in page:
        item = to_out(r)
        ev = evidence.get(r.id)
        if ev is not None:
            item.session_count = int(ev.session_count)
            item.sensors = sorted(ev.sensors)
            item.last_seen = ev.last_seen
        items.append(item)
    return SubmissionPage(items=items, next_cursor=nxt, counts=counts)


# ---- approve and cancel (administrators) ---------------------------------------------------------


@router.post("/abusech/submissions/submit", response_model=Submitted)
async def submit(body: SubmitBody, request: Request, db: DbSession) -> Submitted | JSONResponse:
    """Approve candidates: ``candidate`` to ``pending``; ingest sends them at its next cycle."""
    ids = sorted(set(body.ids))
    profile = await _profile(db)
    if profile is None or profile.mode == "off":
        return error(409, "abuse.ch submission is off.", "mode_off")
    if not server_enabled():
        return error(409, "abuse.ch submission is disabled on this server.", "server_disabled")
    if not profile.key_set:
        return error(409, "Add an abuse.ch Auth-Key first.", "key_required")
    rows = (
        await db.execute(
            text("SELECT id, status, lookup, demo, platform FROM abusech_submissions "
                 "WHERE id = ANY(:ids)"),
            {"ids": ids},
        )
    ).all()  # fmt: skip
    found = {r.id: r for r in rows}
    if set(found) != set(ids):
        return error(404, "Submission not found.", "not_found")
    if any(r.demo for r in rows):
        return error(409, "Demo submissions are never sent.", "demo_submission")
    if any(r.status != "candidate" for r in rows):
        return error(409, "Only a candidate can be submitted.", "not_a_candidate")
    if any(r.lookup != "unknown" for r in rows):
        return error(
            409, "The lookup has not finished or the value is already known.", "lookup_not_ready"
        )
    principal = await current_principal(request)
    await db.execute(
        text(
            "UPDATE abusech_submissions SET status = 'pending', approved_by = :by "
            "WHERE id = ANY(:ids) AND status = 'candidate'"
        ),
        {"by": _actor(principal)[:120], "ids": ids},
    )
    await audit_db.record(
        db,
        actor=_actor(principal),
        action="abusech.submit",
        ip=_client_ip(request),
        details={"ids": ids, "platforms": sorted({r.platform for r in rows})},
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    return Submitted(approved=ids)


@router.post("/abusech/submissions/{submission_id}/cancel", response_model=Cancelled)
async def cancel(submission_id: int, request: Request, db: DbSession) -> Cancelled | JSONResponse:
    row = (
        await db.execute(
            text("SELECT status FROM abusech_submissions WHERE id = :i"), {"i": submission_id}
        )
    ).first()
    if row is None:
        return error(404, "Submission not found.", "not_found")
    if row.status != "pending":
        return error(409, "Only a scheduled submission can be cancelled.", "not_pending")
    principal = await current_principal(request)
    result = await db.execute(
        text(
            "UPDATE abusech_submissions SET status = 'cancelled' "
            "WHERE id = :i AND status = 'pending'"
        ),
        {"i": submission_id},
    )
    if not result.rowcount:  # type: ignore[attr-defined]
        return error(409, "It was just sent or cancelled.", "not_pending")
    await audit_db.record(
        db,
        actor=_actor(principal),
        action="abusech.submit.cancel",
        ip=_client_ip(request),
        details={"id": submission_id},
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    return Cancelled(id=submission_id)

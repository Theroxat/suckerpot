"""Alert channels, rules, watched CVEs and the outbox (M18).

The API only manages configuration and reads results: it never sends anything (it has no internet
access). Ingest delivers, answers "send a test" requests and records what happened.

* A channel target (webhook URL or e-mail address) is validated against the official hosts, then
  encrypted with the Settings key (``suckerpot_db.alert_targets``) and never shown again, only a
  short hint. Creating a channel or changing its target needs the admin password again.
* Rules are seeded disabled. A rule can only be switched on with at least one enabled channel.
* Everything that changes is written to the audit log.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Path, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db import (
    AlertChannelRow,
    AlertOutboxRow,
    AlertRuleRow,
    AlertTestRequestRow,
    EnrichmentStatusRow,
    WatchedCveRow,
)
from suckerpot_db.alert_targets import (
    TargetError,
    encrypt_target,
    target_hint,
    validate_target,
)
from suckerpot_db.secretbox import SecretBox

from api import audit as audit_db
from api import auth as auth_mod
from api import reauth
from api.cursor import InvalidCursorError, decode_cursor, encode_cursor
from api.deps import DbSession

router = APIRouter(tags=["alerts"])

MAX_CHANNELS = 20
MAX_WATCHED = 200
TEST_COOLDOWN = timedelta(seconds=20)
MAX_TESTS_PER_DAY = 10
MAX_LIMIT = 100
RULE_KINDS = (
    "new_campaign",
    "new_download_host",
    "malware_drop",
    "watched_cve_seen",
    "weekly_report",
)

Kind = Literal["discord", "teams", "email"]
Severity = Literal["info", "notice", "warning", "severe"]
CVE_ID = Annotated[str, Path(pattern=r"^CVE-[0-9]{4}-[0-9]{4,10}$")]
RuleName = Annotated[str, Path(pattern="^(" + "|".join(RULE_KINDS) + ")$")]

_error = reauth.error


# ---- models -----------------------------------------------------------------------------------
class LastTest(BaseModel):
    state: str
    detail: str | None
    requested_at: datetime


class Channel(BaseModel):
    id: int
    kind: Kind
    name: str
    enabled: bool
    target_hint: str
    mask_ips: bool
    created_by: str
    created_at: datetime
    updated_at: datetime
    last_test: LastTest | None


class ChannelCreate(BaseModel):
    kind: Kind
    name: str = Field(min_length=1, max_length=64)
    target: str = Field(min_length=1, max_length=512, repr=False)
    mask_ips: bool = True
    enabled: bool = True
    password: str = Field(max_length=1024, repr=False)


class ChannelPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=64)
    enabled: bool | None = None
    mask_ips: bool | None = None
    target: str | None = Field(default=None, min_length=1, max_length=512, repr=False)
    password: str | None = Field(default=None, max_length=1024, repr=False)


class Rule(BaseModel):
    kind: str
    enabled: bool
    channel_ids: list[int]
    min_severity: Severity


class RuleUpdate(BaseModel):
    enabled: bool
    channel_ids: list[int] = Field(default_factory=list, max_length=32)
    min_severity: Severity = "warning"


class WatchedCve(BaseModel):
    cve_id: str
    added_by: str
    added_at: datetime


class OutboxItem(BaseModel):
    id: int
    rule_kind: str
    channel_id: int
    channel_name: str | None
    state: str
    attempts: int
    created_at: datetime
    sent_at: datetime | None
    error_code: str | None
    severity: str | None
    title: str | None
    summary: str | None


class OutboxPage(BaseModel):
    items: list[OutboxItem]
    next_cursor: str | None


class WorkerStatus(BaseModel):
    enabled: bool
    smtp_configured: bool
    can_decrypt: bool
    last_error: str | None
    updated_at: datetime | None


class AlertStatus(BaseModel):
    alerts: WorkerStatus
    reports_enabled: bool
    editing_enabled: bool
    editing_reason: str | None
    channels: int
    limits: dict[str, int]


class TestRequested(BaseModel):
    channel_id: int
    requested_at: datetime


# ---- helpers ----------------------------------------------------------------------------------
def _box(request: Request) -> SecretBox | None:
    box: SecretBox | None = getattr(request.app.state, "secret_box", None)
    return box


def _disabled(request: Request) -> Response:
    reason = getattr(request.app.state, "secret_box_reason", None) or "Editing is disabled."
    return _error(503, reason, "editing_disabled")


def _ip(request: Request) -> str:
    service: auth_mod.AuthService = request.app.state.auth
    return service.client_ip(request)


def _actor_id(request: Request) -> int | str | None:
    principal = request.scope.get("state", {}).get("principal")
    return audit_db.actor_id_of(principal)


async def _last_tests(session: AsyncSession) -> dict[int, LastTest]:
    t = AlertTestRequestRow
    rows = (
        await session.execute(
            select(t.channel_id, t.state, t.detail, t.requested_at)
            .distinct(t.channel_id)
            .order_by(t.channel_id, t.id.desc())
        )
    ).all()
    return {r.channel_id: LastTest(state=r.state, detail=r.detail, requested_at=r.requested_at)
            for r in rows}  # fmt: skip


def _channel(row: AlertChannelRow, tests: dict[int, LastTest]) -> Channel:
    return Channel(
        id=row.id,
        kind=row.kind,  # type: ignore[arg-type]
        name=row.name,
        enabled=row.enabled,
        target_hint=row.target_hint,
        mask_ips=row.mask_ips,
        created_by=row.created_by,
        created_at=row.created_at,
        updated_at=row.updated_at,
        last_test=tests.get(row.id),
    )


# ---- channels ---------------------------------------------------------------------------------
@router.get("/alerts/channels", response_model=list[Channel])
async def list_channels(session: DbSession) -> list[Channel]:
    rows = (
        await session.scalars(select(AlertChannelRow).order_by(AlertChannelRow.id).limit(100))
    ).all()
    tests = await _last_tests(session)
    return [_channel(r, tests) for r in rows]


@router.post("/alerts/channels", status_code=201, response_model=Channel)
async def create_channel(body: ChannelCreate, request: Request, session: DbSession) -> Response:
    box = _box(request)
    if box is None:
        return _disabled(request)
    try:
        target = validate_target(body.kind, body.target)
    except TargetError as exc:
        return _error(422, str(exc), "invalid_target")
    principal, refused = await reauth.guard(request, body.password, "alert channel change")
    if refused is not None:
        return refused
    actor = principal.username if principal else "unknown"
    count = (await session.execute(select(func.count()).select_from(AlertChannelRow))).scalar_one()
    if count >= MAX_CHANNELS:
        return _error(409, f"At most {MAX_CHANNELS} channels are allowed.", "too_many")
    row = AlertChannelRow(
        kind=body.kind,
        name=body.name.strip(),
        enabled=body.enabled,
        target_ciphertext=b"\0" * 40,  # replaced below, once the id is known
        target_hint=target_hint(body.kind, target),
        mask_ips=body.mask_ips,
        created_by=actor,
    )
    session.add(row)
    await session.flush()
    row.target_ciphertext = encrypt_target(box, row.id, target)
    await audit_db.record(
        session, actor=actor, action="alert_channel.create", target=f"{row.kind}:{row.name}",
        ip=_ip(request), actor_id=_actor_id(request), details={"channel_id": row.id},
    )  # fmt: skip
    await session.commit()
    await session.refresh(row)
    return JSONResponse(_channel(row, {}).model_dump(mode="json"), status_code=201)


@router.patch("/alerts/channels/{channel_id}", response_model=Channel)
async def update_channel(
    channel_id: int, body: ChannelPatch, request: Request, session: DbSession
) -> Response:
    row = await session.get(AlertChannelRow, channel_id)
    if row is None:
        return _error(404, "Channel not found.", "not_found")
    changes = body.model_dump(exclude_unset=True, exclude={"password"})
    if not changes:
        return _error(422, "Nothing to change.", "empty")
    target: str | None = None
    blob: bytes | None = None
    if "target" in changes:
        box = _box(request)
        if box is None:
            return _disabled(request)
        try:
            target = validate_target(row.kind, str(changes.pop("target")))
        except TargetError as exc:
            return _error(422, str(exc), "invalid_target")
        if body.password is None:  # reauth.guard lets a missing password through: not here
            return _error(
                401, "Enter your password to change where alerts go.", "password_required"
            )
        principal, refused = await reauth.guard(request, body.password, "alert channel change")
        if refused is not None:
            return refused
        actor = principal.username if principal else "unknown"
        blob = encrypt_target(box, row.id, target)
    else:
        principal, refused = await reauth.guard(request, None, "alert channel change")
        if refused is not None:
            return refused
        actor = principal.username if principal else "unknown"
    for key, value in changes.items():
        setattr(row, key, value.strip() if key == "name" else value)
    if target is not None and blob is not None:
        row.target_ciphertext = blob
        row.target_hint = target_hint(row.kind, target)
    row.updated_at = datetime.now(UTC)
    if changes.get("enabled") is False:
        await _drop_from_rules(session, channel_id)
    await audit_db.record(
        session, actor=actor, action="alert_channel.update", target=f"{row.kind}:{row.name}",
        ip=_ip(request), actor_id=_actor_id(request),
        details={"channel_id": row.id, "fields": sorted([*changes, *(["target"] if blob else [])])},
    )  # fmt: skip
    await session.commit()
    await session.refresh(row)
    tests = await _last_tests(session)
    return JSONResponse(_channel(row, tests).model_dump(mode="json"))


async def _drop_from_rules(session: AsyncSession, channel_id: int) -> None:
    """A disabled or deleted channel leaves every rule; a rule left empty is switched off."""
    rules = (await session.scalars(select(AlertRuleRow))).all()
    for rule in rules:
        if channel_id in rule.channel_ids:
            rule.channel_ids = [c for c in rule.channel_ids if c != channel_id]
            if not rule.channel_ids:
                rule.enabled = False


@router.delete("/alerts/channels/{channel_id}", status_code=204)
async def delete_channel(channel_id: int, request: Request, session: DbSession) -> Response:
    row = await session.get(AlertChannelRow, channel_id)
    if row is None:
        return _error(404, "Channel not found.", "not_found")
    principal, refused = await reauth.guard(request, None, "alert channel change")
    if refused is not None:
        return refused
    actor = principal.username if principal else "unknown"
    await _drop_from_rules(session, channel_id)
    await session.execute(delete(AlertChannelRow).where(AlertChannelRow.id == channel_id))
    await audit_db.record(
        session, actor=actor, action="alert_channel.delete", target=f"{row.kind}:{row.name}",
        ip=_ip(request), actor_id=_actor_id(request), details={"channel_id": channel_id},
    )  # fmt: skip
    await session.commit()
    return Response(status_code=204)


@router.post("/alerts/channels/{channel_id}/test", status_code=202, response_model=TestRequested)
async def request_test(channel_id: int, request: Request, session: DbSession) -> Response:
    """Ask ingest to send one harmless test message to the channel."""
    row = await session.get(AlertChannelRow, channel_id)
    if row is None:
        return _error(404, "Channel not found.", "not_found")
    principal, refused = await reauth.guard(request, None, "alert test")
    if refused is not None:
        return refused
    actor = principal.username if principal else "unknown"
    status = await session.get(EnrichmentStatusRow, "alerts")
    if status is None or not status.detail.get("enabled"):
        return _error(
            409, "Alerts are switched off on this server (ALERTS_ENABLED).", "alerts_disabled"
        )
    now = datetime.now(UTC)
    t = AlertTestRequestRow
    recent = (
        await session.execute(
            select(
                func.count(), func.max(t.requested_at), func.count().filter(t.state == "queued")
            ).where(t.channel_id == channel_id, t.requested_at > now - timedelta(days=1))
        )
    ).one()
    count, latest, queued = recent
    if queued:
        return _error(429, "A test is already waiting.", "pending", {"Retry-After": "20"})
    if latest is not None and latest > now - TEST_COOLDOWN:
        return _error(429, "A test was just requested.", "cooldown", {"Retry-After": "20"})
    if count >= MAX_TESTS_PER_DAY:
        return _error(429, "The daily limit of tests is reached.", "daily_cap")
    session.add(AlertTestRequestRow(channel_id=channel_id, requested_by=actor))
    await audit_db.record(
        session, actor=actor, action="alert_channel.test", target=f"{row.kind}:{row.name}",
        ip=_ip(request), actor_id=_actor_id(request), details={"channel_id": channel_id},
    )  # fmt: skip
    await session.commit()
    return JSONResponse(
        TestRequested(channel_id=channel_id, requested_at=now).model_dump(mode="json"),
        status_code=202,
    )


# ---- rules ------------------------------------------------------------------------------------
@router.get("/alerts/rules", response_model=list[Rule])
async def list_rules(session: DbSession) -> list[Rule]:
    rows = (await session.scalars(select(AlertRuleRow).order_by(AlertRuleRow.kind))).all()
    order = {k: i for i, k in enumerate(RULE_KINDS)}
    rows = sorted(rows, key=lambda r: order.get(r.kind, 99))
    return [
        Rule(
            kind=r.kind,
            enabled=r.enabled,
            channel_ids=list(r.channel_ids),
            min_severity=r.min_severity,  # type: ignore[arg-type]
        )
        for r in rows
    ]


@router.put("/alerts/rules/{kind}", response_model=Rule)
async def update_rule(
    kind: RuleName, body: RuleUpdate, request: Request, session: DbSession
) -> Response:
    rule = await session.get(AlertRuleRow, kind)
    if rule is None:
        return _error(404, "Rule not found.", "not_found")
    ids = sorted(set(body.channel_ids))
    if ids:
        found = (
            await session.scalars(
                select(AlertChannelRow.id).where(
                    AlertChannelRow.id.in_(ids), AlertChannelRow.enabled.is_(True)
                )
            )
        ).all()
        if sorted(found) != ids:
            return _error(422, "Choose channels that exist and are enabled.", "bad_channels")
    if body.enabled and not ids:
        return _error(422, "Choose at least one channel before switching a rule on.", "no_channel")
    principal, refused = await reauth.guard(request, None, "alert rule change")
    if refused is not None:
        return refused
    rule.enabled = body.enabled
    rule.channel_ids = ids
    rule.min_severity = body.min_severity
    await audit_db.record(
        session, actor=principal.username if principal else "unknown",
        action="alert_rule.update", target=kind, ip=_ip(request), actor_id=_actor_id(request),
        details={"enabled": body.enabled, "channels": ids, "min_severity": body.min_severity},
    )  # fmt: skip
    await session.commit()
    return JSONResponse(
        Rule(
            kind=kind, enabled=body.enabled, channel_ids=ids, min_severity=body.min_severity
        ).model_dump(mode="json")
    )


# ---- watched CVEs -----------------------------------------------------------------------------
@router.get("/alerts/watched-cves", response_model=list[WatchedCve])
async def list_watched(session: DbSession) -> list[WatchedCve]:
    rows = (
        await session.scalars(
            select(WatchedCveRow).order_by(WatchedCveRow.added_at.desc()).limit(MAX_WATCHED)
        )
    ).all()
    return [WatchedCve(cve_id=r.cve_id, added_by=r.added_by, added_at=r.added_at) for r in rows]


@router.put("/alerts/watched-cves/{cve_id}", response_model=WatchedCve)
async def watch_cve(cve_id: CVE_ID, request: Request, session: DbSession) -> Response:
    principal, refused = await reauth.guard(request, None, "watched CVE change")
    if refused is not None:
        return refused
    actor = principal.username if principal else "unknown"
    existing = await session.get(WatchedCveRow, cve_id)
    if existing is None:
        total = (
            await session.execute(select(func.count()).select_from(WatchedCveRow))
        ).scalar_one()
        if total >= MAX_WATCHED:
            return _error(409, f"At most {MAX_WATCHED} CVEs can be watched.", "too_many")
        existing = WatchedCveRow(cve_id=cve_id, added_by=actor)
        session.add(existing)
        await audit_db.record(
            session, actor=actor, action="watched_cve.add", target=cve_id, ip=_ip(request),
            actor_id=_actor_id(request),
        )  # fmt: skip
        await session.commit()
        await session.refresh(existing)
    return JSONResponse(
        WatchedCve(
            cve_id=existing.cve_id, added_by=existing.added_by, added_at=existing.added_at
        ).model_dump(mode="json")
    )


@router.delete("/alerts/watched-cves/{cve_id}", status_code=204)
async def unwatch_cve(cve_id: CVE_ID, request: Request, session: DbSession) -> Response:
    principal, refused = await reauth.guard(request, None, "watched CVE change")
    if refused is not None:
        return refused
    result = await session.execute(delete(WatchedCveRow).where(WatchedCveRow.cve_id == cve_id))
    if result.rowcount:  # type: ignore[attr-defined]
        await audit_db.record(
            session, actor=principal.username if principal else "unknown",
            action="watched_cve.remove", target=cve_id, ip=_ip(request),
            actor_id=_actor_id(request),
        )  # fmt: skip
    await session.commit()
    return Response(status_code=204)


# ---- outbox and status ------------------------------------------------------------------------
@router.get("/alerts/outbox", response_model=OutboxPage)
async def list_outbox(
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = 25,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    state: Annotated[Literal["pending", "sent", "failed", "suppressed"] | None, Query()] = None,
    rule: Annotated[str | None, Query(pattern="^(" + "|".join(RULE_KINDS) + ")$")] = None,
) -> Response:
    o, c = AlertOutboxRow, AlertChannelRow
    stmt = (
        select(o, c.name)
        .join(c, c.id == o.channel_id, isouter=True)
        .order_by(o.created_at.desc(), o.id.desc())
        .limit(limit + 1)
    )
    if state:
        stmt = stmt.where(o.state == state)
    if rule:
        stmt = stmt.where(o.rule_kind == rule)
    if cursor:
        try:
            values = decode_cursor(cursor)
            ts, oid = datetime.fromisoformat(str(values[0])), int(values[1])
            if ts.tzinfo is None:
                raise InvalidCursorError("malformed cursor")
        except (InvalidCursorError, ValueError, IndexError, TypeError):
            return _error(400, "Invalid cursor.", "bad_cursor")
        stmt = stmt.where((o.created_at < ts) | ((o.created_at == ts) & (o.id < oid)))
    rows = (await session.execute(stmt)).all()
    more = len(rows) > limit
    rows = rows[:limit]
    items = [_outbox_item(row, name) for row, name in rows]
    nxt = None
    if more and rows:
        last = rows[-1][0]
        nxt = encode_cursor([last.created_at.isoformat(), last.id])
    return JSONResponse(OutboxPage(items=items, next_cursor=nxt).model_dump(mode="json"))


def _outbox_item(row: AlertOutboxRow, channel_name: str | None) -> OutboxItem:
    p: dict[str, Any] = row.payload if isinstance(row.payload, dict) else {}

    def pick(key: str) -> str | None:
        value = p.get(key)
        return value[:300] if isinstance(value, str) else None

    return OutboxItem(
        id=row.id,
        rule_kind=row.rule_kind,
        channel_id=row.channel_id,
        channel_name=channel_name,
        state=row.state,
        attempts=row.attempts,
        created_at=row.created_at,
        sent_at=row.sent_at,
        error_code=row.error_code,
        severity=pick("severity"),
        title=pick("title"),
        summary=pick("summary"),
    )


@router.get("/alerts/status", response_model=AlertStatus)
async def alert_status(request: Request, session: DbSession) -> AlertStatus:
    alerts = await session.get(EnrichmentStatusRow, "alerts")
    reports = await session.get(EnrichmentStatusRow, "reports")
    detail: dict[str, Any] = alerts.detail if alerts else {}
    box = _box(request)
    count = (await session.execute(select(func.count()).select_from(AlertChannelRow))).scalar_one()
    return AlertStatus(
        alerts=WorkerStatus(
            enabled=bool(detail.get("enabled")),
            smtp_configured=bool(detail.get("smtp_configured")),
            can_decrypt=bool(detail.get("can_decrypt")),
            last_error=detail.get("last_error"),
            updated_at=alerts.updated_at if alerts else None,
        ),
        reports_enabled=bool(reports and reports.detail.get("enabled")),
        editing_enabled=box is not None,
        editing_reason=None if box else getattr(request.app.state, "secret_box_reason", None),
        channels=int(count),
        limits={"per_minute": 10, "per_day": 100, "all_channels_per_day": 300},
    )

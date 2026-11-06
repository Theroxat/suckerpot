"""Replies to abuse reports (M26): the list, the owner's corrections and pasted mail.

Ingest reads the mailbox and parses every message (this role has no route out and never sees
the mail's raw bytes again: pasted mail is written once and cleared when ingest has read it).
Here the owner sees what came back, links a reply to its report, confirms or reclassifies it,
and pastes a reply that never reached the mailbox.

Everything in a reply is text from a stranger: answers carry it as plain strings, never as markup
or links. Viewers see the sender's domain only; the address and the excerpt are for
administrators. GET routes are open to both roles; writes are administrator only by the
default-deny rule.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, Final, Literal

from fastapi import APIRouter, Path, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import and_, func, or_, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.models import AbuseRecipientRow, AbuseReplyRow, AbuseReportRow
from suckerpot_db.shared_mail import is_shared_domain

from api import audit as audit_db
from api.abuse_core import env_flag, error
from api.auth import Principal, current_principal
from api.cursor import InvalidCursorError, decode_cursor, encode_cursor
from api.deps import DbSession

router = APIRouter(tags=["abuse"])
log = logging.getLogger("api.abuse")

MAX_LIMIT: Final = 100
MAX_IMPORT_BYTES: Final = 262_144
MAX_BODY_BYTES: Final = MAX_IMPORT_BYTES + 16_384  # a multipart envelope around the file
IMPORTS_PER_HOUR: Final = 20
MAX_REPLY_DOMAINS: Final = 5
CLASSIFICATIONS: Final = (
    "auto_ack",
    "ticket_opened",
    "resolved",
    "rejected",
    "bounce",
    "human_reply",
    "unknown",
)
Classification = Literal[
    "auto_ack", "ticket_opened", "resolved", "rejected", "bounce", "human_reply", "unknown"
]
_DOMAIN = re.compile(
    r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$"
)
# The reply token as it appears in a subject: "(ref 0123456789ab)" and the like.
_REF = re.compile(r"(?<![a-z0-9])ref[ :#]{0,3}[0-9a-f]{12}(?![0-9a-z])", re.I)
_ADDRESS = re.compile(r"^[a-z0-9._%+\-]{1,64}@[a-z0-9.\-]{1,253}$")
_TICKET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,63}$")


def replies_enabled() -> bool:
    """The worker switch; without it nothing reads or parses mail, so imports would wait."""
    return env_flag("ABUSE_REPLIES_ENABLED", False)


# ---- shapes --------------------------------------------------------------------------------


class AttachmentsOut(BaseModel):
    count: int = 0
    types: list[str] = []
    bytes: int = 0


class ReplyOut(BaseModel):
    id: int
    source: Literal["imap", "paste"]
    received_at: datetime
    sent_at: datetime | None  # the Date header, as the sender wrote it
    from_domain: str | None
    from_address: str | None  # administrators only
    subject: str | None
    auth: Literal["pass", "fail", "none"]
    report: str | None  # public id of the report it belongs to
    match_method: str
    verified: bool
    needs_review: bool  # not linked, or not vouched for, or a bounce, and the owner has not looked
    classification: str
    classification_source: Literal["rule", "manual"]
    rule_id: str | None
    ticket_id: str | None
    dsn_status: str | None
    truncated: bool
    attachments: AttachmentsOut
    excerpt: str | None  # administrators only
    excerpt_purged: bool  # the text was deleted after its retention period
    reviewed_at: datetime | None
    reviewed_by: str | None  # administrators only


class ReplyPage(BaseModel):
    items: list[ReplyOut]
    next_cursor: str | None


class ReplyPatch(BaseModel):
    """Corrections. ``report`` set to a public id links the reply, to ``null`` unlinks it."""

    model_config = ConfigDict(extra="forbid")

    report: uuid.UUID | None = None
    classification: Classification | None = None
    ticket_id: Annotated[str | None, Field(max_length=64)] = None
    verified: bool | None = None
    trust_domain: bool = False  # add the sender's domain to the recipient's reply domains


class ImportJson(BaseModel):
    model_config = ConfigDict(extra="forbid")

    raw: Annotated[str, Field(min_length=1, max_length=MAX_IMPORT_BYTES)]
    report: uuid.UUID | None = None


class ImportAccepted(BaseModel):
    id: int
    status: str = "pending"


class ImportState(BaseModel):
    id: int
    status: Literal["pending", "done", "failed"]
    error_code: str | None
    reply_id: int | None
    requested_at: datetime
    done_at: datetime | None


# ---- helpers -------------------------------------------------------------------------------


def _actor(principal: Principal | None) -> str:
    return principal.username if principal else "anonymous"


def _client_ip(request: Request) -> str | None:
    return request.app.state.auth.client_ip(request)  # type: ignore[no-any-return]


def mask_reference(subject: str | None) -> str | None:
    """A subject without the report's reply token (it proves a reply belongs to the report)."""
    return None if subject is None else _REF.sub("ref ************", subject)


def _is_admin(principal: Principal | None) -> bool:
    return principal is not None and principal.is_admin


def _needs_review() -> Any:
    """SQL form of "waiting for the owner" (the same rule as ``outcome.summarise``)."""
    return and_(
        AbuseReplyRow.reviewed_at.is_(None),
        or_(
            AbuseReplyRow.report_id.is_(None),
            AbuseReplyRow.verified.is_(False),
            AbuseReplyRow.classification == "bounce",
        ),
    )


def reply_out(row: AbuseReplyRow, report: uuid.UUID | None, admin: bool) -> ReplyOut:
    """One reply. The address, the excerpt and the reviewer are left out for viewers."""
    waiting = row.reviewed_at is None and (
        row.report_id is None or not row.verified or row.classification == "bounce"
    )
    attachments = row.attachments if isinstance(row.attachments, dict) else {}
    return ReplyOut(
        id=row.id,
        source=row.source,  # type: ignore[arg-type]
        received_at=row.received_at,
        sent_at=row.date_header,
        from_domain=row.from_domain,
        from_address=row.from_address if admin else None,
        subject=row.subject if admin else mask_reference(row.subject),
        auth=row.auth,  # type: ignore[arg-type]
        report=str(report) if report is not None else None,
        match_method=row.match_method,
        verified=row.verified,
        needs_review=waiting,
        classification=row.classification,
        classification_source=row.classification_source,  # type: ignore[arg-type]
        rule_id=row.rule_id,
        ticket_id=row.ticket_id,
        dsn_status=row.dsn_status,
        truncated=row.truncated,
        attachments=AttachmentsOut(
            count=int(attachments.get("count", 0)),
            types=[str(t) for t in attachments.get("types", [])][:10],
            bytes=int(attachments.get("bytes", 0)),
        ),
        excerpt=row.excerpt if admin else None,
        excerpt_purged=row.excerpt_purged_at is not None,
        reviewed_at=row.reviewed_at,
        reviewed_by=row.reviewed_by if admin else None,
    )


async def replies_of_report(
    db: AsyncSession, report_id: int, public_id: uuid.UUID, admin: bool, limit: int = 20
) -> list[ReplyOut]:
    """The latest replies of one report, newest first."""
    rows = (
        await db.scalars(
            select(AbuseReplyRow)
            .where(AbuseReplyRow.report_id == report_id)
            .order_by(AbuseReplyRow.received_at.desc(), AbuseReplyRow.id.desc())
            .limit(limit)
        )
    ).all()
    return [reply_out(r, public_id, admin) for r in rows]


def _cursor(value: str) -> tuple[datetime, int]:
    values = decode_cursor(value)
    try:
        ts, rid = values
        if not isinstance(ts, str) or not isinstance(rid, int):
            raise TypeError
        parsed = datetime.fromisoformat(ts)
    except (ValueError, TypeError) as exc:
        raise InvalidCursorError("malformed cursor") from exc
    if parsed.tzinfo is None:
        raise InvalidCursorError("malformed cursor")
    return parsed.astimezone(UTC), rid


def _json(model: BaseModel, status: int = 200) -> Response:
    return JSONResponse(
        model.model_dump(mode="json"), status_code=status, headers={"Cache-Control": "no-store"}
    )


async def _report_ids(db: AsyncSession, ids: set[int]) -> dict[int, uuid.UUID]:
    if not ids:
        return {}
    rows = await db.execute(
        select(AbuseReportRow.id, AbuseReportRow.public_id).where(AbuseReportRow.id.in_(ids))
    )
    return {rid: pid for rid, pid in rows}


# ---- pasted mail (declared before /abuse/replies/{reply_id}) -------------------------------


_BOUNDARY = re.compile(r'boundary=(?:"([^"\r\n]{1,70})"|([^;\s"]{1,70}))', re.IGNORECASE)
_FIELD = re.compile(r'(?:^|[;\s])name="([^"]{1,64})"', re.IGNORECASE)


def _multipart_file(content_type: str, body: bytes) -> tuple[bytes | None, str | None]:
    """The ``file`` part (bytes) and the ``report`` field of a multipart/form-data body.

    A plain split on the boundary: the parts are only looked at, never decoded, executed or
    followed (an ``.eml`` is a ``message/rfc822`` part, which a mail parser would unpack)."""
    found = _BOUNDARY.search(content_type)
    if found is None:
        return None, None
    delimiter = b"--" + (found.group(1) or found.group(2)).encode("latin-1", "replace")
    file: bytes | None = None
    report: str | None = None
    for chunk in body.split(delimiter)[1:]:
        if chunk.startswith(b"--"):
            break
        head, sep, data = chunk.partition(b"\r\n\r\n")
        if not sep:
            continue
        data = data.removesuffix(b"\r\n")
        disposition = next(
            (
                line.decode("latin-1")
                for line in head.split(b"\r\n")
                if line.lower().startswith(b"content-disposition:")
            ),
            "",
        )
        field = _FIELD.search(disposition)
        if field is None:
            continue
        if field.group(1) == "file":
            file = data
        elif field.group(1) == "report":
            report = data.decode("utf-8", "replace").strip() or None
    return file, report


async def _read_body(request: Request) -> bytes | None:
    """The request body, or None once it is larger than a reply may be."""
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


async def _hint(db: AsyncSession, public_id: uuid.UUID | None) -> tuple[int | None, bool]:
    """``(report id or None, found)`` for the optional report the owner names."""
    if public_id is None:
        return None, True
    row = (
        await db.execute(
            select(AbuseReportRow.id, AbuseReportRow.status).where(
                AbuseReportRow.public_id == public_id
            )
        )
    ).first()
    if row is None or row.status not in ("sent", "closed"):
        return None, False
    return int(row.id), True


@router.post("/abuse/replies/import", status_code=202, response_model=ImportAccepted)
async def import_reply(request: Request, db: DbSession) -> Response:
    """Paste a reply (JSON ``{raw, report?}``) or upload an ``.eml`` (multipart ``file``).
    Ingest parses it like mailbox mail, links it to a report, and clears the raw text."""
    if not replies_enabled():
        return error(409, "Reading replies is switched off on this server.", "replies_disabled")
    body = await _read_body(request)
    if body is None:
        return error(413, "That file is larger than a reply can be (256 KiB).", "too_large")
    ctype = request.headers.get("content-type", "")
    raw: bytes | None
    hint_text: str | None = None
    if ctype.lower().startswith("multipart/form-data"):
        try:
            raw, hint_text = _multipart_file(ctype, body)
        except Exception:
            raw = None
    else:
        try:
            parsed = ImportJson.model_validate(json.loads(body))
        except ValueError, ValidationError:
            return error(
                422, "Send {raw, report?} as JSON or an .eml as a form upload.", "bad_body"
            )
        raw, hint_text = parsed.raw.encode("utf-8"), str(parsed.report) if parsed.report else None
    if raw is None or not raw.strip():
        return error(422, "No mail was found in the request.", "empty")
    if len(raw) > MAX_IMPORT_BYTES:
        return error(413, "That file is larger than a reply can be (256 KiB).", "too_large")
    public: uuid.UUID | None = None
    if hint_text:
        try:
            public = uuid.UUID(hint_text)
        except ValueError:
            return error(422, "That report id is not valid.", "bad_report")
    report_id, found = await _hint(db, public)
    if not found:
        return error(409, "That report was not sent, so it cannot have a reply.", "not_sent")
    recent = await db.scalar(
        text(
            "SELECT count(*) FROM abuse_reply_imports "
            "WHERE requested_at > now() - interval '1 hour'"
        )
    )
    if int(recent or 0) >= IMPORTS_PER_HOUR:
        return error(429, "Too many replies pasted this hour. Try again later.", "rate_limited")
    principal = await current_principal(request)
    new_id = await db.scalar(
        text(
            "INSERT INTO abuse_reply_imports (report_id, raw, requested_by) "
            "VALUES (:r, :raw, :by) RETURNING id"
        ),
        {"r": report_id, "raw": raw, "by": _actor(principal)[:120]},
    )
    await audit_db.record(
        db,
        actor=_actor(principal),
        action="abuse.reply.import",
        ip=_client_ip(request),
        details={"bytes": len(raw), "report": bool(public)},  # sizes only, never the mail
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    return _json(ImportAccepted(id=int(new_id or 0)), 202)


@router.get("/abuse/replies/imports/{import_id}", response_model=ImportState)
async def import_state(
    import_id: Annotated[int, Path(ge=1, le=2**62)], request: Request, db: DbSession
) -> Response:
    """Where a pasted reply stands. Only the owner's own paste is of interest, so both roles
    may ask; the answer carries no mail content."""
    row = (
        await db.execute(
            text(
                "SELECT id, status, error_code, reply_id, requested_at, done_at "
                "FROM abuse_reply_imports WHERE id = :i"
            ),
            {"i": import_id},
        )
    ).first()
    if row is None:
        return error(404, "Not found.", "not_found")
    return _json(
        ImportState(
            id=row.id,
            status=row.status,
            error_code=row.error_code,
            reply_id=row.reply_id,
            requested_at=row.requested_at,
            done_at=row.done_at,
        )
    )


# ---- the list ------------------------------------------------------------------------------


@router.get("/abuse/replies", response_model=ReplyPage)
async def list_replies(
    request: Request,
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = 25,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    report: uuid.UUID | None = None,
    classification: Classification | None = None,
    matched: bool | None = None,
    needs_review: bool | None = None,
    since: AwareDatetime | None = None,
) -> Response:
    admin = _is_admin(await current_principal(request))
    stmt = select(AbuseReplyRow, AbuseReportRow.public_id).join(
        AbuseReportRow, AbuseReportRow.id == AbuseReplyRow.report_id, isouter=True
    )
    if report is not None:
        stmt = stmt.where(AbuseReportRow.public_id == report)
    if classification is not None:
        stmt = stmt.where(AbuseReplyRow.classification == classification)
    if matched is not None:
        stmt = stmt.where(
            AbuseReplyRow.report_id.is_not(None) if matched else AbuseReplyRow.report_id.is_(None)
        )
    if needs_review is not None:
        stmt = stmt.where(_needs_review() if needs_review else ~_needs_review())
    if since is not None:
        stmt = stmt.where(AbuseReplyRow.received_at >= since)
    if cursor is not None:
        try:
            c_ts, c_id = _cursor(cursor)
        except InvalidCursorError:
            return error(400, "Invalid cursor.", "invalid_cursor")
        stmt = stmt.where(
            (AbuseReplyRow.received_at < c_ts)
            | ((AbuseReplyRow.received_at == c_ts) & (AbuseReplyRow.id < c_id))
        )
    stmt = stmt.order_by(AbuseReplyRow.received_at.desc(), AbuseReplyRow.id.desc()).limit(limit + 1)
    rows = (await db.execute(stmt)).all()
    page, more = rows[:limit], len(rows) > limit
    nxt = (
        encode_cursor([page[-1][0].received_at.isoformat(), page[-1][0].id])
        if more and page
        else None
    )
    return _json(ReplyPage(items=[reply_out(r, pid, admin) for r, pid in page], next_cursor=nxt))


async def _one(db: AsyncSession, reply_id: int) -> tuple[AbuseReplyRow, uuid.UUID | None] | None:
    found = (
        await db.execute(
            select(AbuseReplyRow, AbuseReportRow.public_id)
            .join(AbuseReportRow, AbuseReportRow.id == AbuseReplyRow.report_id, isouter=True)
            .where(AbuseReplyRow.id == reply_id)
        )
    ).first()
    return None if found is None else (found[0], found[1])


ReplyId = Annotated[int, Path(ge=1, le=2**62)]


@router.get("/abuse/replies/{reply_id}", response_model=ReplyOut)
async def get_reply(reply_id: ReplyId, request: Request, db: DbSession) -> Response:
    admin = _is_admin(await current_principal(request))
    found = await _one(db, reply_id)
    if found is None:
        return error(404, "Reply not found.", "not_found")
    return _json(reply_out(found[0], found[1], admin))


@router.patch("/abuse/replies/{reply_id}", response_model=ReplyOut)
async def patch_reply(
    reply_id: ReplyId, body: ReplyPatch, request: Request, db: DbSession
) -> Response:
    """Link, confirm or reclassify a reply. The outcome of the report follows on ingest's next
    cycle (within a minute): this role cannot write it."""
    found = await _one(db, reply_id)
    if found is None:
        return error(404, "Reply not found.", "not_found")
    row = found[0]
    sent = body.model_fields_set
    values: dict[str, Any] = {}
    names: list[str] = []
    target_report = row.report_id
    if "report" in sent:
        if body.report is None:
            values |= {"report_id": None, "match_method": "none", "verified": False}
            target_report = None
        else:
            target = (
                await db.execute(
                    select(AbuseReportRow.id, AbuseReportRow.status).where(
                        AbuseReportRow.public_id == body.report
                    )
                )
            ).first()
            if target is None:
                return error(404, "Report not found.", "not_found")
            if target.status not in ("sent", "closed"):
                return error(409, "That report was not sent.", "not_sent")
            # The owner linked it by hand: that is their word for it, unless they say otherwise.
            values |= {"report_id": target.id, "match_method": "manual", "verified": True}
            target_report = int(target.id)
        names.append("report")
    if body.classification is not None:
        values |= {"classification": body.classification, "classification_source": "manual"}
        names.append("classification")
    if "ticket_id" in sent:
        ticket = (body.ticket_id or "").strip()
        if ticket and not _TICKET.match(ticket):
            return error(422, "The ticket id has characters that are not allowed.", "bad_ticket")
        values["ticket_id"] = ticket or None
        names.append("ticket_id")
    if body.verified is not None:
        values["verified"] = body.verified
        names.append("verified")
    domain_note: str | None = None
    if body.trust_domain:
        domain = (row.from_domain or "").lower()
        if target_report is None:
            return error(409, "Link the reply to a report first.", "no_report")
        if not _DOMAIN.match(domain):
            return error(409, "This reply has no sender domain to trust.", "no_domain")
        # A free or shared mail provider speaks for nobody: trust the exact address instead.
        address = (row.from_address or "").lower()
        if is_shared_domain(domain):
            if not _ADDRESS.match(address):
                return error(409, "This reply has no sender address to trust.", "no_address")
            domain = address
        domain_note = domain
        names.append("trust_domain")
    if not names:
        return error(422, "Nothing to change.", "empty")
    principal = await current_principal(request)
    values |= {"reviewed_at": datetime.now(UTC), "reviewed_by": _actor(principal)[:120]}
    if domain_note is not None:
        added = await _trust(db, target_report, domain_note)
        if added == "full":
            await db.rollback()
            return error(409, "Five reply domains is the most one provider can have.", "too_many")
    await db.execute(update(AbuseReplyRow).where(AbuseReplyRow.id == reply_id).values(**values))
    await audit_db.record(
        db,
        actor=_actor(principal),
        action="abuse.reply.update",
        target=str(reply_id),
        ip=_client_ip(request),
        details={"fields": names},  # field names only; no mail text, no addresses
        actor_id=audit_db.actor_id_of(principal),
    )
    await db.commit()
    db.expire_all()
    fresh = await _one(db, reply_id)
    assert fresh is not None  # noqa: S101 - it was just updated
    return _json(reply_out(fresh[0], fresh[1], True))


async def _trust(db: AsyncSession, report_id: int | None, domain: str) -> str:
    """Add ``domain`` to the reply domains of the report's recipient. ``full`` if it has five."""
    if report_id is None:
        return "full"
    rec = (
        await db.execute(
            select(AbuseRecipientRow.id, AbuseRecipientRow.reply_domains)
            .join(AbuseReportRow, AbuseReportRow.recipient_id == AbuseRecipientRow.id)
            .where(AbuseReportRow.id == report_id)
        )
    ).first()
    if rec is None:
        return "full"
    current = list(rec.reply_domains or [])
    if domain in current:
        return "present"
    if len(current) >= MAX_REPLY_DOMAINS:
        return "full"
    try:
        await db.execute(
            update(AbuseRecipientRow)
            .where(AbuseRecipientRow.id == rec.id)
            .values(reply_domains=[*current, domain])
        )
    except DBAPIError:
        return "full"
    return "added"


# ---- counts for the status card ------------------------------------------------------------


async def counts(db: AsyncSession) -> tuple[int, int]:
    """``(unmatched, needs_review)``: replies the owner has not looked at yet."""
    unmatched = await db.scalar(
        select(func.count())
        .select_from(AbuseReplyRow)
        .where(AbuseReplyRow.report_id.is_(None), AbuseReplyRow.reviewed_at.is_(None))
    )
    waiting = await db.scalar(
        select(func.count())
        .select_from(AbuseReplyRow)
        .where(AbuseReplyRow.report_id.is_not(None), _needs_review())
    )
    return int(unmatched or 0), int(waiting or 0)

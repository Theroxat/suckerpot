"""Machine-readable blocklist feeds (M16), for firewalls and other tools.

This is the only part of the API outside the dashboard login. It is mounted only when
``FEEDS_ENABLED=true`` (off by default), under ``/feeds`` and outside ``/api/v1``, and it
authenticates with a bearer token created in Settings:

* ``GET /feeds/{token}/{kind}.{txt|csv}`` for tools that can only fetch a URL (OPNsense and
  pfSense URL-table aliases). The token is part of the path, so treat the URL like a password and
  revoke the token if it leaks. The API does not write access logs.
* ``GET /feeds/{kind}.{txt|csv}`` with ``Authorization: Bearer <token>`` for tools that can send
  a header (preferred).

A token has 256 random bits and is stored only as a hash; it can be revoked at any time or given
an expiry; it limits which kinds, which minimum score and whether research scanners are listed.
Requests are rate limited per client address and per token, wrong tokens count against the
client address, and every refusal looks the same (404), so a probe learns nothing. Demo entries
are never served. The feed is read-only, built from rows already in the database.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from datetime import UTC, datetime

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import or_, select, update
from sqlalchemy.exc import SQLAlchemyError
from suckerpot_db.models import FeedTokenRow

from api import blocklist_rows, exports, feed_tokens
from api.deps import DbSession

log = logging.getLogger(__name__)

router = APIRouter(tags=["feeds"])

KIND_NAMES = ("ip", "domain", "url", "hash")
EXTENSIONS = ("txt", "csv")
# Requests per window. A firewall asks every few minutes to every hour; this is generous.
PER_IP_LIMIT = (60, 60.0)
PER_TOKEN_LIMIT = (30, 60.0)
FAILURE_LIMIT = (10, 60.0)
MAX_TRACKED = 10_000


class Window:
    """A sliding-window counter per key, with bounded memory."""

    def __init__(self, limit: int, seconds: float) -> None:
        self.limit = limit
        self.seconds = seconds
        self.hits: dict[str, deque[float]] = {}

    def retry_after(self, key: str, now: float) -> int | None:
        q = self.hits.get(key)
        if q is None:
            return None
        while q and q[0] <= now - self.seconds:
            q.popleft()
        if len(q) >= self.limit:
            return max(1, int(q[0] + self.seconds - now) + 1)
        return None

    def add(self, key: str, now: float) -> None:
        if key not in self.hits and len(self.hits) >= MAX_TRACKED:
            for k in [k for k, q in self.hits.items() if not q or q[-1] <= now - self.seconds]:
                del self.hits[k]
            if len(self.hits) >= MAX_TRACKED:
                self.hits.pop(next(iter(self.hits)))
        self.hits.setdefault(key, deque()).append(now)


class Limits:
    def __init__(self) -> None:
        self.per_ip = Window(*PER_IP_LIMIT)
        self.per_token = Window(*PER_TOKEN_LIMIT)
        self.failures = Window(*FAILURE_LIMIT)


def _limits(request: Request) -> Limits:
    limits: Limits | None = getattr(request.app.state, "feed_limits", None)
    if limits is None:
        limits = Limits()
        request.app.state.feed_limits = limits
    return limits


def _not_found() -> Response:
    return JSONResponse(
        {"detail": "Not Found"}, status_code=404, headers={"Cache-Control": "no-store"}
    )


def _too_many(seconds: int) -> Response:
    return JSONResponse(
        {"detail": "Too many requests"},
        status_code=429,
        headers={"Retry-After": str(seconds), "Cache-Control": "no-store"},
    )


def _parse_name(name: str) -> tuple[str, str] | None:
    kind, dot, ext = name.partition(".")
    if not dot or kind not in KIND_NAMES or ext not in EXTENSIONS:
        return None
    return kind, ext


async def _serve_checked(request: Request, db: DbSession, token: str, name: str) -> Response:
    limits = _limits(request)
    now = time.monotonic()
    client = request.app.state.auth.client_ip(request)[:64] or "unknown"
    wait = limits.per_ip.retry_after(client, now) or limits.failures.retry_after(client, now)
    if wait is not None:
        return _too_many(wait)
    limits.per_ip.add(client, now)
    parsed = _parse_name(name)
    digest = feed_tokens.hash_token(token)
    row: FeedTokenRow | None = None
    if digest is not None:
        try:
            when = datetime.now(UTC)
            row = (
                await db.execute(
                    select(FeedTokenRow).where(
                        FeedTokenRow.token_hash == digest,
                        FeedTokenRow.revoked_at.is_(None),
                        or_(FeedTokenRow.expires_at.is_(None), FeedTokenRow.expires_at > when),
                    )
                )
            ).scalar_one_or_none()
        except SQLAlchemyError:
            log.warning("feed lookup failed: database unavailable")
            return _not_found()
    if row is None:
        limits.failures.add(client, now)
        return _not_found()
    wait = limits.per_token.retry_after(str(row.id), now)
    if wait is not None:
        return _too_many(wait)
    limits.per_token.add(str(row.id), now)
    if parsed is None or parsed[0] not in row.kinds:
        return _not_found()
    kind, ext = parsed
    rows = await blocklist_rows.effective_rows(
        db,
        [kind],
        min_score=row.min_score,
        include_benign=row.include_benign,
        include_demo=False,
        limit=exports.MAX_EXPORT_ROWS,
    )
    tag = f"{await blocklist_rows.version(db)}-{kind}-{ext}-{row.min_score}-{row.include_benign:d}"
    etag = f'W/"{tag}"'
    await db.execute(
        update(FeedTokenRow)
        .where(FeedTokenRow.id == row.id)
        .values(
            last_used_at=datetime.now(UTC),
            last_used_ip=client,
            use_count=FeedTokenRow.use_count + 1,
        )
    )
    await db.commit()
    headers = {
        "Cache-Control": "private, max-age=300",
        "ETag": etag,
        "X-Content-Type-Options": "nosniff",
    }
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers=headers)
    body, media = exports.render("csv" if ext == "csv" else "txt", kind, rows)
    return Response(body, media_type=media, headers={**headers, "X-Entry-Count": str(len(rows))})


async def _serve(request: Request, db: DbSession, token: str, name: str) -> Response:
    """Whatever goes wrong, the caller sees the same plain 404 (and the cause is logged)."""
    try:
        return await _serve_checked(request, db, token, name[:64])
    except Exception:
        log.warning("feed request failed", exc_info=True)
        return _not_found()


@router.get("/{token}/{name}", include_in_schema=False)
async def feed_by_path(token: str, name: str, request: Request, db: DbSession) -> Response:
    return await _serve(request, db, token, name)


@router.get("/{name}", include_in_schema=False)
async def feed_by_header(name: str, request: Request, db: DbSession) -> Response:
    # Read by hand and cut short: a declared Header(max_length) would answer 422, not 404.
    scheme, _, token = request.headers.get("authorization", "")[:200].partition(" ")
    return await _serve(request, db, token.strip() if scheme.lower() == "bearer" else "", name)

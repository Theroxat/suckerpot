"""The external feed job (design M36), called by the worker once per cycle after the fetch.

Flow of ``run_once``:

1. ``HUB_EXTERNAL_FEED_MODE`` other than ``publish`` (or the feeds ``off``): nothing is read or
   written, and ``/v1/external/`` does not exist.
2. Load the feed signing key and the exclusions (stale CDN or Tor ranges stop the run, fail
   closed), then the stored copy of the selected CC0 sources. Nothing else is read: no node, no
   consensus table, no report (X1).
3. ``select``: expiry, exclusions, cap. Breaker: a change that is too large waits for an
   operator (``hub.admin external release``), the last published files stay.
4. Render with ``suckerpot_netproto.feeds.external`` and publish atomically under
   ``<feed dir>/external/`` with the tier's own serial. A run that changes no file and has a
   fresh index publishes nothing.

The main feed job never calls this module and this module never touches the main directory (X3).
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_netproto.feeds import minisign
from suckerpot_netproto.feeds.errors import FeedError
from suckerpot_netproto.feeds.external import ExternalSource

from ..config import Settings
from ..feeds import publish
from ..feeds.filter import RangesStale, load_exclusions
from . import readme, select
from .select import SourceRow
from .sources import Source, SourceError, selected

log = logging.getLogger("hub.external_feed")

STATUS_KEY = "external_status"
RELEASE_KEY = "external_release"
HELD_KEY = "external_held"
SERIAL_KEY = "external_serial"
LIST_FILE = "external-outbound.txt"
EXCLUSION_LIST = "outbound"  # delisting decisions scoped to the outbound list apply here too


@dataclass
class JobResult:
    state: str  # off|waiting|published|unchanged|held|failed
    serial: int | None = None
    error_code: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


async def _get(session: AsyncSession, key: str) -> str | None:
    row = (
        await session.execute(text("SELECT value FROM worker_state WHERE key = :k"), {"k": key})
    ).first()
    return str(row[0]) if row else None


async def _set(session: AsyncSession, key: str, value: str | None) -> None:
    if value is None:
        await session.execute(text("DELETE FROM worker_state WHERE key = :k"), {"k": key})
        return
    await session.execute(
        text(
            "INSERT INTO worker_state (key, value) VALUES (:k, :v) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
        ),
        {"k": key, "v": value},
    )


async def _status(session: AsyncSession, result: JobResult, now: datetime) -> JobResult:
    body = {
        "state": result.state,
        "serial": result.serial,
        "error": result.error_code,
        "at": now.isoformat(),
    }
    await _set(session, STATUS_KEY, json.dumps(body))
    await session.commit()
    return result


def _load_secret(path: str) -> minisign.SecretKey | None:
    try:
        return minisign.parse_secret_key(Path(path).read_text(encoding="ascii"))
    except OSError, FeedError, ValueError:
        return None


def published_values(root: Path) -> set[str] | None:
    """Addresses of the published external list, or ``None`` when nothing was published."""
    if publish.read_external_index(root) is None:
        return None
    try:
        return set((root / LIST_FILE).read_text(encoding="utf-8").split())
    except OSError, UnicodeDecodeError:
        return None


async def load_rows(session: AsyncSession, ids: list[str]) -> list[SourceRow]:
    result = await session.execute(
        text(
            "SELECT source, value, family, ports, families, first_seen, last_seen "
            "FROM external_entries WHERE source = ANY(:ids)"
        ),
        {"ids": ids},
    )
    return [
        SourceRow(
            r.source,
            r.value,
            r.family,
            tuple(r.ports or ()),
            tuple(r.families or ()),
            r.first_seen,
            r.last_seen,
        )
        for r in result
    ]


async def _next_serial(session: AsyncSession, root: Path) -> int:
    stored = int(await _get(session, SERIAL_KEY) or 0)
    return max(stored, publish.current_external_serial(root)) + 1


def to_external_sources(sources: list[Source]) -> list[ExternalSource]:
    return [
        ExternalSource.model_validate(
            {"id": src.id, "name": src.name, "licence": src.licence, "url": src.page or src.url}
        )
        for src in sources
    ]


async def run_once(session: AsyncSession, s: Settings, now: datetime) -> JobResult:
    if s.external_feed_mode != "publish" or s.feed_mode == "off":
        return JobResult("off")
    secret = _load_secret(s.feed_signing_key_file)
    if secret is None:
        return await _status(session, JobResult("failed", error_code="no_key"), now)
    try:
        sources = selected(s.external_sources)
    except SourceError:
        return await _status(session, JobResult("failed", error_code="bad_sources"), now)
    ids = [src.id for src in sources]
    fetched = (
        await session.execute(
            text(
                "SELECT count(*) FROM external_feed_state "
                "WHERE source = ANY(:ids) AND last_ok_at IS NOT NULL"
            ),
            {"ids": ids},
        )
    ).scalar_one()
    if not fetched:  # never publish an empty list that nobody could tell from "no C2 exists"
        return await _status(session, JobResult("waiting"), now)
    root = publish.external_root(Path(s.feed_dir))
    today = now.date()
    try:
        excl = await load_exclusions(session, s, today)
    except RangesStale:
        return await _status(session, JobResult("failed", error_code="ranges_stale"), now)

    def excluded(value: str) -> str | None:
        return excl.classify(value, is_domain=False, list_id=EXCLUSION_LIST)

    rows = await load_rows(session, ids)
    sel = select.select_entries(rows, today=today, excluded=excluded)
    before = published_values(root)
    after = sel.values
    counts: dict[str, Any] = {
        "entries": len(sel.entries),
        "expired": sel.expired,
        "excluded": dict(sel.excluded),
        "capped": sel.capped,
    }
    trips = select.breaker(
        before,
        after,
        add_pct=s.feed_breaker_add_pct,
        remove_pct=s.feed_breaker_remove_pct,
        minimum=s.feed_breaker_min,
    )
    if trips:
        fingerprint = select.digest(before, after)
        if await _get(session, RELEASE_KEY) != fingerprint:
            await _set(
                session, HELD_KEY, json.dumps({"digest": fingerprint, "at": now.isoformat()})
            )
            log.warning("external run held: operator review needed")
            return await _status(
                session, JobResult("held", detail={"digest": fingerprint, **counts}), now
            )
        await _set(session, RELEASE_KEY, None)
    await _set(session, HELD_KEY, None)
    serial = await _next_serial(session, root)
    ext_sources = to_external_sources(sources)
    try:
        rendered = await asyncio.to_thread(
            publish.render_external,
            serial=serial,
            now=now,
            valid_days=s.feed_valid_days,
            sources=ext_sources,
            entries=sel.entries,
            allow_documentation=s.allow_documentation,
        )
    except publish.PublishError as exc:
        return await _status(session, JobResult("failed", serial, str(exc)), now)
    remaining = publish.external_index_remaining(root, now)
    stale = remaining is None or remaining < timedelta(days=s.feed_valid_days) / 2
    other = {"readme.txt": readme.render_readme(s, secret.public.encoded, sources)}
    if not publish.changed_files(root, {select.LIST_ID: rendered}, other) and not stale:
        return await _status(session, JobResult("unchanged", detail=counts), now)
    try:
        await asyncio.to_thread(
            publish.publish_external,
            root,
            secret,
            serial=serial,
            now=now,
            valid_days=s.feed_valid_days,
            rendered=rendered,
            other=other,
            sources=ext_sources,
        )
    except publish.PublishError as exc:
        return await _status(session, JobResult("failed", serial, str(exc)), now)
    await _set(session, SERIAL_KEY, str(serial))
    return await _status(session, JobResult("published", serial, detail=counts), now)


async def release(session: AsyncSession) -> bool:
    """Approve the held change: the next run publishes exactly that change."""
    raw = await _get(session, HELD_KEY)
    if raw is None:
        return False
    await _set(session, RELEASE_KEY, str(json.loads(raw)["digest"]))
    await session.commit()
    return True


async def status(session: AsyncSession) -> dict[str, Any]:
    """Operator view: last run, held change, per-source fetch state. No address values."""
    raw = await _get(session, STATUS_KEY)
    sources = [
        dict(r._mapping)
        for r in await session.execute(
            text(
                "SELECT source, last_try_at, last_ok_at, last_error, entry_count "
                "FROM external_feed_state ORDER BY source"
            )
        )
    ]
    return {
        "last_run": json.loads(raw) if raw else None,
        "held": await _get(session, HELD_KEY) is not None,
        "sources": sources,
    }


def summary(result: JobResult) -> dict[str, Any]:
    return {"state": result.state, "serial": result.serial, "error": result.error_code}

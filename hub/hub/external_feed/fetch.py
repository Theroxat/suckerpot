"""Fetch the CC0 external sources into ``external_entries`` (design M36 X4), fail closed.

Same code path as the CDN and Tor range fetcher (``hub/feeds/external.py``): https, the default
port, no redirect, no credentials, no query string, a generic client identity, the proxy from
``HTTPS_PROXY``, a size cap and a shrink check. A download that is too large, slow, redirected,
malformed, too small or suddenly much smaller than the stored copy changes nothing and the last
good copy stays; it then ages out of the published list after ``TTL_DAYS`` (a stale list is never
served as fresh). Only the URLs of ``hub/data/external.yaml`` are contacted: nothing a node or a
visitor sends can trigger a fetch. Failures are logged by code only.

With ``HUB_EXTERNAL_FEED_MODE=off`` (or the feeds ``off``) nothing is contacted at all.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_netproto.enums import FAMILIES_V1
from suckerpot_netproto.feeds.models import check_ip_global

from ..config import Settings
from ..feeds.external import TIMEOUT, RangesError, _download
from .sources import Source, selected

log = logging.getLogger("hub.external_feed.fetch")

SHRINK_CHECK_FROM = 20  # below this many stored addresses the shrink check is skipped
MAX_ROWS = 50_000
MAX_PORTS = 16


class FetchError(Exception):
    """A refused fetch. The message is a short code, never a value."""


@dataclass(frozen=True)
class Row:
    value: str
    family: int
    ports: tuple[int, ...] = ()
    families: tuple[str, ...] = ()


def _items(doc: Any) -> list[Any]:
    if isinstance(doc, dict):
        doc = doc.get("blocklist")
    if not isinstance(doc, list):
        raise FetchError("bad_json")
    return doc


def parse_feodo_json(body: bytes, *, allow_documentation: bool = False) -> list[Row]:
    """Rows of the Feodo Tracker JSON blocklist: a list of objects with ``ip_address`` and
    optional ``port`` and ``malware``. A row that is not an object with a parseable address
    refuses the whole download. Addresses that are not global unicast are dropped here and
    excluded again at render time."""
    try:
        doc = json.loads(body)
    except ValueError as exc:
        raise FetchError("bad_json") from exc
    merged: dict[str, tuple[int, set[int], set[str]]] = {}
    for item in _items(doc):
        if not isinstance(item, dict):
            raise FetchError("bad_row")
        raw_ip = item.get("ip_address")
        if not isinstance(raw_ip, str):
            raise FetchError("bad_row")
        try:
            ip = ipaddress.ip_address(raw_ip.strip())
        except ValueError as exc:
            raise FetchError("bad_row") from exc
        port = item.get("port")
        if port is not None and (
            isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
        ):
            raise FetchError("bad_row")
        malware = item.get("malware")
        if malware is not None and not isinstance(malware, str):
            raise FetchError("bad_row")
        value = str(ip)
        try:
            check_ip_global(value, allow_documentation=allow_documentation)
        except ValueError:
            continue
        _, ports, families = merged.setdefault(value, (ip.version, set(), set()))
        if port is not None:
            ports.add(port)
        if malware and malware.strip().lower() in FAMILIES_V1:
            families.add(malware.strip().lower())
        if len(merged) > MAX_ROWS:
            raise FetchError("too_many")
    return [
        Row(v, fam, tuple(sorted(ports))[:MAX_PORTS], tuple(sorted(fams)))
        for v, (fam, ports, fams) in sorted(merged.items())
    ]


def parse_source(src: Source, body: bytes, *, allow_documentation: bool = False) -> list[Row]:
    if src.format != "feodo-json":  # pragma: no cover - guarded by the loader
        raise FetchError("bad_format")
    rows = parse_feodo_json(body, allow_documentation=allow_documentation)
    if len(rows) < src.min_count:
        raise FetchError("too_few")
    return rows


async def fetch_source(
    client: httpx.AsyncClient, src: Source, *, allow_documentation: bool = False
) -> list[Row]:
    try:
        body = await _download(client, src.url, src.max_bytes)
    except RangesError as exc:
        raise FetchError(str(exc)) from exc
    except (httpx.HTTPError, TimeoutError, OSError) as exc:
        raise FetchError("network") from exc
    return parse_source(src, body, allow_documentation=allow_documentation)


# --- storage and schedule ---------------------------------------------------------------------


async def _stored_count(session: AsyncSession, source: str) -> int:
    row = (
        await session.execute(
            text("SELECT count(*) FROM external_entries WHERE source = :s"), {"s": source}
        )
    ).one()
    return int(row[0])


async def _last_try(session: AsyncSession, source: str) -> datetime | None:
    row = (
        await session.execute(
            text("SELECT last_try_at FROM external_feed_state WHERE source = :s"), {"s": source}
        )
    ).first()
    return row[0] if row else None


async def replace_source(
    session: AsyncSession, source: str, rows: list[Row], now: datetime
) -> None:
    """Swap the stored copy of one source in a single transaction. ``first_seen`` is kept for an
    address that stays listed; an address that left the source is deleted (upstream removal
    reaches the published list within one cycle)."""
    today = now.date()
    for i in range(0, len(rows), 2000):
        await session.execute(
            text(
                "INSERT INTO external_entries (source, value, family, ports, families, "
                "first_seen, last_seen) VALUES (:s, :v, :f, :p, :fa, :d, :d) "
                "ON CONFLICT (source, value) DO UPDATE SET family = EXCLUDED.family, "
                "ports = EXCLUDED.ports, families = EXCLUDED.families, "
                "last_seen = EXCLUDED.last_seen"
            ),
            [
                {
                    "s": source,
                    "v": r.value,
                    "f": r.family,
                    "p": list(r.ports),
                    "fa": list(r.families),
                    "d": today,
                }
                for r in rows[i : i + 2000]
            ],
        )
    await session.execute(
        text("DELETE FROM external_entries WHERE source = :s AND NOT (value = ANY(:keep))"),
        {"s": source, "keep": [r.value for r in rows]},
    )


async def _state(
    session: AsyncSession, source: str, now: datetime, *, ok: bool, error: str | None, count: int
) -> None:
    await session.execute(
        text(
            "INSERT INTO external_feed_state (source, last_try_at, last_ok_at, last_error, "
            "entry_count) VALUES (:s, :now, :ok_at, :e, :c) "
            "ON CONFLICT (source) DO UPDATE SET last_try_at = EXCLUDED.last_try_at, "
            "last_ok_at = coalesce(EXCLUDED.last_ok_at, external_feed_state.last_ok_at), "
            "last_error = EXCLUDED.last_error, entry_count = EXCLUDED.entry_count"
        ),
        {"s": source, "now": now, "ok_at": now if ok else None, "e": error, "c": count},
    )


async def refresh(
    session: AsyncSession,
    s: Settings,
    now: datetime,
    *,
    client: httpx.AsyncClient | None = None,
    sources: list[Source] | None = None,
    force: bool = False,
) -> dict[str, str]:
    """Refresh every selected source that is due. Returns ``{id: outcome}``; never raises on a
    source. Outcomes: ``updated:<n>``, ``fresh`` or ``failed:<code>``."""
    if s.external_feed_mode != "publish" or s.feed_mode == "off":
        return {}
    todo = sources if sources is not None else selected(s.external_sources)
    own = client is None
    http = client or httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False)
    out: dict[str, str] = {}
    try:
        for src in todo:
            if not force:
                tried = await _last_try(session, src.id)
                if tried is not None and now - tried < timedelta(minutes=s.external_interval_min):
                    out[src.id] = "fresh"
                    continue
            count = await _stored_count(session, src.id)
            try:
                rows = await fetch_source(http, src, allow_documentation=s.allow_documentation)
                if count >= SHRINK_CHECK_FROM and len(rows) * 2 < count:
                    raise FetchError("shrunk")
            except FetchError as exc:
                code = str(exc)
            else:
                await replace_source(session, src.id, rows, now)
                await _state(session, src.id, now, ok=True, error=None, count=len(rows))
                await session.commit()
                out[src.id] = f"updated:{len(rows)}"
                continue
            await session.rollback()
            await _state(session, src.id, now, ok=False, error=code, count=count)
            await session.commit()
            log.warning("external source %s kept its last copy: %s", src.id, code)
            out[src.id] = f"failed:{code}"
    finally:
        if own:
            await http.aclose()
    return out

"""The SuckerPot community lists, node API and local mirror (design M30 section 10.5).

The ingest feed worker fetches the public lists, verifies the signature and stores the entries
(``network_feed_entries``, ``network_feed_state``). This module only reads what was stored:

* ``GET /network/feed/status`` and ``GET /network/feed/entries`` show it in the dashboard (every
  signed-in user, read only, paginated).
* ``mirror_entries`` and ``render_mirror`` build the verified local mirror that ``api.feeds``
  serves to firewalls with a feed token of kind ``network``.

The API has no route out: nothing here contacts the feed host or the hub, and the public URLs
are only built as text, to be copied. The API role can read the two feed tables and nothing more.
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import os
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Annotated, Any, Final

from fastapi import APIRouter, Query, Response
from fastapi.responses import JSONResponse
from sqlalchemy import and_, exists, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.blocklist_values import normalize_value
from suckerpot_db.models import BlocklistOverrideRow, NetworkFeedEntryRow, NetworkFeedStateRow
from suckerpot_netproto import defaults

from api.abuse_core import error
from api.cursor import InvalidCursorError, decode_cursor, encode_cursor
from api.deps import DbSession
from api.exports import csv_cell

router = APIRouter(tags=["network"])

TRUE_VALUES: Final = {"1", "true", "yes", "on"}
LIST_IDS: Final = ("inbound", "outbound", "outbound-domains")
DIRECTIONS: Final = {"inbound": "inbound", "outbound": "outbound", "outbound-domains": "outbound"}
TIERS: Final = ("standard", "high")
MAX_MIRROR_ROWS: Final = 50_000
MAX_URL: Final = 200
EPOCH: Final = date(1970, 1, 1)
# Address and name formats of the public site (design 6.1): (format, file extension).
_IP_FORMATS: Final = (
    ("txt", "txt"), ("v4", "v4.txt"), ("v6", "v6.txt"), ("nft", "nft"), ("ipset", "ipset"),
    ("rsc", "rsc"), ("csv", "csv"), ("json", "json"),
)  # fmt: skip
_DOMAIN_FORMATS: Final = (("txt", "txt"), ("csv", "csv"), ("json", "json"))
# Target kinds whose value is a host the entries can be compared with.
_HOST_KINDS: Final = ("ip", "c2_ip", "domain", "c2_domain")
# Mirror file names: list name -> (stored list, tier filter, kind of the value).
MIRROR_LISTS: Final[dict[str, tuple[str, str | None, str]]] = {
    "inbound": ("inbound", None, "ip"),
    "inbound-high": ("inbound", "high", "ip"),
    "outbound": ("outbound", None, "ip"),
    "outbound-high": ("outbound", "high", "ip"),
    "outbound-domains": ("outbound-domains", None, "domain"),
}
MIRROR_EXTENSIONS: Final = ("txt", "csv")
MIRROR_CSV_COLUMNS: Final = (
    "value", "family", "tier", "categories", "tags", "families", "ports", "first_seen",
    "last_seen", "expires",
)  # fmt: skip


# ---- environment ---------------------------------------------------------------------------


def feed_enabled() -> bool:
    return os.environ.get("NETWORK_FEED_ENABLED", "").strip().lower() in TRUE_VALUES


def public_base_url() -> str | None:
    """``NETWORK_FEED_URL`` without a trailing slash; only an https address counts."""
    url = defaults.effective(os.environ, "NETWORK_FEED_URL").rstrip("/")
    if not url or len(url) > MAX_URL or not url.startswith("https://") or not url.isprintable():
        return None
    return url if " " not in url else None


def feeds_enabled() -> bool:
    return os.environ.get("FEEDS_ENABLED", "").strip().lower() in TRUE_VALUES


# ---- state ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class FeedInfo:
    """What the status endpoint says about the stored data."""

    state: str
    error_code: str | None
    serial: int | None
    generated_at: datetime | None
    valid_until: datetime | None
    last_ok_at: datetime | None


def derive_state(enabled: bool, row: NetworkFeedStateRow | None, now: datetime) -> FeedInfo:
    """``disabled``, ``never``, ``ok``, ``stale`` or ``error``; past ``valid_until`` is stale."""
    code = row.error_code if row is not None else None
    if not enabled:
        state = "disabled"
    elif row is None or row.serial is None or row.valid_until is None:
        # No verified copy: never fetched, or wiped by a disable that kept only the last serial.
        state = "error" if code else "never"
    elif row.valid_until is not None and row.valid_until <= now:
        state = "stale"
    elif code:
        state = "error"
    else:
        state = "ok"
    return FeedInfo(
        state=state,
        error_code=code if state in ("error", "stale") else None,
        serial=row.serial if row is not None else None,
        generated_at=row.generated_at if row is not None else None,
        valid_until=row.valid_until if row is not None else None,
        last_ok_at=row.last_ok_at if row is not None else None,
    )


async def load_state(db: AsyncSession, now: datetime | None = None) -> FeedInfo:
    row = (
        await db.execute(select(NetworkFeedStateRow).where(NetworkFeedStateRow.id == 1))
    ).scalar_one_or_none()
    return derive_state(feed_enabled(), row, now or datetime.now(UTC))


async def is_member(db: AsyncSession) -> bool:
    state = (
        await db.execute(text("SELECT state FROM network_membership WHERE id = 1"))
    ).scalar_one_or_none()
    return state == "member"


def _stamp(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _day(value: date | None) -> str:
    return value.isoformat() if value else ""


def files_for(list_id: str, base: str | None) -> list[dict[str, str]]:
    """The public files of a list, from the fixed names of the spec (they exist even when off)."""
    names = [(list_id, "standard")]
    formats: tuple[tuple[str, str], ...] = _DOMAIN_FORMATS
    if list_id != "outbound-domains":
        names.append((f"{list_id}-high", "high"))
        formats = _IP_FORMATS
    files: list[dict[str, str]] = []
    for name, tier in names:
        for fmt, ext in formats:
            files.append({"name": f"{name}.{ext}", "format": fmt, "tier": tier, "url": ""})
        if list_id == "outbound":
            files.append({"name": f"{name}.stix.json", "format": "stix", "tier": tier, "url": ""})
    if base is None:
        return []
    for f in files:
        f["url"] = f"{base}/{f['name']}"
    return files


async def _counts(db: AsyncSession) -> dict[str, tuple[int, int, int]]:
    rows = await db.execute(
        text(
            'SELECT "list" AS name, count(*) AS n, '
            "count(*) FILTER (WHERE tier = 'high') AS high, "
            'count(*) FILTER (WHERE seen_here) AS seen FROM network_feed_entries GROUP BY "list"'
        )
    )
    return {r.name: (int(r.n), int(r.high), int(r.seen)) for r in rows}


async def _helped_counts(db: AsyncSession) -> dict[str, int]:
    rows = await db.execute(
        text(
            'SELECT e."list" AS name, count(*) AS n FROM network_feed_entries e WHERE EXISTS ('
            "SELECT 1 FROM network_targets t WHERE t.mine AND t.kind = ANY(:kinds) "
            'AND t.value = e.value) GROUP BY e."list"'
        ),
        {"kinds": list(_HOST_KINDS)},
    )
    return {r.name: int(r.n) for r in rows}


async def _helped_values(db: AsyncSession, values: list[str]) -> set[str]:
    if not values:
        return set()
    rows = await db.execute(
        text(
            "SELECT DISTINCT value FROM network_targets "
            "WHERE mine AND kind = ANY(:kinds) AND value = ANY(:values)"
        ),
        {"kinds": list(_HOST_KINDS), "values": values},
    )
    return {str(r.value) for r in rows}


def _no_store(body: Any) -> JSONResponse:
    return JSONResponse(body, headers={"Cache-Control": "no-store"})


# ---- routes --------------------------------------------------------------------------------


@router.get("/network/feed/status")
async def feed_status(db: DbSession) -> Response:
    info = await load_state(db)
    base = public_base_url()
    member = await is_member(db)
    counts = await _counts(db) if info.state != "disabled" else {}
    helped = await _helped_counts(db) if member and counts else {}
    lists = []
    for list_id in LIST_IDS:
        entries, high, seen = counts.get(list_id, (0, 0, 0))
        lists.append(
            {
                "id": list_id,
                "direction": DIRECTIONS[list_id],
                "entries": entries,
                "high": high,
                "seen_here": seen,
                "helped": helped.get(list_id, 0) if member else None,
                "files": files_for(list_id, base),
            }
        )
    return _no_store(
        {
            "enabled_env": feed_enabled(),
            "configured": base is not None,
            "state": info.state,
            "error_code": info.error_code,
            "serial": info.serial,
            "generated_at": _stamp(info.generated_at),
            "valid_until": _stamp(info.valid_until),
            "last_ok_at": _stamp(info.last_ok_at),
            "signature": "verified" if info.state in ("ok", "stale") else None,
            "member": member,
            "public_base_url": base,
            "lists": lists,
            "local_mirror": {"feeds_enabled": feeds_enabled()},
        }
    )


def _entry(r: NetworkFeedEntryRow, helped: set[str] | None) -> dict[str, Any]:
    return {
        "list": r.list_name,
        "value": r.value,
        "family": r.family,
        "tier": r.tier or "standard",
        "categories": list(r.categories or []),
        "services": list(r.services or []),
        "tags": list(r.tags or []),
        "families": list(r.families or []),
        "ports": list(r.ports or []),
        "first_seen": _day(r.first_seen),
        "last_seen": _day(r.last_seen),
        "expires": _day(r.expires),
        "reported": bool(r.reported),
        "seen_here": bool(r.seen_here),
        "helped": None if helped is None else r.value in helped,
    }


def _like(q: str) -> str:
    escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


@router.get("/network/feed/entries")
async def feed_entries(
    db: DbSession,
    list_id: Annotated[str | None, Query(alias="list", max_length=24)] = None,
    tier: Annotated[str | None, Query(max_length=16)] = None,
    q: Annotated[str | None, Query(max_length=64)] = None,
    seen_here: Annotated[str | None, Query(max_length=8)] = None,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> Response:
    """Stored entries, newest last-seen first. Keyset pagination; empty while the feed is off."""
    if list_id not in (None, *LIST_IDS):
        return error(422, "Unknown list.", "invalid_filter")
    if tier not in (None, *TIERS):
        return error(422, "Unknown tier.", "invalid_filter")
    if (await load_state(db)).state == "disabled":
        return _no_store({"items": [], "next_cursor": None})
    last = func.coalesce(NetworkFeedEntryRow.last_seen, EPOCH)
    conds: list[Any] = []
    if list_id:
        conds.append(NetworkFeedEntryRow.list_name == list_id)
    if tier:
        conds.append(NetworkFeedEntryRow.tier == tier)
    if q and q.strip():
        conds.append(NetworkFeedEntryRow.value.ilike(_like(q.strip().lower()), escape="\\"))
    if seen_here and seen_here.strip().lower() in TRUE_VALUES:
        conds.append(NetworkFeedEntryRow.seen_here.is_(True))
    if cursor:
        try:
            values = decode_cursor(cursor)
            c_day, c_list, c_value = date.fromisoformat(str(values[0])), str(values[1]), values[2]
        except InvalidCursorError, ValueError, IndexError:
            return error(400, "Invalid cursor.", "invalid_cursor")
        before = or_(
            last < c_day,
            and_(last == c_day, NetworkFeedEntryRow.list_name < c_list),
            and_(
                last == c_day,
                NetworkFeedEntryRow.list_name == c_list,
                NetworkFeedEntryRow.value < str(c_value),
            ),
        )
        conds.append(before)
    ordered = (
        select(NetworkFeedEntryRow)
        .where(*conds)
        .order_by(
            last.desc(), NetworkFeedEntryRow.list_name.desc(), NetworkFeedEntryRow.value.desc()
        )
        .limit(limit + 1)
    )
    rows = (await db.execute(ordered)).scalars().all()
    more = len(rows) > limit
    page = list(rows[:limit])
    helped = await _helped_values(db, [r.value for r in page]) if await is_member(db) else None
    nxt = None
    if more and page:
        tail = page[-1]
        nxt = encode_cursor([(tail.last_seen or EPOCH).isoformat(), tail.list_name, tail.value])
    return _no_store({"items": [_entry(r, helped) for r in page], "next_cursor": nxt})


# ---- local mirror --------------------------------------------------------------------------


def parse_mirror_name(name: str) -> tuple[str, str | None, str, str] | None:
    """``outbound-high.txt`` -> (stored list, tier filter, value kind, extension)."""
    base, dot, ext = name.rpartition(".")
    spec = MIRROR_LISTS.get(base)
    if not dot or spec is None or ext not in MIRROR_EXTENSIONS:
        return None
    return spec[0], spec[1], spec[2], ext


def _sort_key(value: str) -> tuple[int, int | str]:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return (2, value)
    return (addr.version, int(addr))


async def mirror_entries(
    db: AsyncSession, list_name: str, tier: str | None, kind: str
) -> list[NetworkFeedEntryRow]:
    """Verified entries to serve: nothing unless the feed is on, fresh and has been verified.

    The administrator's always-allow overrides win over the network list, and every value is
    checked again with ``normalize_value`` at the last moment.
    """
    info = await load_state(db)
    if info.state not in ("ok", "error") or info.serial is None:
        return []  # disabled, never fetched, or stale (N15): fail toward not blocking
    now = datetime.now(UTC)
    allowed = exists().where(
        BlocklistOverrideRow.kind == kind,
        BlocklistOverrideRow.value == NetworkFeedEntryRow.value,
        BlocklistOverrideRow.action == "allow",
        or_(BlocklistOverrideRow.expires_at.is_(None), BlocklistOverrideRow.expires_at > now),
    )
    stmt = select(NetworkFeedEntryRow).where(NetworkFeedEntryRow.list_name == list_name, ~allowed)
    if tier:
        stmt = stmt.where(NetworkFeedEntryRow.tier == tier)
    rows = (await db.execute(stmt.limit(MAX_MIRROR_ROWS))).scalars().all()
    seen: set[str] = set()
    good: list[NetworkFeedEntryRow] = []
    for r in rows:
        if normalize_value(kind, r.value) != r.value or r.value in seen:
            continue
        seen.add(r.value)
        good.append(r)
    good.sort(key=lambda r: _sort_key(r.value))
    return good


def render_mirror(ext: str, rows: list[NetworkFeedEntryRow]) -> tuple[str, str]:
    """(body, media type): one value per line, or a spreadsheet-safe CSV with CRLF line ends."""
    if ext == "csv":
        out = io.StringIO()
        writer = csv.writer(out, lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
        writer.writerow(MIRROR_CSV_COLUMNS)
        for r in rows:
            cells = {
                "value": r.value, "family": r.family or "", "tier": r.tier or "standard",
                "categories": r.categories or [], "tags": r.tags or [],
                "families": r.families or [], "ports": [str(p) for p in r.ports or []],
                "first_seen": _day(r.first_seen), "last_seen": _day(r.last_seen),
                "expires": _day(r.expires),
            }  # fmt: skip
            writer.writerow([csv_cell(cells[c]) for c in MIRROR_CSV_COLUMNS])
        return out.getvalue(), "text/csv; charset=utf-8"
    return "".join(f"{r.value}\n" for r in rows), "text/plain; charset=utf-8"


def mirror_etag(ext: str, name: str, body: str) -> str:
    digest = hashlib.sha256(f"{name}.{ext}\n{body}".encode()).hexdigest()[:24]
    return f'W/"net-{digest}"'

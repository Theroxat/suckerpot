"""Probable command-and-control addresses (read-only, passive).

For hashes that VirusTotal or abuse.ch already recognise, ingest reads from those providers
which network addresses public sandboxes saw the malware contact (``indicator_contacts``). This
endpoint lists them so the owner can block them. Nothing here contacts an address or an intel
API: the API has no internet access and only reads tables. Every address is returned raw and
defanged; the web UI shows only the defanged form and never renders an address as a link.

* ``GET /indicators/c2``  keyset-paginated list, best confidence first (``high`` is ThreatFox
  ``botnet_cc``; ``medium`` is a VirusTotal sandbox contact outside the never-block list).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text

from api.cursor import InvalidCursorError, decode_cursor, encode_cursor
from api.deps import DbSession
from api.indicators import defang, safe_reference

router = APIRouter(tags=["indicators"])

MAX_LIMIT = 200
MAX_WINDOW_HOURS = 24 * 90
DEFAULT_WINDOW_HOURS = 24 * 30
MAX_HASHES = 10
MAX_REFERENCES = 5
STATEMENT_TIMEOUT_MS = 3000


class C2Hash(BaseModel):
    sha256: str  # the hash as recorded (MD5, SHA-1 or SHA-256)
    family: str | None


class C2Address(BaseModel):
    address: str
    defanged: str
    kind: Literal["ip", "domain"]
    port: int | None
    confidence: Literal["high", "medium"]  # the best across sources
    sources: list[Literal["virustotal", "threatfox"]]
    families: list[str]
    hashes: list[C2Hash]  # at most 10, most recent first
    hash_count: int
    sessions: int  # our sessions that dropped any of these hashes
    first_seen: datetime
    last_seen: datetime  # when one of those hashes was last dropped here
    references: list[str]  # links to the providers only


class C2Page(BaseModel):
    items: list[C2Address]
    next_cursor: str | None


def _parse_cursor(cursor: str) -> tuple[int, int, str, str]:
    values = decode_cursor(cursor)
    try:
        rank, neg_epoch, kind, address = values
        if not (
            isinstance(rank, int)
            and isinstance(neg_epoch, int)
            and isinstance(kind, str)
            and isinstance(address, str)
        ):
            raise TypeError
    except (ValueError, TypeError) as exc:
        raise InvalidCursorError("malformed cursor") from exc
    return rank, neg_epoch, kind, address


_PAGE = """
SELECT * FROM (
    SELECT c.kind, c.address,
           min(CASE c.confidence WHEN 'high' THEN 0 ELSE 1 END) AS rank,
           (-floor(extract(epoch FROM max(h.last_seen))))::bigint AS neg_epoch,
           max(h.last_seen) AS last_seen, min(c.first_seen) AS first_seen,
           (array_agg(c.port) FILTER (WHERE c.port IS NOT NULL))[1] AS port,
           array_agg(DISTINCT c.source) AS sources,
           array_agg(DISTINCT c.family) FILTER (WHERE c.family IS NOT NULL) AS families,
           array_agg(DISTINCT c.reference) FILTER (WHERE c.reference IS NOT NULL) AS refs,
           array_agg(DISTINCT c.hash_indicator_id) AS hash_ids
    FROM indicator_contacts c
    JOIN indicators h ON h.id = c.hash_indicator_id
    WHERE c.confidence IN ('high', 'medium') AND h.last_seen >= :since {kind_filter}
    GROUP BY c.kind, c.address
) g
{where}
ORDER BY rank, neg_epoch, kind, address
LIMIT :lim
"""
_HASHES = """
SELECT x.kind, x.address, x.sha, x.family FROM (
    SELECT c.kind, c.address, h.value AS sha, max(c.family) AS family,
           row_number() OVER (PARTITION BY c.kind, c.address
                              ORDER BY max(h.last_seen) DESC, h.value) AS rn
    FROM indicator_contacts c JOIN indicators h ON h.id = c.hash_indicator_id
    WHERE c.confidence IN ('high', 'medium') AND h.last_seen >= :since
      AND (c.kind, c.address) IN (SELECT * FROM unnest(CAST(:kinds AS text[]),
                                                       CAST(:addrs AS text[])))
    GROUP BY c.kind, c.address, h.value
) x WHERE x.rn <= :max_hashes ORDER BY x.kind, x.address, x.rn
"""
_SESSIONS = """
SELECT k.kind, k.address, count(DISTINCT l.session_id) AS sessions
FROM unnest(CAST(:kinds AS text[]), CAST(:addrs AS text[])) AS k(kind, address)
JOIN indicator_contacts c ON c.kind = k.kind AND c.address = k.address
                         AND c.confidence IN ('high', 'medium')
JOIN indicators h ON h.id = c.hash_indicator_id AND h.last_seen >= :since
JOIN indicator_sessions l ON l.indicator_id = c.hash_indicator_id
GROUP BY k.kind, k.address
"""


@router.get("/indicators/c2", response_model=C2Page)
async def list_c2(
    db: DbSession,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = 50,
    min_confidence: Literal["high", "medium"] = "medium",
    kind: Literal["ip", "domain"] | None = None,
    hours: Annotated[int, Query(ge=1, le=MAX_WINDOW_HOURS)] = DEFAULT_WINDOW_HOURS,
) -> C2Page:
    await db.execute(text(f"SET LOCAL statement_timeout = {STATEMENT_TIMEOUT_MS}"))
    since = datetime.now(UTC) - timedelta(hours=hours)
    params: dict[str, Any] = {"since": since, "lim": limit + 1}
    kind_filter = ""
    if kind:
        kind_filter = " AND c.kind = :kind"
        params["kind"] = kind
    conditions: list[str] = []
    if min_confidence == "high":
        conditions.append("rank = 0")
    if cursor is not None:
        try:
            rank, neg_epoch, c_kind, c_addr = _parse_cursor(cursor)
        except InvalidCursorError as exc:
            raise HTTPException(status_code=400, detail="invalid cursor") from exc
        conditions.append("(rank, neg_epoch, kind, address) > (:c_rank, :c_neg, :c_kind, :c_addr)")
        params.update(c_rank=rank, c_neg=neg_epoch, c_kind=c_kind, c_addr=c_addr)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    sql = _PAGE.format(kind_filter=kind_filter, where=where)  # fixed fragments, values are bound
    rows = (await db.execute(text(sql), params)).all()
    page, more = rows[:limit], len(rows) > limit
    kinds, addrs = [r.kind for r in page], [r.address for r in page]
    hashes: dict[tuple[str, str], list[C2Hash]] = {}
    sessions: dict[tuple[str, str], int] = {}
    if page:
        pair = {"kinds": kinds, "addrs": addrs}
        for h in (
            await db.execute(text(_HASHES), {**pair, "since": since, "max_hashes": MAX_HASHES})
        ).all():
            hashes.setdefault((h.kind, h.address), []).append(C2Hash(sha256=h.sha, family=h.family))
        for s in (await db.execute(text(_SESSIONS), {**pair, "since": since})).all():
            sessions[(s.kind, s.address)] = s.sessions
    items = [
        C2Address(
            address=r.address,
            defanged=defang(r.kind, r.address),
            kind=r.kind,
            port=r.port,
            confidence="high" if r.rank == 0 else "medium",
            sources=list(r.sources),
            families=sorted(r.families or []),
            hashes=hashes.get((r.kind, r.address), []),
            hash_count=len(r.hash_ids),
            sessions=sessions.get((r.kind, r.address), 0),
            first_seen=r.first_seen,
            last_seen=r.last_seen,
            references=sorted({u for u in (safe_reference(x) for x in r.refs or []) if u})[
                :MAX_REFERENCES
            ],
        )
        for r in page
    ]
    end = page[-1] if more else None
    next_cursor = (
        encode_cursor([end.rank, end.neg_epoch, end.kind, end.address]) if end is not None else None
    )
    return C2Page(items=items, next_cursor=next_cursor)

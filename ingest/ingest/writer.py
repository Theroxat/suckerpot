"""Batched writer: events insert + sessions upsert in one transaction.

When an :class:`Enricher` is given, events are enriched on the way in (local GeoIP/ASN
lookups, cached reputation, tagging rules) and session-scope rules run on the upserted
counters. Nothing here calls the network.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import UTC, date
from typing import Any

from sqlalchemy import (
    ARRAY,
    ColumnElement,
    Text,
    bindparam,
    func,
    insert,
    literal_column,
    select,
    text,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_common import Event
from suckerpot_db.models import EventRow, IpReputationRow, SessionRow, TechniqueDailyRow

from ingest.aggregate import SessionDelta, compute_session_deltas
from ingest.bruteforce import TAG as BRUTE_TAG
from ingest.diskguard import DiskGuard
from ingest.enrichment.enricher import Enricher
from ingest.indicator_store import store_indicators

log = logging.getLogger(__name__)

_UNION_TAGS: ColumnElement[Any] = literal_column(
    "ARRAY(SELECT DISTINCT unnest(sessions.tags || excluded.tags) ORDER BY 1)"
)
_UNION_TECHNIQUES: ColumnElement[Any] = literal_column(
    "ARRAY(SELECT DISTINCT unnest(sessions.techniques || excluded.techniques) ORDER BY 1 LIMIT 64)"
)


def strip_nul(value: Any) -> Any:
    """PostgreSQL jsonb rejects U+0000: remove it from every string (keys and values)."""
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, dict):
        return {strip_nul(k): strip_nul(v) for k, v in value.items()}
    if isinstance(value, list):
        return [strip_nul(v) for v in value]
    return value


def event_to_row(ev: Event) -> dict[str, Any]:
    return {
        "ts": ev.ts,
        "sensor": str(ev.sensor),
        "session_id": ev.session_id,
        "type": str(ev.type),
        "src_ip": str(ev.src_ip),
        "src_port": ev.src_port,
        "dst_port": ev.dst_port,
        "data": strip_nul(ev.data),
    }


def delta_to_row(d: SessionDelta) -> dict[str, Any]:
    return {
        "session_id": d.session_id,
        "sensor": d.sensor,
        "src_ip": d.src_ip,
        "src_port": d.src_port,
        "dst_port": d.dst_port,
        "started_at": d.started_at,
        "ended_at": d.ended_at,
        "last_event_at": d.last_event_at,
        "event_count": d.event_count,
        "login_attempts": d.login_attempts,
        "login_success": d.login_success,
        "commands": d.commands,
        "downloads": d.downloads,
        "http_requests": d.http_requests,
        "country": d.country,
        "city": d.city,
        "asn": d.asn,
        "org": d.org,
        "abuse_score": d.abuse_score,
        "known_scanner": d.known_scanner,
        "tags": sorted(d.tags),
        "client_tool": d.client_tool,
        "techniques": sorted(d.techniques),
    }


async def _cached_reputation(
    session: AsyncSession, ips: Sequence[str]
) -> dict[str, tuple[int | None, bool | None]]:
    """abuse_score and GreyNoise noise flag already known for these addresses."""
    stmt = select(
        func.host(IpReputationRow.ip), IpReputationRow.abuse_score, IpReputationRow.gn_noise
    ).where(IpReputationRow.ip.in_(ips))
    return {ip: (score, noise) for ip, score, noise in (await session.execute(stmt)).all()}


def _enrich_rows(
    events: Sequence[Event],
    rows: list[dict[str, Any]],
    deltas: list[SessionDelta],
    enricher: Enricher,
    reputation: dict[str, tuple[int | None, bool | None]],
) -> None:
    by_session = {d.session_id: d for d in deltas}
    for ev, row in zip(events, rows, strict=True):
        ip = str(ev.src_ip)
        geo = enricher.geo.lookup(ip)
        score, noise = reputation.get(ip, (None, None))
        tags = enricher.rules.tag_event(str(ev.type), str(ev.sensor), row["data"])
        if str(ev.type) == "login_attempt" and enricher.brute.record(ip, str(ev.sensor), ev.ts):
            tags = sorted({*tags, BRUTE_TAG})
        techniques: list[str] = []
        if enricher.attack is not None:
            techniques = enricher.attack.for_event(str(ev.type), str(ev.sensor), row["data"], tags)
        row["techniques"] = techniques or None
        row.update(
            country=geo.country, city=geo.city, asn=geo.asn, org=geo.org,
            abuse_score=score, known_scanner=noise, tags=tags,
        )  # fmt: skip
        d = by_session[ev.session_id]
        d.tags.update(tags)
        d.techniques.update(techniques)
        if d.country is None and geo.country is not None:
            d.country, d.city, d.asn, d.org = geo.country, geo.city, geo.asn, geo.org
        d.abuse_score = score if score is not None else d.abuse_score
        d.known_scanner = noise if noise is not None else d.known_scanner


async def write_batch(
    factory: async_sessionmaker[AsyncSession],
    events: Sequence[Event],
    enricher: Enricher | None = None,
    guard: DiskGuard | None = None,
) -> None:
    """Insert events and upsert sessions atomically. Raises on failure (nothing is committed)."""
    if not events:
        return
    deltas = compute_session_deltas(events)
    rows = [event_to_row(e) for e in events]
    degraded = guard is not None and await guard.is_degraded()
    prior: dict[str, set[str]] = {}
    async with factory() as session, session.begin():
        if enricher is not None:
            ips = sorted({str(e.src_ip) for e in events})
            reputation = await _cached_reputation(session, ips)
            _enrich_rows(events, rows, deltas, enricher, reputation)
            if enricher.attack is not None:
                prior = await _prior_techniques(session, [d.session_id for d in deltas])
        if degraded and guard is not None:
            guard.degrade_rows(rows)  # after tagging, which needs the full payload
        await session.execute(insert(EventRow), rows)
        stmt = pg_insert(SessionRow)
        ex = stmt.excluded
        t = SessionRow.__table__
        upsert = stmt.on_conflict_do_update(
            index_elements=[t.c.session_id],
            set_={
                "event_count": t.c.event_count + ex.event_count,
                "login_attempts": t.c.login_attempts + ex.login_attempts,
                "login_success": t.c.login_success | ex.login_success,
                "commands": t.c.commands + ex.commands,
                "downloads": t.c.downloads + ex.downloads,
                "http_requests": t.c.http_requests + ex.http_requests,
                "started_at": func.least(t.c.started_at, ex.started_at),
                "last_event_at": func.greatest(t.c.last_event_at, ex.last_event_at),
                # greatest() ignores NULLs in PostgreSQL.
                "ended_at": func.greatest(t.c.ended_at, ex.ended_at),
                "country": func.coalesce(t.c.country, ex.country),
                "city": func.coalesce(t.c.city, ex.city),
                "asn": func.coalesce(t.c.asn, ex.asn),
                "org": func.coalesce(t.c.org, ex.org),
                "abuse_score": func.coalesce(ex.abuse_score, t.c.abuse_score),
                "known_scanner": func.coalesce(ex.known_scanner, t.c.known_scanner),
                "tags": _UNION_TAGS,
                "client_tool": func.coalesce(ex.client_tool, t.c.client_tool),
                "techniques": _UNION_TECHNIQUES,
            },
        ).returning(
            t.c.session_id, t.c.sensor, t.c.event_count, t.c.login_attempts, t.c.login_success,
            t.c.commands, t.c.downloads, t.c.http_requests, t.c.known_scanner, t.c.abuse_score,
            t.c.tags,
        )  # fmt: skip
        result = await session.execute(upsert, [delta_to_row(d) for d in deltas])
        if enricher is not None:
            await _apply_session_rules(session, enricher, result.all())
            if enricher.attack is not None:
                await record_technique_daily(session, events, rows, deltas, prior)
            if enricher.indicators is not None and not degraded:
                await store_indicators(session, events, enricher.indicators, enricher.link_cap)


async def _apply_session_rules(
    session: AsyncSession, enricher: Enricher, rows: Sequence[Any]
) -> None:
    """Evaluate session-scope rules on the upserted counters and add any new tags."""
    updates: list[dict[str, Any]] = []
    for r in rows:
        facts = {
            "session.sensor": r.sensor,
            "session.event_count": r.event_count,
            "session.login_attempts": r.login_attempts,
            "session.login_success": r.login_success,
            "session.commands": r.commands,
            "session.downloads": r.downloads,
            "session.http_requests": r.http_requests,
            "session.known_scanner": r.known_scanner,
            "session.abuse_score": r.abuse_score,
            "session.tags": list(r.tags or []),
        }
        new = set(enricher.rules.tag_session(facts)) - set(r.tags or [])
        if new:
            techniques = enricher.attack.for_tags(sorted(new)) if enricher.attack else []
            updates.append({"sid": r.session_id, "t": sorted(new), "x": sorted(techniques)})
    if updates:
        await session.execute(
            text(
                "UPDATE sessions SET tags = ARRAY(SELECT DISTINCT unnest(tags || :t) ORDER BY 1), "
                "techniques = ARRAY(SELECT DISTINCT unnest(techniques || :x) ORDER BY 1 LIMIT 64) "
                "WHERE session_id = :sid"
            ).bindparams(bindparam("t", type_=ARRAY(Text)), bindparam("x", type_=ARRAY(Text))),
            updates,
        )


async def _prior_techniques(
    session: AsyncSession, session_ids: Sequence[str]
) -> dict[str, set[str]]:
    """Techniques the sessions already carry, to count each session once per technique."""
    stmt = select(SessionRow.session_id, SessionRow.techniques).where(
        SessionRow.session_id.in_(list(session_ids))
    )
    return {sid: set(techs or []) for sid, techs in (await session.execute(stmt)).all()}


async def record_technique_daily(
    session: AsyncSession,
    events: Sequence[Event],
    rows: Sequence[dict[str, Any]],
    deltas: Sequence[SessionDelta],
    prior: dict[str, set[str]],
) -> None:
    """Add the batch to ``technique_daily`` in a savepoint: a failure here never costs events.

    ``events`` counts every event that shows a technique; ``sessions`` counts a session once,
    when it first shows the technique; ``sources`` counts the addresses of those sessions within
    the batch (an upper bound across batches, as a returning address is counted again).
    """
    cells: dict[tuple[date, str, str], list[Any]] = {}
    first_day: dict[tuple[str, str], date] = {}
    for ev, row in zip(events, rows, strict=True):
        techs = row.get("techniques") or []
        day = ev.ts.astimezone(UTC).date()
        for tid in techs:
            cell = cells.setdefault((day, tid, str(ev.sensor)), [0, set(), set()])
            cell[0] += 1
            first_day.setdefault((ev.session_id, tid), day)
    ip_of = {d.session_id: d.src_ip for d in deltas}
    sensor_of = {d.session_id: d.sensor for d in deltas}
    for (sid, tid), day in first_day.items():
        if tid in prior.get(sid, set()):
            continue
        cell = cells.setdefault((day, tid, sensor_of[sid]), [0, set(), set()])
        cell[1].add(sid)
        cell[2].add(ip_of[sid])
    if not cells:
        return
    values = [
        {
            "day": day, "technique": tid, "sensor": sensor,
            "sessions": len(c[1]), "events": c[0], "sources": len(c[2]),
        }
        for (day, tid, sensor), c in sorted(cells.items())
    ]  # fmt: skip
    stmt = pg_insert(TechniqueDailyRow)
    ex = stmt.excluded
    t = TechniqueDailyRow.__table__
    stmt = stmt.on_conflict_do_update(
        index_elements=[t.c.day, t.c.technique, t.c.sensor],
        set_={
            "sessions": t.c.sessions + ex.sessions,
            "events": t.c.events + ex.events,
            "sources": t.c.sources + ex.sources,
        },
    )
    try:
        async with session.begin_nested():
            await session.execute(stmt, values)
    except SQLAlchemyError as exc:
        log.warning("technique counters failed (%s)", type(exc).__name__)

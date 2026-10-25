"""Persist the indicators of a batch: upsert the rows, then add bounded session links.

Runs inside the batch transaction, in a savepoint: a problem here never costs the events.
Nothing in this module touches the network.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

from sqlalchemy import ColumnElement, func, literal_column, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_db.models import IndicatorRow, IndicatorSessionRow

from ingest.indicators import Aggregate, IndicatorExtractor, aggregate_batch

log = logging.getLogger(__name__)

_UNION_SENSORS: ColumnElement[Any] = literal_column(
    "ARRAY(SELECT DISTINCT unnest(indicators.sensors || excluded.sensors) ORDER BY 1)"
)


async def store_indicators(
    session: AsyncSession,
    events: Sequence[Any],
    extractor: IndicatorExtractor,
    link_cap: int,
) -> int:
    """Extract and store; returns the number of indicators touched. Never raises on SQL errors."""
    try:
        items = aggregate_batch(events, extractor)
    except Exception:  # extraction is pure code: log the kind only, keep the events
        log.warning("indicator extraction failed", exc_info=True)
        return 0
    if not items:
        return 0
    try:
        async with session.begin_nested():
            await _write(session, items, link_cap)
    except SQLAlchemyError as exc:
        log.warning("indicator storage failed (%s)", type(exc).__name__)
        return 0
    return len(items)


async def _write(session: AsyncSession, items: Sequence[Aggregate], link_cap: int) -> None:
    stmt = pg_insert(IndicatorRow)
    ex = stmt.excluded
    t = IndicatorRow.__table__
    upsert = stmt.on_conflict_do_update(
        index_elements=[t.c.type, t.c.value],
        set_={
            "first_seen": func.least(t.c.first_seen, ex.first_seen),
            "last_seen": func.greatest(t.c.last_seen, ex.last_seen),
            "sightings": t.c.sightings + ex.sightings,
            "sensors": _UNION_SENSORS,
            # 'download_host' sorts after 'contacted_host': once seen as a download source it stays.
            "role": func.greatest(t.c.role, ex.role),
            "host": func.coalesce(t.c.host, ex.host),
            "trusted": t.c.trusted | ex.trusted,
            "demo": t.c.demo & ex.demo,
        },
    ).returning(t.c.id, t.c.type, t.c.value)
    rows = [
        {
            "type": a.type,
            "value": a.value,
            "role": a.role,
            "host": a.host,
            "first_seen": a.first_seen,
            "last_seen": a.last_seen,
            "sightings": a.sightings,
            "trusted": a.trusted,
            "demo": a.demo,
            "sensors": sorted(a.sensors),
        }
        for a in items
    ]
    ids = {(r.type, r.value): r.id for r in (await session.execute(upsert, rows)).all()}
    if not ids:
        return
    count_rows = await session.execute(
        select(IndicatorSessionRow.indicator_id, func.count())
        .where(IndicatorSessionRow.indicator_id.in_(list(ids.values())))
        .group_by(IndicatorSessionRow.indicator_id)
    )
    counts: dict[int, int] = {iid: n for iid, n in count_rows.tuples()}
    links: list[dict[str, Any]] = []
    for a in items:
        iid = ids.get((a.type, a.value))
        if iid is None:
            continue
        room = max(0, link_cap - counts.get(iid, 0))
        for sid, (ip, sensor, ts) in list(a.sessions.items())[:room]:
            links.append(
                {
                    "indicator_id": iid,
                    "session_id": sid,
                    "src_ip": ip,
                    "sensor": sensor,
                    "seen_at": ts,
                }
            )
    if links:
        await session.execute(pg_insert(IndicatorSessionRow).on_conflict_do_nothing(), links)

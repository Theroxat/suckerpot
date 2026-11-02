"""The feed job (design M30 section 5.1), called by the worker once per cycle.

Flow of ``run_once``:

1. ``HUB_FEED_MODE=off`` (or external ranges disabled, or paused): nothing is read or written.
2. Load the signing key, the exclusions (stale CDN or Tor ranges stop the run, fail closed), the
   eligible nodes, the confirmed targets with their observations and the existing entries.
3. ``select``: candidates with k-supported fields; outside lookups only where they can change the
   answer and within a per-run cap, cached in ``feed_entries``.
4. ``lifecycle.plan``: hold, filter, expiry, takedown removal, caps.
5. Breaker: a change that is too large, or any addition in ``review`` mode, is held for the
   operator (``feed_runs.state = held`` with its diff, an audit row) and nothing is stored.
6. Store the plan, render with ``suckerpot_netproto.feeds``, and publish atomically with a
   monotonic serial. A run that changes no list file and has a fresh index publishes nothing.

Operator hooks used by ``hub.admin``: ``release``, ``discard``, ``set_paused``, ``status``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_netproto.feeds import FeedEntry, minisign
from suckerpot_netproto.feeds.errors import FeedError
from suckerpot_netproto.feeds.models import LIST_IDS

from .. import consensus
from ..config import Settings
from ..never import split_host_port
from . import lifecycle, publish, readme, select
from . import stats as feed_stats
from .filter import Exclusions, RangesStale, load_exclusions
from .lifecycle import EntryRow, Plan
from .select import Candidate, Obs, SelectContext, TargetInput

log = logging.getLogger("hub.feeds")

STATUS_KEY = "feed_status"
LAST_RUN_KEY = "feed_last_run"
PAUSED_KEY = "feed_paused"
RELEASE_KEY = "feed_release"
DISCARD_KEY = "feed_discard"
LOOKUP_CAP = 100
LOOKUP_KINDS = frozenset({"ip", "payload_ip", "c2_ip"})
CORROBORATION_DAYS = 7
GOOD_KINDS = tuple(select.KIND_LIST)

Corroborate = Callable[[str], Awaitable[bool]]


@dataclass
class JobResult:
    state: str  # off|paused|skipped|published|unchanged|held|discarded|failed
    serial: int | None = None
    error_code: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


# --- worker_state helpers -------------------------------------------------------------------


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


# --- loading --------------------------------------------------------------------------------


def _row_to_entry(r: Any) -> EntryRow:
    return EntryRow(
        list_id=r.list,
        value=r.value,
        family=r.family,
        tier=r.tier,
        state=r.state,
        categories=list(r.categories or []),
        services=list(r.services or []),
        tags=list(r.tags or []),
        families=list(r.families or []),
        ports=list(r.ports or []),
        first_seen=r.first_seen,
        last_seen=r.last_seen,
        expires=r.expires,
        reported=r.reported,
        eligible_at=r.eligible_at,
        listed_day=r.listed_day,
        removed_day=r.removed_day,
        removed_reason=r.removed_reason,
        corroborated=r.corroborated,
        corroborated_day=r.corroborated_day,
        target_id=r.target_id,
    )


async def load_existing(session: AsyncSession) -> dict[tuple[str, str], EntryRow]:
    rows = await session.execute(text("SELECT * FROM feed_entries"))
    return {(r.list, r.value): _row_to_entry(r) for r in rows}


async def link_hosts(session: AsyncSession, since: date) -> None:
    """Tie payload hosts to the URL targets they served (for takedown removal)."""
    await session.execute(
        text(
            """
            INSERT INTO target_hosts (url_target_id, payload_target_id)
            SELECT DISTINCT u.id, h.id FROM payload_links pl
            JOIN targets u ON u.kind = 'url' AND coalesce(u.value_b, u.value) = pl.url_b
            JOIN targets h ON h.kind = pl.kind AND coalesce(h.value_b, h.value) = pl.value
            WHERE pl.day >= :since
            ON CONFLICT DO NOTHING
            """
        ),
        {"since": since},
    )


async def load_inputs(
    session: AsyncSession, s: Settings, today: date, eligible: dict[uuid.UUID, Any]
) -> list[TargetInput]:
    if not eligible:
        return []
    rows = await session.execute(
        text(
            """
            SELECT t.id, t.kind, t.value, t.state, t.confirmed_day, t.reported_day,
                   o.node_id, o.day, o.services, o.activity, o.tags, o.families, o.attempts,
                   o.fetched, o.via
            FROM targets t
            JOIN observations o ON o.kind = t.kind AND o.value = coalesce(t.value_b, t.value)
            WHERE t.state IN ('confirmed', 'reported') AND t.kind = ANY(:kinds)
              AND t.value IS NOT NULL AND o.node_id = ANY(:nodes)
              AND o.day >= :since AND o.day < :today
            ORDER BY t.id
            """
        ),
        {
            "kinds": list(GOOD_KINDS),
            "nodes": list(eligible),
            "since": today - timedelta(days=s.obs_retention_days),
            "today": today,
        },
    )
    heads: dict[str, tuple[Any, list[Obs]]] = {}
    for r in rows:
        head = heads.setdefault(r.id, (r, []))
        head[1].append(
            Obs(
                node=r.node_id,
                day=r.day,
                services=tuple(r.services or ()),
                activity=tuple(r.activity or ()),
                tags=tuple(r.tags or ()),
                families=tuple(r.families or ()),
                attempts=r.attempts,
                fetched=bool(r.fetched),
                via=r.via,
            )
        )
    return [
        TargetInput(
            target_id=r.id,
            kind=r.kind,
            value=r.value,
            state=r.state,
            confirmed_day=r.confirmed_day,
            reported=r.reported_day is not None,
            obs=obs,
        )
        for r, obs in heads.values()
    ]


def _strip_port(kind: str, value: str) -> str:
    return split_host_port(value)[0] if kind == "c2_ip" else value


async def taken_down_keys(
    session: AsyncSession, candidate_keys: set[tuple[str, str]]
) -> set[tuple[str, str]]:
    """Entries to remove because the thing they point at is down.

    Payload hosts: every URL target they served is ``taken_down`` (at least one is). Others: the
    target itself is ``taken_down`` and no live target still backs the value.
    """
    out: set[tuple[str, str]] = set()
    hosts = await session.execute(
        text(
            """
            SELECT h.kind, h.value FROM targets h
            WHERE h.kind IN ('payload_ip', 'domain') AND h.state IN ('confirmed', 'reported')
              AND h.value IS NOT NULL
              AND EXISTS (SELECT 1 FROM target_hosts th JOIN targets u ON u.id = th.url_target_id
                          WHERE th.payload_target_id = h.id AND u.state = 'taken_down')
              AND NOT EXISTS (SELECT 1 FROM target_hosts th
                              JOIN targets u ON u.id = th.url_target_id
                              WHERE th.payload_target_id = h.id
                                AND u.state IN ('confirmed', 'reported'))
            """
        )
    )
    for kind, value in hosts:
        out.add((select.KIND_LIST[kind], value))
    own = await session.execute(
        text(
            "SELECT kind, value FROM targets WHERE state = 'taken_down' "
            "AND kind IN ('ip', 'c2_ip', 'c2_domain') AND value IS NOT NULL"
        )
    )
    for kind, value in own:
        key = (select.KIND_LIST[kind], _strip_port(kind, value))
        if key not in candidate_keys:
            out.add(key)
    return out


# --- evaluation with outside lookups ----------------------------------------------------------


async def build_candidates(
    inputs: list[TargetInput],
    ctx: SelectContext,
    existing: dict[tuple[str, str], EntryRow],
    corroborate: Corroborate | None,
    today: date,
) -> tuple[dict[tuple[str, str], Candidate], dict[tuple[str, str], bool]]:
    """Candidates by (list, value), and the lookups made this run."""
    found: list[Candidate] = []
    looked: dict[str, bool] = {}
    fresh: dict[tuple[str, str], bool] = {}
    lookups = 0
    for t in inputs:
        host = _strip_port(t.kind, t.value)
        list_id = select.KIND_LIST[t.kind]
        cached: bool | None = None
        old = existing.get((list_id, host))
        if (
            old is not None
            and old.corroborated is not None
            and old.corroborated_day is not None
            and (today - old.corroborated_day).days <= CORROBORATION_DAYS
        ):
            cached = old.corroborated
        if host in looked:
            cached = looked[host]
        ev = select.evaluate(t, ctx, cached)
        if (
            ev.needs_lookup
            and corroborate is not None
            and t.kind in LOOKUP_KINDS
            and lookups < LOOKUP_CAP
        ):
            lookups += 1
            looked[host] = await corroborate(host)
            fresh[(list_id, host)] = looked[host]
            ev = select.evaluate(t, ctx, looked[host])
        if ev.candidate is not None:
            found.append(ev.candidate)
    return select.merge_all(found), fresh


# --- storing and rendering --------------------------------------------------------------------


_UPSERT = text(
    """
    INSERT INTO feed_entries (list, value, family, tier, state, categories, services, tags,
        families, ports, first_seen, last_seen, expires, reported, eligible_at, listed_day,
        removed_day, removed_reason, corroborated, corroborated_day, target_id)
    VALUES (:list, :value, :family, :tier, :state, :categories, :services, :tags, :families,
        :ports, :first_seen, :last_seen, :expires, :reported, :eligible_at, :listed_day,
        :removed_day, :removed_reason, :corroborated, :corroborated_day, :target_id)
    ON CONFLICT (list, value) DO UPDATE SET family = EXCLUDED.family, tier = EXCLUDED.tier,
        state = EXCLUDED.state, categories = EXCLUDED.categories, services = EXCLUDED.services,
        tags = EXCLUDED.tags, families = EXCLUDED.families, ports = EXCLUDED.ports,
        first_seen = EXCLUDED.first_seen, last_seen = EXCLUDED.last_seen,
        expires = EXCLUDED.expires, reported = EXCLUDED.reported,
        eligible_at = EXCLUDED.eligible_at, listed_day = EXCLUDED.listed_day,
        removed_day = EXCLUDED.removed_day, removed_reason = EXCLUDED.removed_reason,
        corroborated = EXCLUDED.corroborated, corroborated_day = EXCLUDED.corroborated_day,
        target_id = EXCLUDED.target_id
    """
)


def _params(r: EntryRow) -> dict[str, Any]:
    return {
        "list": r.list_id,
        "value": r.value,
        "family": r.family,
        "tier": r.tier,
        "state": r.state,
        "categories": r.categories,
        "services": r.services,
        "tags": r.tags,
        "families": r.families,
        "ports": r.ports,
        "first_seen": r.first_seen,
        "last_seen": r.last_seen,
        "expires": r.expires,
        "reported": r.reported,
        "eligible_at": r.eligible_at,
        "listed_day": r.listed_day,
        "removed_day": r.removed_day,
        "removed_reason": r.removed_reason,
        "corroborated": r.corroborated,
        "corroborated_day": r.corroborated_day,
        "target_id": r.target_id,
    }


async def store_plan(
    session: AsyncSession, plan: Plan, existing: dict[tuple[str, str], EntryRow]
) -> None:
    changed = [_params(r) for k, r in plan.rows.items() if existing.get(k) != r]
    for i in range(0, len(changed), 2000):
        await session.execute(_UPSERT, changed[i : i + 2000])
    for list_id, value in plan.deletes:
        await session.execute(
            text("DELETE FROM feed_entries WHERE list = :l AND value = :v AND state <> 'removed'"),
            {"l": list_id, "v": value},
        )


def to_feed_entry(r: EntryRow) -> FeedEntry | None:
    try:
        return FeedEntry(
            value=r.value,
            family=r.family if r.family in (4, 6) else "dns",
            tier=r.tier,
            categories=r.categories,
            services=r.services,
            tags=r.tags,
            families=r.families,
            ports=r.ports,
            first_seen=r.first_seen.isoformat(),
            last_seen=r.last_seen.isoformat(),
            expires=r.expires.isoformat(),
            reported=r.reported,
        )
    except (ValidationError, ValueError):
        return None


def entries_by_list(
    plan: Plan, excluded: Callable[[str, str], str | None]
) -> tuple[dict[str, list[FeedEntry]], int]:
    """Entries of the five published lists. Every one is checked against the exclusions once
    more at render time. Returns the lists and how many entries were dropped by that check."""
    out: dict[str, list[FeedEntry]] = {name: [] for name in LIST_IDS}
    dropped = 0
    for base, rows in plan.listed().items():
        for r in rows:
            entry = to_feed_entry(r)
            if entry is None or excluded(base, r.value) is not None:
                dropped += 1
                continue
            out[base].append(entry)
            if r.tier == "high" and base in lifecycle.HIGH_OF:
                out[lifecycle.HIGH_OF[base]].append(entry)
    return out, dropped


async def _next_serial(session: AsyncSession, root: Path) -> int:
    top = (
        await session.execute(text("SELECT coalesce(max(serial), 0) FROM feed_runs"))
    ).scalar_one()
    return max(int(top), publish.current_serial(root)) + 1


async def _record_run(
    session: AsyncSession,
    *,
    serial: int,
    now: datetime,
    state: str,
    counts: dict[str, Any],
    diff: dict[str, Any] | None = None,
    error_code: str | None = None,
) -> None:
    await session.execute(
        text(
            "INSERT INTO feed_runs (serial, run_at, state, counts, diff, error_code) "
            "VALUES (:s, :at, :st, CAST(:c AS jsonb), CAST(:d AS jsonb), :e)"
        ),
        {
            "s": serial,
            "at": now,
            "st": state,
            "c": json.dumps(counts),
            "d": json.dumps(diff) if diff is not None else None,
            "e": error_code,
        },
    )


async def _audit(session: AsyncSession, action: str, detail: dict[str, Any]) -> None:
    await session.execute(
        text(
            "INSERT INTO hub_audit (actor, action, detail) "
            "VALUES ('feed-job', :a, CAST(:d AS jsonb))"
        ),
        {"a": action, "d": json.dumps(detail)},
    )


# --- the job ----------------------------------------------------------------------------------


def _load_secret(path: str) -> minisign.SecretKey | None:
    try:
        return minisign.parse_secret_key(Path(path).read_text(encoding="ascii"))
    except (OSError, FeedError, ValueError):
        return None


async def run_once(
    session: AsyncSession,
    s: Settings,
    now: datetime,
    *,
    corroborate: Corroborate | None = None,
    force: bool = False,
) -> JobResult:
    """One feed run. ``force`` skips the interval check (tests, ``hub.admin feeds rebuild``)."""
    if s.feed_mode == "off" or not s.external_ranges_enabled:
        return JobResult("off")
    if await _get(session, PAUSED_KEY) == "1":
        return JobResult("paused")
    last = await _get(session, LAST_RUN_KEY)
    if (
        not force
        and last is not None
        and now - datetime.fromisoformat(last) < timedelta(minutes=s.feed_interval_min)
    ):
        return JobResult("skipped")
    await _set(session, LAST_RUN_KEY, now.isoformat())
    await session.commit()
    secret = _load_secret(s.feed_signing_key_file)
    if secret is None:
        return await _status(session, JobResult("failed", error_code="no_key"), now)
    today = now.date()
    root = Path(s.feed_dir)
    try:
        excl = await load_exclusions(session, s, today)
    except RangesStale:
        return await _status(session, JobResult("failed", error_code="ranges_stale"), now)

    def excluded(list_id: str, value: str) -> str | None:
        return excl.classify(value, is_domain=list_id == select.DOMAINS)

    eligible = await consensus.eligible_nodes(session, s, today)
    await link_hosts(session, today - timedelta(days=s.obs_retention_days))
    inputs = await load_inputs(session, s, today, eligible)
    existing = await load_existing(session)
    ctx = SelectContext(
        k=s.min_nodes,
        today=today,
        cohort_of={n: e.cohort for n, e in eligible.items()},
        ttl_inbound=s.feed_ttl_inbound_days,
        ttl_payload=s.feed_ttl_payload_days,
        ttl_c2=s.feed_ttl_c2_days,
    )
    candidates, fresh = await build_candidates(inputs, ctx, existing, corroborate, today)
    down = await taken_down_keys(session, set(candidates))
    ids = [r.target_id for r in existing.values() if r.target_id]
    states = {
        r.id: r.state
        for r in await session.execute(
            text("SELECT id, state FROM targets WHERE id = ANY(:ids)"), {"ids": ids}
        )
    }
    caps = {
        select.INBOUND: s.feed_max_inbound,
        select.OUTBOUND: s.feed_max_outbound,
        select.DOMAINS: s.feed_max_domains,
    }
    plan = lifecycle.plan(
        existing=existing,
        candidates=candidates,
        now=now,
        hold=timedelta(hours=s.feed_hold_hours),
        caps=caps,
        excluded=excluded,
        taken_down=down,
        target_states=states,
    )
    for key, value in fresh.items():
        row = plan.rows.get(key)
        if row is not None and row.state != lifecycle.REMOVED:
            row.corroborated, row.corroborated_day = value, today
    return await _decide(session, s, now, root, secret, plan, existing, excluded)


async def _decide(
    session: AsyncSession,
    s: Settings,
    now: datetime,
    root: Path,
    secret: minisign.SecretKey,
    plan: Plan,
    existing: dict[tuple[str, str], EntryRow],
    excluded: Callable[[str, str], str | None],
) -> JobResult:
    before = lifecycle.published_sets(_listed_of(existing))
    after = lifecycle.published_sets(plan.listed())
    fingerprint = lifecycle.digest(before, after)
    trips = lifecycle.breaker(
        before,
        after,
        add_pct=s.feed_breaker_add_pct,
        remove_pct=s.feed_breaker_remove_pct,
        minimum=s.feed_breaker_min,
    )
    review = s.feed_mode == "review" and lifecycle.has_additions(before, after)
    if trips or review:
        if await _get(session, DISCARD_KEY) == fingerprint:
            await session.rollback()
            return JobResult("discarded", detail={"digest": fingerprint})
        if await _get(session, RELEASE_KEY) != fingerprint:
            await session.rollback()
            return await _hold(session, s, now, root, before, after, fingerprint, trips)
        await _set(session, RELEASE_KEY, None)
        await session.execute(
            text(
                "UPDATE feed_runs SET state = 'published', diff = NULL, "
                "counts = counts || CAST('{\"released\": true}' AS jsonb) "
                "WHERE state = 'held' AND diff->>'digest' = :d"
            ),
            {"d": fingerprint},
        )
    # Store the plan, then render. Nothing is visible until publish() moves the files.
    await store_plan(session, plan, existing)
    await feed_stats.record_daily(session, plan, now.date())
    serial = await _next_serial(session, root)
    lists, dropped = entries_by_list(plan, excluded)
    counts: dict[str, Any] = {
        "entries": {name: len(v) for name, v in lists.items()},
        "added": dict(plan.added),
        "removed": {k: dict(v) for k, v in plan.removed.items()},
        "exclusions": dict(plan.exclusions),
        "render_dropped": dropped,
    }
    try:
        rendered = await asyncio.to_thread(
            publish.render_all,
            serial=serial,
            now=now,
            valid_days=s.feed_valid_days,
            lists=lists,
            allow_documentation=s.allow_documentation,
        )
    except publish.PublishError as exc:
        await session.rollback()
        await _record_run(
            session, serial=serial, now=now, state="failed", counts={}, error_code=str(exc)
        )
        return await _status(session, JobResult("failed", serial, str(exc)), now)
    remaining = publish.index_remaining(root, now)
    stale = remaining is None or remaining < timedelta(days=s.feed_valid_days) / 2
    if not publish.changed_files(root, rendered, {}) and not stale:
        await session.commit()
        return await _status(session, JobResult("unchanged", detail=counts), now)
    other = {
        "stats.json": await feed_stats.build_stats(session, plan, serial=serial, now=now),
        "removed.json": await feed_stats.build_removed(session, now=now, excluded=excluded),
        "readme.txt": readme.render_readme(s, secret.public.encoded),
        "delist.html": readme.delist_page(),
    }
    await _record_run(session, serial=serial, now=now, state="published", counts=counts)
    try:
        await asyncio.to_thread(
            publish.publish,
            root,
            secret,
            serial=serial,
            now=now,
            valid_days=s.feed_valid_days,
            rendered=rendered,
            other=other,
        )
    except publish.PublishError as exc:
        await session.rollback()
        await _record_run(
            session, serial=serial, now=now, state="failed", counts={}, error_code=str(exc)
        )
        return await _status(session, JobResult("failed", serial, str(exc)), now)
    await session.commit()
    return await _status(session, JobResult("published", serial, detail=counts), now)


def _listed_of(rows: dict[tuple[str, str], EntryRow]) -> dict[str, list[EntryRow]]:
    out: dict[str, list[EntryRow]] = {name: [] for name in select.BASE_LISTS}
    for r in rows.values():
        if r.state == lifecycle.LISTED:
            out[r.list_id].append(r)
    return out


async def _hold(
    session: AsyncSession,
    s: Settings,
    now: datetime,
    root: Path,
    before: dict[str, set[str]],
    after: dict[str, set[str]],
    fingerprint: str,
    trips: list[lifecycle.Trip],
) -> JobResult:
    already = (
        await session.execute(
            text(
                "SELECT serial FROM feed_runs WHERE state = 'held' AND diff->>'digest' = :d "
                "ORDER BY serial DESC LIMIT 1"
            ),
            {"d": fingerprint},
        )
    ).scalar_one_or_none()
    if already is not None:
        await session.commit()
        return JobResult("held", int(already), detail={"digest": fingerprint})
    serial = await _next_serial(session, root)
    diff: dict[str, Any] = {
        "digest": fingerprint,
        "mode": s.feed_mode,
        "trips": [t.__dict__ for t in trips],
        "lists": lifecycle.diff(before, after),
    }
    await _record_run(
        session, serial=serial, now=now, state="held", counts={"trips": len(trips)}, diff=diff
    )
    held = {"serial": serial, "trips": len(trips), "mode": s.feed_mode}
    await _audit(session, "feeds.held", held)
    await session.commit()
    log.warning("feed run held (serial %s): operator review needed", serial)
    return await _status(session, JobResult("held", serial, detail={"digest": fingerprint}), now)


# --- operator hooks (hub.admin) ---------------------------------------------------------------


async def release(session: AsyncSession, serial: int) -> bool:
    """Approve a held run: the next job run publishes exactly that change (and only that)."""
    row = (
        await session.execute(
            text("SELECT diff->>'digest' FROM feed_runs WHERE serial = :s AND state = 'held'"),
            {"s": serial},
        )
    ).first()
    if row is None or row[0] is None:
        return False
    await _set(session, RELEASE_KEY, str(row[0]))
    await _audit(session, "feeds.release", {"serial": serial})
    await session.commit()
    return True


async def discard(session: AsyncSession, serial: int) -> bool:
    """Reject a held run: the same change is not held again until it differs."""
    row = (
        await session.execute(
            text("SELECT diff->>'digest' FROM feed_runs WHERE serial = :s AND state = 'held'"),
            {"s": serial},
        )
    ).first()
    if row is None or row[0] is None:
        return False
    await _set(session, DISCARD_KEY, str(row[0]))
    await session.execute(
        text("UPDATE feed_runs SET state = 'discarded', diff = NULL WHERE serial = :s"),
        {"s": serial},
    )
    await _audit(session, "feeds.discard", {"serial": serial})
    await session.commit()
    return True


async def set_paused(session: AsyncSession, paused: bool) -> None:
    await _set(session, PAUSED_KEY, "1" if paused else None)
    await _audit(session, "feeds.pause" if paused else "feeds.resume", {})
    await session.commit()


def summary(result: JobResult) -> dict[str, Any]:
    """What the worker records for the step (no values)."""
    return {"state": result.state, "serial": result.serial, "error": result.error_code}


__all__ = ["Exclusions", "JobResult", "discard", "release", "run_once", "set_paused", "summary"]

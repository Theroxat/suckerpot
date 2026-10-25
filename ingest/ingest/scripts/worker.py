"""The script library job (M17): fingerprint what attackers typed, explain it from the base.

Every cycle it takes quiet sessions that ran at least two commands, rebuilds each session's
command list from its ``command`` events, normalises it (``ingest.normalize``) and groups the
sessions by fingerprint. One row of ``scripts`` stands for one distinct sequence; its counters
only ever grow (they survive the deletion of old sessions), the links to sessions are capped.
A progress marker in ``system_status`` stops a restart from counting a session twice.

Nothing here executes, fetches or resolves anything from a script: it is text in, text out.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import ARRAY, Text, bindparam, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ingest.features import FeatureSettings, FeatureWorker
from ingest.normalize import MAX_COMMANDS
from ingest.scripts.annotations import AnnotationBase
from ingest.scripts.library import (
    MIN_COMMANDS,
    Pair,
    bounded_lines,
    explain_pairs,
    extract_pairs,
    script_fingerprint,
)

log = logging.getLogger(__name__)

SESSION_BUDGET = 2000  # sessions per cycle
BATCH = 200
LINK_CAP = 200  # links per script
QUIET_MINUTES = 10
INITIAL_LOOKBACK_DAYS = 90
BACKFILL = 200  # explanations rebuilt per cycle when the base changed
CURSOR_KEY = "scripts_cursor"
MAX_TEXT = 8192
CURSOR_MARGIN = timedelta(hours=1)  # the saved progress marker stays this far behind now()


def fit(lines: list[str], limit: int = MAX_TEXT) -> str:
    """Join lines with newlines, dropping trailing lines that would pass ``limit`` characters."""
    out: list[str] = []
    used = 0
    for line in lines:
        used += len(line) + 1
        if used > limit:
            break
        out.append(line)
    return "\n".join(out)


@dataclass(slots=True)
class Seen:
    session_id: str
    ip: str
    sensor: str
    seen_at: datetime
    started_at: datetime
    demo: bool
    pairs: list[Pair] = field(default_factory=list)


class ScriptWorker(FeatureWorker):
    name = "scripts"
    interval_s = 300.0

    def __init__(
        self,
        settings: FeatureSettings,
        factory: async_sessionmaker[AsyncSession] | None = None,
        annotations: AnnotationBase | None = None,
        *,
        link_cap: int = LINK_CAP,
        session_budget: int = SESSION_BUDGET,
    ) -> None:
        super().__init__(settings, enabled=settings.scripts_enabled)
        self.factory = factory
        self.annotations = annotations or AnnotationBase((), 1)
        self.link_cap = link_cap
        self.session_budget = session_budget
        self.processed = 0
        self.skipped = 0
        self.rows_read = 0  # command rows fetched by the last cycle (a bound, for tests)

    def _db(self) -> AsyncSession:
        if self.factory is None:
            raise RuntimeError("the script worker has no database")
        return self.factory()

    async def status(self) -> dict[str, Any]:
        out = await super().status()
        if self.enabled:
            out[self.name]["sessions_processed"] = self.processed
            out[self.name]["annotation_rules"] = len(self.annotations.entries)
        return out

    async def run_once(self) -> None:
        if self.factory is None:
            return
        await self.ingest_sessions()
        await self.link_campaigns()
        await self.rebuild_explanations()

    # ---- progress marker ---------------------------------------------------------------------
    async def _cursor(self) -> tuple[datetime, str]:
        async with self._db() as db:
            row = (
                await db.execute(
                    text("SELECT value FROM system_status WHERE key = :k"), {"k": CURSOR_KEY}
                )
            ).first()
            if row is not None:
                try:
                    return datetime.fromisoformat(row.value["ts"]), str(row.value["session_id"])
                except (KeyError, ValueError, TypeError):
                    pass
            start = (
                await db.execute(
                    text("SELECT now() - make_interval(days => :d) AS ts"),
                    {"d": INITIAL_LOOKBACK_DAYS},
                )
            ).scalar_one()
            return start, ""

    @staticmethod
    async def _save_cursor(db: AsyncSession, ts: datetime, session_id: str) -> None:
        value = json.dumps({"ts": ts.isoformat(), "session_id": session_id})
        await db.execute(
            text(
                """
                INSERT INTO system_status (key, value, updated_at)
                VALUES (:k, CAST(:v AS jsonb), now())
                ON CONFLICT (key) DO UPDATE SET value = CAST(:v AS jsonb), updated_at = now()
                """
            ),
            {"k": CURSOR_KEY, "v": value},
        )

    # ---- sessions -> scripts -----------------------------------------------------------------
    async def ingest_sessions(self) -> int:
        done = 0
        ts, sid = await self._cursor()
        saved = (ts, sid)
        self.rows_read = 0
        while done < self.session_budget:
            limit = min(BATCH, self.session_budget - done)
            async with self._db() as db, db.begin():
                batch = await self._candidates(db, ts, sid, limit)
                if not batch:
                    break
                self.rows_read += await self._load_commands(db, batch)
                groups: dict[str, list[Seen]] = {}
                for seen in batch:
                    if len(seen.pairs) >= MIN_COMMANDS:
                        groups.setdefault(script_fingerprint(seen.pairs), []).append(seen)
                for fp, members in groups.items():
                    try:
                        async with db.begin_nested():  # a failing group is skipped, not fatal
                            await self._store_group(db, fp, members)
                    except Exception as exc:  # the message may hold a statement: log the type
                        self.skipped += 1
                        log.warning("script group skipped (%s)", type(exc).__name__)
                ts, sid = batch[-1].seen_at, batch[-1].session_id
                # The saved marker trails now() by CURSOR_MARGIN, so a session that reached the
                # database late is still picked up; sessions already linked are not re-read.
                await self._save_cursor(db, *self._margin(saved, (ts, sid)))
                saved = self._margin(saved, (ts, sid))
            done += len(batch)
            self.processed += len(batch)
            if len(batch) < limit:
                break
        return done

    @staticmethod
    async def _candidates(db: AsyncSession, ts: datetime, sid: str, limit: int) -> list[Seen]:
        rows = await db.execute(
            text(
                """
                SELECT s.session_id, host(s.src_ip) AS ip, s.sensor, s.started_at, s.last_event_at
                FROM sessions s
                WHERE s.commands >= :min AND NOT s.benign
                  AND s.last_event_at < now() - make_interval(mins => :quiet)
                  AND (s.last_event_at, s.session_id) > (:ts, :sid)
                  AND NOT EXISTS (SELECT 1 FROM script_sessions x WHERE x.session_id = s.session_id)
                ORDER BY s.last_event_at, s.session_id
                LIMIT :n
                """
            ),
            {"min": MIN_COMMANDS, "quiet": QUIET_MINUTES, "ts": ts, "sid": sid, "n": limit},
        )
        return [
            Seen(r.session_id, r.ip, r.sensor, r.last_event_at, r.started_at, False) for r in rows
        ]

    @staticmethod
    def _margin(saved: tuple[datetime, str], reached: tuple[datetime, str]) -> tuple[datetime, str]:
        """The progress marker to save: never behind ``saved``, never within the margin of now."""
        floor = datetime.now(UTC) - CURSOR_MARGIN
        ts = min(reached[0], floor)
        return max(saved, (ts, "" if ts != reached[0] else reached[1]))

    @staticmethod
    async def _load_commands(db: AsyncSession, batch: list[Seen]) -> int:
        """Fill ``pairs`` of every session; at most MAX_COMMANDS rows per session are read."""
        by_id = {s.session_id: s for s in batch}
        stmt = text(
            """
            SELECT s.session_id, e.cmd, e.demo
            FROM unnest(CAST(:ids AS text[])) AS s(session_id)
            CROSS JOIN LATERAL (
                SELECT left(COALESCE(data ->> 'input', data ->> 'command', ''), 1024) AS cmd,
                       COALESCE(data ->> 'demo', '') = 'true' AS demo
                FROM events
                WHERE type = 'command' AND session_id = s.session_id
                  AND ts >= :lo AND ts <= :hi
                ORDER BY ts, id
                LIMIT :cap
            ) AS e
            """
        ).bindparams(bindparam("ids", type_=ARRAY(Text)))
        lo = min(s.started_at for s in batch)
        hi = max(s.seen_at for s in batch)
        rows = await db.execute(stmt, {"ids": list(by_id), "lo": lo, "hi": hi, "cap": MAX_COMMANDS})
        commands: dict[str, list[str]] = {}
        demo: dict[str, bool] = {}
        count = 0
        for r in rows:
            count += 1
            commands.setdefault(r.session_id, []).append(r.cmd)
            demo[r.session_id] = demo.get(r.session_id, True) and r.demo
        for sid, cmds in commands.items():
            by_id[sid].pairs = extract_pairs(cmds)
            by_id[sid].demo = demo[sid]
        return count

    async def _store_group(self, db: AsyncSession, fp: str, members: list[Seen]) -> None:
        members.sort(key=lambda m: (m.seen_at, m.session_id))
        previous = (
            await db.execute(
                text("SELECT last_seen FROM scripts WHERE fingerprint = decode(:fp, 'hex')"),
                {"fp": fp},
            )
        ).scalar_one_or_none()
        first = members[0]
        explained = explain_pairs(first.pairs, self.annotations)
        sensors = sorted({m.sensor for m in members})
        row = (
            await db.execute(
                text(
                    """
                    INSERT INTO scripts (fingerprint, normalized_text, sample_text, line_count,
                                         first_seen, last_seen, sensors, techniques, demo)
                    VALUES (decode(:fp, 'hex'), :norm, :sample, :n, :first, :last, :sensors,
                            :techs, :demo)
                    ON CONFLICT (fingerprint) DO UPDATE SET
                        first_seen = LEAST(scripts.first_seen, EXCLUDED.first_seen),
                        last_seen = GREATEST(scripts.last_seen, EXCLUDED.last_seen),
                        sensors = (SELECT COALESCE(array_agg(DISTINCT x ORDER BY x), '{}')
                                   FROM unnest(scripts.sensors || EXCLUDED.sensors) AS x),
                        demo = scripts.demo AND EXCLUDED.demo
                    RETURNING id, (xmax = 0) AS inserted
                    """
                ).bindparams(
                    bindparam("sensors", type_=ARRAY(Text)), bindparam("techs", type_=ARRAY(Text))
                ),
                {
                    "fp": fp,
                    "norm": fit([p.norm for p in first.pairs]),
                    "sample": fit([p.raw for p in first.pairs]),
                    "n": min(len(first.pairs), 32000),
                    "first": members[0].seen_at,
                    "last": members[-1].seen_at,
                    "sensors": sensors[:16],
                    "techs": explained["techniques"],
                    "demo": all(m.demo for m in members),
                },
            )
        ).one()
        script_id: int = row.id
        if row.inserted:
            await self._save_explanation(db, script_id, explained)
        linked = (
            await db.execute(
                text("SELECT count(*) FROM script_sessions WHERE script_id = :i"), {"i": script_id}
            )
        ).scalar_one()
        new_sources = 0
        if linked >= self.link_cap and previous is not None:
            # Past the cap there is no link to say "already counted": a session older than the
            # script's newest counted one is a re-read, not a new run.
            members = [m for m in members if m.seen_at > previous]
            if not members:
                return
        if linked < self.link_cap:  # past the cap the source count stops growing (lower bound)
            known = {
                r.ip
                for r in await db.execute(
                    text(
                        "SELECT host(src_ip) AS ip FROM script_sessions WHERE script_id = :i "
                        "AND host(src_ip) = ANY(:ips)"
                    ).bindparams(bindparam("ips", type_=ARRAY(Text))),
                    {"i": script_id, "ips": sorted({m.ip for m in members})},
                )
            }
            new_sources = len({m.ip for m in members} - known)
        for m in members[: max(0, self.link_cap - linked)]:
            await db.execute(
                text(
                    """
                    INSERT INTO script_sessions (script_id, session_id, src_ip, sensor, seen_at)
                    VALUES (:i, :sid, CAST(:ip AS inet), :sensor, :at)
                    ON CONFLICT DO NOTHING
                    """
                ),
                {
                    "i": script_id,
                    "sid": m.session_id,
                    "ip": m.ip,
                    "sensor": m.sensor,
                    "at": m.seen_at,
                },
            )
        await db.execute(
            text(
                "UPDATE scripts SET sessions = sessions + :n, sources = sources + :s WHERE id = :i"
            ),
            {"n": len(members), "s": new_sources, "i": script_id},
        )

    # ---- explanations ------------------------------------------------------------------------
    async def _save_explanation(
        self, db: AsyncSession, script_id: int, explained: dict[str, Any]
    ) -> None:
        await db.execute(
            text(
                """
                INSERT INTO script_explanations (script_id, source, prompt_version, lines, summary)
                VALUES (:i, 'annotations', :v, CAST(:lines AS jsonb), :summary)
                ON CONFLICT (script_id, source) DO UPDATE SET
                    prompt_version = :v, lines = CAST(:lines AS jsonb), summary = :summary,
                    created_at = now()
                """
            ),
            {
                "i": script_id,
                "v": self.annotations.version,
                "lines": json.dumps(bounded_lines(explained["lines"])),
                "summary": explained["summary"][:600],
            },
        )

    async def rebuild_explanations(self) -> int:
        """Explain scripts that have no explanation from the current rule files."""
        async with self._db() as db, db.begin():
            rows = (
                await db.execute(
                    text(
                        """
                        SELECT s.id, s.sample_text FROM scripts s
                        LEFT JOIN script_explanations e
                               ON e.script_id = s.id AND e.source = 'annotations'
                        WHERE e.script_id IS NULL OR e.prompt_version <> :v
                        ORDER BY s.last_seen DESC LIMIT :n
                        """
                    ),
                    {"v": self.annotations.version, "n": BACKFILL},
                )
            ).all()
            for r in rows:
                try:
                    async with db.begin_nested():
                        explained = explain_pairs(
                            extract_pairs(r.sample_text.splitlines()), self.annotations
                        )
                        await self._save_explanation(db, r.id, explained)
                        await db.execute(
                            text("UPDATE scripts SET techniques = :t WHERE id = :i").bindparams(
                                bindparam("t", type_=ARRAY(Text))
                            ),
                            {"t": explained["techniques"], "i": r.id},
                        )
                except Exception as exc:
                    self.skipped += 1
                    log.warning("script explanation skipped (%s)", type(exc).__name__)
        return len(rows)

    # ---- campaigns (M15 maps the 'script' key; this only reads it) ----------------------------
    async def link_campaigns(self) -> int:
        async with self._db() as db, db.begin():
            result = await db.execute(
                text(
                    """
                    UPDATE scripts s SET campaign_id = COALESCE(c.merged_into, c.id)
                    FROM campaign_keys k JOIN campaigns c ON c.id = k.campaign_id
                    WHERE k.kind = 'script' AND k.value = encode(s.fingerprint, 'hex')
                      AND s.last_seen > now() - interval '30 days'
                      AND s.campaign_id IS DISTINCT FROM COALESCE(c.merged_into, c.id)
                    """
                )
            )
            return int(getattr(result, "rowcount", 0) or 0)


__all__ = ["ScriptWorker", "fit"]

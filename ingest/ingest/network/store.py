"""Database access of the network worker: one narrow interface and its SQL implementation.

The worker only talks to ``Store``, so its logic is tested against an in-memory fake. The SQL
here reads membership, submissions, targets and the summary (ingest owns them), and a few
indicator values for the reveal flow and the "you helped" flag (read only).
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, fields
from datetime import date, datetime
from typing import Any, Protocol

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_netproto import models as wire

from . import demo

# Columns the worker may set (never an arbitrary name from outside this module).
MEMBERSHIP_COLUMNS = (
    "desired", "state", "pseudonym", "country", "show_country", "node_id", "fingerprint",
    "pubkey", "privkey_enc", "privkey_nonce", "enrolled_day", "eligible_from_day", "standing",
    "next_submit_at", "last_submit_day", "last_pull_at", "last_summary_at", "pull_cursor",
    "synced_pseudonym", "synced_country", "synced_show_country", "leave_requested_at",
    "last_error_code",
)  # fmt: skip
RECENT_VALUES_LIMIT = 20_000
MINE_DAYS = 14


@dataclass(slots=True)
class Membership:
    desired: str = "off"
    state: str = "off"
    pseudonym: str | None = None
    country: str | None = None
    show_country: bool = False
    node_id: uuid.UUID | None = None
    fingerprint: str | None = None
    pubkey: bytes | None = None
    privkey_enc: bytes | None = None
    privkey_nonce: bytes | None = None
    enrolled_day: date | None = None
    eligible_from_day: date | None = None
    standing: str | None = None
    next_submit_at: datetime | None = None
    last_submit_day: date | None = None
    last_pull_at: datetime | None = None
    last_summary_at: datetime | None = None
    pull_cursor: str | None = None
    synced_pseudonym: str | None = None
    synced_country: str | None = None
    synced_show_country: bool | None = None
    leave_requested_at: datetime | None = None
    last_error_code: str | None = None


assert {f.name for f in fields(Membership)} == set(MEMBERSHIP_COLUMNS)  # noqa: S101


class Store(Protocol):
    async def membership(self) -> Membership: ...
    async def update(self, **values: Any) -> None: ...
    async def wipe(self, *, leave_error: str | None = None) -> None: ...
    async def submitted_days(self) -> set[date]: ...
    async def submission(self, day: date) -> dict[str, Any] | None: ...
    async def record_submission(
        self,
        day: date,
        *,
        batch_id: str,
        status: str,
        counts: dict[str, int],
        dropped: dict[str, int],
        error_code: str | None,
        payload: dict[str, Any] | None,
        sent_at: datetime | None,
    ) -> None: ...
    async def drop_payload(self, day: date) -> None: ...
    async def upsert_targets(self, targets: list[wire.Target]) -> None: ...
    async def revealable(self, value_bs: set[str]) -> set[str]: ...
    async def reveal_values(self, kind: str) -> list[str]: ...
    async def refresh_mine(self) -> None: ...
    async def mark_mine_blinded(self, value_bs: set[str]) -> None: ...
    async def save_summary(self, data: dict[str, Any]) -> None: ...
    async def recent_values(self, kind: str) -> list[str]: ...


class SqlStore:
    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self.factory = factory

    async def membership(self) -> Membership:
        cols = ", ".join(MEMBERSHIP_COLUMNS)
        async with self.factory() as session:
            row = (
                await session.execute(text(f"SELECT {cols} FROM network_membership WHERE id = 1"))  # noqa: S608
            ).one_or_none()
        return Membership() if row is None else Membership(**row._asdict())

    async def update(self, **values: Any) -> None:
        unknown = set(values) - set(MEMBERSHIP_COLUMNS)
        if unknown:
            raise ValueError("unknown membership column")
        if not values:
            return
        sets = ", ".join(f"{k} = :{k}" for k in values)
        async with self.factory() as session, session.begin():
            await session.execute(
                text(f"UPDATE network_membership SET {sets} WHERE id = 1"),  # noqa: S608
                values,
            )

    async def wipe(self, *, leave_error: str | None = None) -> None:
        """Leaving: membership back to its defaults (key included), every network row gone."""
        blank: dict[str, Any] = {c: None for c in MEMBERSHIP_COLUMNS}
        blank.update(desired="off", state="off", show_country=False, last_error_code=leave_error)
        sets = ", ".join(f"{k} = :{k}" for k in blank)
        async with self.factory() as session, session.begin():
            await session.execute(text(f"UPDATE network_membership SET {sets} WHERE id = 1"), blank)  # noqa: S608
            await session.execute(
                text("UPDATE network_membership SET requested_by = NULL, requested_at = NULL")
            )
            for table in ("network_targets", "network_submissions", "network_summary"):
                await session.execute(text(f"DELETE FROM {table}"))  # noqa: S608

    async def submitted_days(self) -> set[date]:
        async with self.factory() as session:
            rows = await session.execute(
                text("SELECT day FROM network_submissions WHERE status IN ('sent', 'skipped')")
            )
            return {r.day for r in rows}

    async def submission(self, day: date) -> dict[str, Any] | None:
        async with self.factory() as session:
            row = (
                await session.execute(
                    text(
                        "SELECT batch_id, status, error_code, payload "
                        "FROM network_submissions WHERE day = :d"
                    ),
                    {"d": day},
                )
            ).one_or_none()
        return None if row is None else dict(row._asdict())

    async def record_submission(
        self,
        day: date,
        *,
        batch_id: str,
        status: str,
        counts: dict[str, int],
        dropped: dict[str, int],
        error_code: str | None,
        payload: dict[str, Any] | None,
        sent_at: datetime | None,
    ) -> None:
        async with self.factory() as session, session.begin():
            await session.execute(
                text(
                    """
                    INSERT INTO network_submissions
                        (day, batch_id, sent_at, status, counts, dropped, error_code, payload)
                    VALUES (:day, :bid, :sent, :status, CAST(:counts AS jsonb),
                            CAST(:dropped AS jsonb), :err, CAST(:payload AS jsonb))
                    ON CONFLICT (day) DO UPDATE SET batch_id = EXCLUDED.batch_id,
                        sent_at = EXCLUDED.sent_at, status = EXCLUDED.status,
                        counts = EXCLUDED.counts, dropped = EXCLUDED.dropped,
                        error_code = EXCLUDED.error_code,
                        payload = COALESCE(EXCLUDED.payload, network_submissions.payload)
                    """
                ),
                {
                    "day": day,
                    "bid": batch_id,
                    "sent": sent_at,
                    "status": status,
                    "counts": json.dumps(counts),
                    "dropped": json.dumps(dropped),
                    "err": error_code,
                    "payload": None if payload is None else json.dumps(payload),
                },
            )

    async def drop_payload(self, day: date) -> None:
        """Forget the stored body of a day (a batch the guard refused is never kept)."""
        async with self.factory() as session, session.begin():
            await session.execute(
                text("UPDATE network_submissions SET payload = NULL WHERE day = :day"),
                {"day": day},
            )

    async def upsert_targets(self, targets: list[wire.Target]) -> None:
        if not targets:
            return
        async with self.factory() as session, session.begin():
            for t in targets:
                await session.execute(
                    text(
                        """
                        INSERT INTO network_targets (hub_id, kind, value, value_b, state, nodes,
                            countries, first_day, last_day, services, activity, tags, families,
                            reported_day, taken_down_day, updated_at)
                        VALUES (:id, :kind, :value, :value_b, :state, :nodes, :countries,
                            :first_day, :last_day, :services, :activity, :tags, :families,
                            :reported_day, :taken_down_day, now())
                        ON CONFLICT (hub_id) DO UPDATE SET
                            value = COALESCE(EXCLUDED.value, network_targets.value),
                            value_b = COALESCE(EXCLUDED.value_b, network_targets.value_b),
                            state = EXCLUDED.state, nodes = EXCLUDED.nodes,
                            countries = EXCLUDED.countries, first_day = EXCLUDED.first_day,
                            last_day = EXCLUDED.last_day, services = EXCLUDED.services,
                            activity = EXCLUDED.activity, tags = EXCLUDED.tags,
                            families = EXCLUDED.families, reported_day = EXCLUDED.reported_day,
                            taken_down_day = EXCLUDED.taken_down_day, updated_at = now()
                        """
                    ),
                    {
                        "id": t.id,
                        "kind": t.kind,
                        "value": t.value,
                        "value_b": t.value_b,
                        "state": t.state,
                        "nodes": t.nodes,
                        "countries": t.countries,
                        "first_day": date.fromisoformat(t.first_day),
                        "last_day": date.fromisoformat(t.last_day),
                        "services": t.services,
                        "activity": t.activity,
                        "tags": t.tags,
                        "families": t.families,
                        "reported_day": _day(t.reported_day),
                        "taken_down_day": _day(t.taken_down_day),
                    },
                )

    async def refresh_mine(self) -> None:
        """Flag the targets this sensor saw in the last 14 days (clear values, then blinded)."""
        window = f"{MINE_DAYS} days"
        real = demo.not_demo("s", f"now() - interval '{window}'", "now() + interval '1 day'")
        async with self.factory() as session, session.begin():
            await session.execute(
                text(
                    f"""
                    UPDATE network_targets t SET mine = true
                    WHERE NOT t.mine AND (
                      (t.kind = 'ip' AND EXISTS (
                         SELECT 1 FROM sessions s WHERE host(s.src_ip) = t.value
                           AND NOT s.benign AND s.scanner_name IS NULL
                           AND s.started_at >= now() - interval '{window}'
                           AND {real}))
                      OR (t.kind = 'sha256' AND EXISTS (
                         SELECT 1 FROM samples sm WHERE sm.sha256 = t.value
                           AND sm.last_seen >= now() - interval '{window}'))
                      OR (t.kind IN ('c2_ip', 'c2_domain') AND EXISTS (
                         SELECT 1 FROM sample_links l JOIN samples sm ON sm.sha256 = l.sha256
                         WHERE l.value = split_part(t.value, ':', 1)
                           AND sm.last_seen >= now() - interval '{window}'))
                      OR (t.kind IN ('url', 'domain') AND t.value IS NOT NULL AND EXISTS (
                         SELECT 1 FROM indicators i
                         WHERE (i.value = t.value OR i.host = t.value) AND NOT i.demo
                           AND i.last_seen >= now() - interval '{window}'))
                    )
                    """  # noqa: S608  (constant fragment only)
                )
            )

    async def mark_mine_blinded(self, value_bs: set[str]) -> None:
        if not value_bs:
            return
        async with self.factory() as session, session.begin():
            await session.execute(
                text("UPDATE network_targets SET mine = true WHERE value_b = ANY(:v)"),
                {"v": sorted(value_bs)},
            )

    async def save_summary(self, data: dict[str, Any]) -> None:
        async with self.factory() as session, session.begin():
            await session.execute(
                text(
                    """
                    INSERT INTO network_summary (id, data, fetched_at)
                    VALUES (1, CAST(:d AS jsonb), now())
                    ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, fetched_at = now()
                    """
                ),
                {"d": json.dumps(data)},
            )

    async def revealable(self, value_bs: set[str]) -> set[str]:
        """Hashes this node may reveal: targets the hub confirmed that it holds only blinded."""
        if not value_bs:
            return set()
        async with self.factory() as session:
            rows = await session.execute(
                text(
                    "SELECT DISTINCT value_b FROM network_targets "
                    "WHERE value_b = ANY(:v) AND value IS NULL "
                    "AND state IN ('confirmed', 'reported', 'taken_down')"
                ),
                {"v": sorted(value_bs)},
            )
            return {r.value_b for r in rows}

    async def reveal_values(self, kind: str) -> list[str]:
        """Clear values eligible for a reveal: the same rows the batch builder submits.

        Download URLs (or their hosts) of real, non-benign, non-scanner sessions only; any other
        indicator role is never revealed, whatever hash the hub asks for.
        """
        column = "i.value" if kind == "url" else "i.host"
        async with self.factory() as session:
            rows = await session.execute(
                text(
                    f"SELECT DISTINCT {column} AS v FROM indicators i "  # noqa: S608
                    f"WHERE {column} IS NOT NULL AND i.type = 'url' "
                    "AND i.role = 'download_host' AND NOT i.demo "
                    f"AND i.last_seen >= now() - interval '{MINE_DAYS} days' "
                    "AND EXISTS (SELECT 1 FROM indicator_sessions x "
                    "JOIN sessions s ON s.session_id = x.session_id "
                    "WHERE x.indicator_id = i.id AND NOT s.benign AND s.scanner_name IS NULL) "
                    "LIMIT :lim"
                ),
                {"lim": RECENT_VALUES_LIMIT},
            )
            return [r.v for r in rows]

    async def recent_values(self, kind: str) -> list[str]:
        """Recent indicator values: full URLs for ``url``, host names for ``domain``."""
        column = "value" if kind == "url" else "host"
        async with self.factory() as session:
            rows = await session.execute(
                text(
                    f"SELECT DISTINCT {column} AS v FROM indicators "  # noqa: S608
                    f"WHERE {column} IS NOT NULL AND NOT demo "
                    + ("AND type = 'url' " if kind == "url" else "")
                    + f"AND last_seen >= now() - interval '{MINE_DAYS} days' LIMIT :lim"
                ),
                {"lim": RECENT_VALUES_LIMIT},
            )
            return [r.v for r in rows]


def _day(value: str | None) -> date | None:
    return None if value is None else date.fromisoformat(value)

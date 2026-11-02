"""The community blocklist feed worker (design M30 section 10).

Downloads the public, signed Selfhostr blocklist feed and keeps the verified entries in
``network_feed_entries``. It is independent of network membership: the feed is public, so a node
that never joined can use it. Off unless ``NETWORK_FEED_ENABLED=true`` with a URL and a key.

One cycle:

1. N11: flag, URL and key set; the egress gate is open (``FeedClient``);
2. conditional ``GET index.json``, then ``index.json.minisig``; verify the signature, the trusted
   comment, freshness and rollback (N13);
3. for each configured list whose sha256 changed: ``GET <list>.json`` and its signature, verify
   size, sha256, signature and name against the index, parse strictly (N14);
4. replace every changed list and update ``network_feed_state`` in ONE transaction, so a failure
   anywhere keeps the last good data and only records an ``error_code``;
5. ``seen_here`` from local data only (sessions, indicators, fetch targets, sample links).

Nothing from the feed is logged, executed or contacted.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any, Protocol

import httpx
from sqlalchemy import insert, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db.models import NetworkFeedEntryRow, NetworkFeedStateRow
from suckerpot_netproto.feeds import FeedEntry, FeedError, minisign
from suckerpot_netproto.feeds import models as fm
from suckerpot_netproto.feeds import parse as fp

from ingest.egress import EgressClosed, EgressGate
from ingest.features import FeatureSettings, FeatureWorker

from . import demo
from .feed_client import (
    FeedClient,
    FeedHttpError,
    FeedSettings,
    FeedTooLarge,
    FeedUnavailable,
)

log = logging.getLogger(__name__)

SEEN_DAYS = 30
INDEX = "index.json"
INSERT_CHUNK = 5000
RETRY_CLOSED_S = 120.0
# Library code -> worker error code (design 10.4).
ERROR_CODES = {
    "bad_signature": "bad_signature",
    "wrong_key": "bad_signature",
    "wrong_file": "bad_signature",
    "wrong_serial": "bad_signature",
    "rollback": "feed_rollback",
    "expired": "feed_expired",
    "too_large": "too_large",
}


class FeedFailure(Exception):
    """A cycle that ends with an error code. The last good data stays."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def library_code(exc: FeedError) -> str:
    return ERROR_CODES.get(exc.code, "feed_invalid")


@dataclass(slots=True)
class FeedState:
    serial: int | None = None
    generated_at: datetime | None = None
    valid_until: datetime | None = None
    key_id: str | None = None
    index_sha256: str | None = None
    files: dict[str, dict[str, Any]] = field(default_factory=dict)
    last_fetch_at: datetime | None = None
    last_ok_at: datetime | None = None
    error_code: str | None = None


class FeedStore(Protocol):
    async def state(self) -> FeedState | None: ...
    async def record_error(self, code: str, now: datetime) -> None: ...
    async def touch_ok(self, now: datetime) -> None: ...
    async def apply(
        self,
        state: FeedState,
        replace: dict[str, list[FeedEntry]],
        keep_lists: set[str],
    ) -> None: ...
    async def recompute_seen_here(self, now: datetime) -> int: ...
    async def wipe(self) -> bool: ...


def _entry_row(list_id: str, e: FeedEntry) -> dict[str, Any]:
    return {
        "list_name": list_id,
        "value": e.value,
        "family": e.family if isinstance(e.family, int) else None,  # NULL = a domain name
        "tier": e.tier,
        "categories": list(e.categories),
        "services": list(e.services),
        "tags": list(e.tags),
        "families": list(e.families),
        "ports": list(e.ports),
        "first_seen": date.fromisoformat(e.first_seen),
        "last_seen": date.fromisoformat(e.last_seen),
        "expires": date.fromisoformat(e.expires),
        "reported": e.reported,
        "seen_here": False,
    }


class SqlFeedStore:
    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self.factory = factory

    async def state(self) -> FeedState | None:
        async with self.factory() as session:
            row = await session.get(NetworkFeedStateRow, 1)
            if row is None:
                return None
            return FeedState(
                serial=row.serial,
                generated_at=row.generated_at,
                valid_until=row.valid_until,
                key_id=row.key_id,
                index_sha256=row.index_sha256,
                files=dict(row.files or {}),
                last_fetch_at=row.last_fetch_at,
                last_ok_at=row.last_ok_at,
                error_code=row.error_code,
            )

    async def _upsert(self, session: AsyncSession, values: dict[str, Any]) -> None:
        stmt = pg_insert(NetworkFeedStateRow).values(id=1, **values)
        await session.execute(
            stmt.on_conflict_do_update(
                index_elements=["id"], set_={**values, "updated_at": text("now()")}
            )
        )

    async def record_error(self, code: str, now: datetime) -> None:
        async with self.factory() as session, session.begin():
            await self._upsert(session, {"error_code": code, "last_fetch_at": now})

    async def touch_ok(self, now: datetime) -> None:
        async with self.factory() as session, session.begin():
            await self._upsert(
                session, {"error_code": None, "last_fetch_at": now, "last_ok_at": now}
            )

    async def apply(
        self, state: FeedState, replace: dict[str, list[FeedEntry]], keep_lists: set[str]
    ) -> None:
        async with self.factory() as session, session.begin():
            # A list that is no longer configured goes; a changed list is replaced whole.
            await session.execute(
                text("DELETE FROM network_feed_entries WHERE NOT (list = ANY(:keep))"),
                {"keep": sorted(keep_lists)},
            )
            for list_id, entries in replace.items():
                await session.execute(
                    text("DELETE FROM network_feed_entries WHERE list = :list"), {"list": list_id}
                )
                rows = [_entry_row(list_id, e) for e in entries]
                for i in range(0, len(rows), INSERT_CHUNK):
                    await session.execute(insert(NetworkFeedEntryRow), rows[i : i + INSERT_CHUNK])
            await self._upsert(
                session,
                {
                    "serial": state.serial,
                    "generated_at": state.generated_at,
                    "valid_until": state.valid_until,
                    "key_id": state.key_id,
                    "index_sha256": state.index_sha256,
                    "files": state.files,
                    "last_fetch_at": state.last_fetch_at,
                    "last_ok_at": state.last_ok_at,
                    "error_code": None,
                },
            )

    async def recompute_seen_here(self, now: datetime) -> int:
        """True when the value is a source of a real session or a host we saw, in 30 days."""
        since = now - timedelta(days=SEEN_DAYS)
        sql = f"""
            WITH seen(v) AS (
                SELECT host(se.src_ip) FROM sessions se
                WHERE NOT se.benign AND se.started_at >= :since
                  AND {demo.not_demo("se", ":since", ":until")}
                UNION
                SELECT lower(i.host) FROM indicators i
                WHERE NOT i.demo AND i.host IS NOT NULL AND i.last_seen >= :since
                UNION
                SELECT lower(ft.host) FROM fetch_targets ft
                WHERE coalesce(ft.last_attempt_at, ft.first_seen) >= :since
                UNION
                SELECT lower(sl.value) FROM sample_links sl
                JOIN samples sm ON sm.sha256 = sl.sha256
                WHERE sl.kind IN ('c2_ip', 'c2_domain') AND sm.last_seen >= :since
            )
            UPDATE network_feed_entries e
            SET seen_here = (lower(e.value) IN (SELECT v FROM seen))
            WHERE e.seen_here IS DISTINCT FROM (lower(e.value) IN (SELECT v FROM seen))
        """  # noqa: S608  (constant fragments only)
        async with self.factory() as session, session.begin():
            result = await session.execute(
                text(sql), {"since": since, "until": now + timedelta(days=1)}
            )
            return int(getattr(result, "rowcount", 0) or 0)

    async def wipe(self) -> bool:
        """Delete the stored lists and everything about the last fetch, except the last accepted
        ``serial`` and its ``key_id``: rollback protection must survive turning the feed off and
        on again (security review L8). Answers whether anything was deleted."""
        async with self.factory() as session, session.begin():
            row = (
                await session.execute(
                    text(
                        "WITH a AS (DELETE FROM network_feed_entries RETURNING 1), "
                        "b AS (UPDATE network_feed_state SET generated_at = NULL, "
                        "valid_until = NULL, index_sha256 = NULL, files = '{}'::jsonb, "
                        "last_fetch_at = NULL, last_ok_at = NULL, error_code = NULL, "
                        "updated_at = now() "
                        "WHERE generated_at IS NOT NULL OR valid_until IS NOT NULL "
                        "OR index_sha256 IS NOT NULL OR files <> '{}'::jsonb "
                        "OR last_fetch_at IS NOT NULL OR last_ok_at IS NOT NULL "
                        "OR error_code IS NOT NULL RETURNING 1) "
                        "SELECT (SELECT count(*) FROM a) + (SELECT count(*) FROM b)"
                    )
                )
            ).scalar_one()
            return int(row) > 0


class FeedWorker(FeatureWorker):
    name = "network_feed"

    def __init__(
        self,
        features: FeatureSettings,
        feed: FeedSettings,
        store: FeedStore | None,
        *,
        gate: EgressGate | None = None,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        allow_documentation: bool = False,
    ) -> None:
        super().__init__(features, enabled=features.network_feed_enabled)
        self.feed = feed
        self.store = store
        self._gate = gate
        self._client = client
        self._clock = clock
        self._allow_doc = allow_documentation  # test overlay only, as in the batch builder
        self.interval_s = float(feed.interval_s)
        self.state = "off"
        self.reason: str | None = None

    async def status(self) -> dict[str, Any]:
        return {
            self.name: {
                "enabled": self.enabled,
                "configured": self.feed.configured,
                "state": self.state,
                "reason": self.reason,
                "cycles": self.cycles,
                "last_error": self.last_error,
            }
        }

    async def run(self, publish: Any = None) -> None:
        """Disabled in .env: nothing is fetched, and what an earlier run stored is wiped."""
        if self.enabled or self.store is None:
            await super().run(publish)
            return
        while True:
            try:
                if await self.store.wipe():
                    self.reason = "feed_disabled_wiped"
                    log.info("network feed is disabled: stored feed data deleted")
                self.state = "off"
                if publish is not None:
                    await publish(await self.status())
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("network feed wipe failed (%s)", type(exc).__name__)
            await asyncio.sleep(3600)

    async def run_once(self) -> None:
        store = self.store
        if store is None:
            self.state, self.reason = "off", None
            return
        now = self._clock()
        self.interval_s = float(self.feed.interval_s)
        try:
            if not self.feed.configured:
                raise FeedFailure("not_configured")
            await self._cycle(store, now)
            self.state, self.reason = "ok", None
        except FeedFailure as exc:
            await self._fail(store, exc.code, now)
        except EgressClosed:
            self.interval_s = RETRY_CLOSED_S
            await self._fail(store, "egress_closed", now)
        except FeedHttpError as exc:
            await self._fail(store, exc.code, now)
        except FeedTooLarge:
            await self._fail(store, "too_large", now)
        except FeedUnavailable:
            await self._fail(store, "unreachable", now)
        except FeedError as exc:
            await self._fail(store, library_code(exc), now)
        # Local data only: a failure here never invalidates the verified entries.
        try:
            await store.recompute_seen_here(now)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("network feed seen_here failed (%s)", type(exc).__name__)

    async def _fail(self, store: FeedStore, code: str, now: datetime) -> None:
        self.state, self.reason = "error", code
        await store.record_error(code, now)

    async def _cycle(self, store: FeedStore, now: datetime) -> None:
        public = minisign.parse_public_key(self.feed.key)
        client = FeedClient(self.feed, gate=self._gate, client=self._client)
        old = await store.state()
        wanted = list(self.feed.lists)
        have = old.files if old else {}
        complete = old is not None and all(f"{lid}.json" in have for lid in wanted)
        etag = (have.get(INDEX) or {}).get("etag") if complete and old else None

        resp = await client.get(INDEX, max_bytes=fm.MAX_INDEX_BYTES, etag=etag)
        if resp.status == 304 and old is not None:
            if old.valid_until is None or old.valid_until <= now:
                raise FeedFailure("feed_expired")
            await store.touch_ok(now)
            return

        sig = await client.get_text(f"{INDEX}.minisig")
        # The serial space belongs to the key: a new key (another hub) starts afresh, the same
        # key never goes back, even across a disable that wiped the lists.
        same_key = old is not None and old.key_id == public.key_id_hex
        index = fp.verify_index(
            resp.body, sig, public, now=now, last_serial=old.serial if old and same_key else None
        )

        new_files: dict[str, dict[str, Any]] = {
            INDEX: {"sha256": hashlib.sha256(resp.body).hexdigest(), "etag": resp.etag}
        }
        replace: dict[str, list[FeedEntry]] = {}
        for list_id in wanted:
            name = f"{list_id}.json"
            ref = index.find_file(name)
            if ref is None or not any(lst.id == list_id for lst in index.lists):
                raise FeedFailure("feed_invalid")
            prev = have.get(name) or {}
            if prev.get("sha256") == ref.sha256:
                new_files[name] = prev
                continue
            data = (await client.get(name, max_bytes=ref.bytes + 1)).body
            file_sig = await client.get_text(f"{name}.minisig")
            fp.verify_file_against_index(index, name, data, file_sig, public)
            parsed = fp.parse_list_json(
                data,
                expected_list=list_id,
                max_entries=fm.MAX_ENTRIES[list_id],
                allow_documentation=self._allow_doc,
            )
            replace[list_id] = list(parsed.feed.entries)
            new_files[name] = {"sha256": ref.sha256, "etag": None}

        state = FeedState(
            serial=index.serial,
            generated_at=fm.parse_ts(index.generated_at),
            valid_until=fm.parse_ts(index.valid_until),
            key_id=index.key_id,
            index_sha256=new_files[INDEX]["sha256"],
            files=new_files,
            last_fetch_at=now,
            last_ok_at=now,
        )
        await store.apply(state, replace, set(wanted))

"""The CVE watch job: once a day, mirror CISA KEV, recent NVD CVEs and GitHub advisories.

Each source is independent: a failure in one is recorded in ``cve_sync_state`` and retried after
an hour, the others still run. Calls spend a persisted daily quota (``enrichment_quota``) so a bug
or a restart loop can never hammer a public API. NVD and GitHub keys are optional; they only
raise the rate limits. Nothing is ever sent to these services except the query itself.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ingest.cve import sources
from ingest.cve.relevance import RelevanceMap, rank_score
from ingest.cve.sources import Batch, CveRecord, SourceError
from ingest.enrichment.config import EnrichmentSettings
from ingest.enrichment.reputation import reserve_quota

log = logging.getLogger(__name__)

SOURCES = ("kev", "nvd", "github")
RUN_EVERY = timedelta(hours=24)
RETRY_AFTER_ERROR = timedelta(hours=1)
CHECK_INTERVAL_S = 900.0
KEV_DAILY_QUOTA = 6  # one download per run; a few retries
FIRST_LOOKBACK = timedelta(days=30)
MAX_LOOKBACK = timedelta(days=30)
OVERLAP = timedelta(days=1)
RETENTION_DAYS = 180  # irrelevant, non-KEV CVEs older than this are pruned

_UNION = "ARRAY(SELECT DISTINCT unnest(cve.{c} || excluded.{c}) ORDER BY 1)"

_COLUMNS = (
    "cve_id, title, description, vendor, product, published_at, modified_at, cvss_score, "
    "cvss_severity, cwes, ghsa_ids, refs, cpes, in_kev, kev_added_at, kev_due_date, "
    "kev_ransomware, kev_action, sources"
)
_VALUES = (
    ":cve_id, :title, :description, :vendor, :product, :published_at, :modified_at, "
    ":cvss_score, :cvss_severity, :cwes, :ghsa_ids, :refs, :cpes, :in_kev, :kev_added_at, "
    ":kev_due_date, :kev_ransomware, :kev_action, ARRAY[:source]"
)

# Per source, which columns it is authoritative for. Elsewhere the first non-null value wins.
_UPSERTS: dict[str, str] = {
    "kev": f"""
        title = COALESCE(excluded.title, cve.title),
        description = COALESCE(cve.description, excluded.description),
        vendor = excluded.vendor, product = excluded.product,
        in_kev = true, kev_added_at = excluded.kev_added_at,
        kev_due_date = excluded.kev_due_date, kev_ransomware = excluded.kev_ransomware,
        kev_action = excluded.kev_action,
        cwes = {_UNION.format(c="cwes")}
    """,
    "nvd": f"""
        description = COALESCE(excluded.description, cve.description),
        published_at = COALESCE(excluded.published_at, cve.published_at),
        modified_at = COALESCE(excluded.modified_at, cve.modified_at),
        cvss_score = COALESCE(excluded.cvss_score, cve.cvss_score),
        cvss_severity = COALESCE(excluded.cvss_severity, cve.cvss_severity),
        cwes = {_UNION.format(c="cwes")}, refs = {_UNION.format(c="refs")},
        cpes = {_UNION.format(c="cpes")}
    """,
    "github": f"""
        title = COALESCE(cve.title, excluded.title),
        description = COALESCE(cve.description, excluded.description),
        published_at = COALESCE(cve.published_at, excluded.published_at),
        modified_at = COALESCE(cve.modified_at, excluded.modified_at),
        cvss_score = COALESCE(cve.cvss_score, excluded.cvss_score),
        cvss_severity = COALESCE(cve.cvss_severity, excluded.cvss_severity),
        cwes = {_UNION.format(c="cwes")}, ghsa_ids = {_UNION.format(c="ghsa_ids")},
        refs = {_UNION.format(c="refs")}
    """,
}


def upsert_sql(source: str) -> Any:
    return text(
        f"""
        INSERT INTO cve ({_COLUMNS}) VALUES ({_VALUES})
        ON CONFLICT (cve_id) DO UPDATE SET {_UPSERTS[source]},
            sources = ARRAY(SELECT DISTINCT unnest(cve.sources || excluded.sources) ORDER BY 1),
            updated_at = now()
        """  # noqa: S608 - fragments are the fixed constants above, values are bound
    )


def _params(rec: CveRecord, source: str) -> dict[str, Any]:
    return {**asdict(rec), "in_kev": source == "kev", "source": source}


class CveWatch:
    def __init__(
        self,
        factory: async_sessionmaker[AsyncSession],
        settings: EnrichmentSettings,
        client: httpx.AsyncClient | None = None,
        *,
        relevance: RelevanceMap | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.factory = factory
        self.s = settings
        self.client = client or httpx.AsyncClient(timeout=sources.HTTP_TIMEOUT)
        self._sleep = sleep
        self.relevance = relevance
        self._retry_at: dict[str, datetime] = {}
        self.last_error: dict[str, str] = {}
        self.test_result: dict[str, dict[str, Any]] = {}

    def apply_settings(self, settings: EnrichmentSettings, changed: set[str]) -> None:
        """Hot-swap the optional keys. A changed key clears backoff and the last error."""
        self.s = settings
        for provider in changed & {"nvd", "github"}:
            self._retry_at.pop(provider, None)
            self.last_error.pop(provider, None)
            self.test_result.pop(provider, None)

    # ---- quota ----------------------------------------------------------------------------
    def _reserve(self, source: str) -> Callable[[], Awaitable[bool]]:
        limit = {
            "kev": KEV_DAILY_QUOTA,
            "nvd": self.s.cve_nvd_daily_quota,
            "github": self.s.cve_github_daily_quota,
        }[source]

        async def reserve() -> bool:
            if limit <= 0:  # reserve_quota would let the first call of the day through
                return False
            return await reserve_quota(self.factory, f"cve_{source}", limit)

        return reserve

    # ---- state ----------------------------------------------------------------------------
    async def _last_success(self, source: str) -> datetime | None:
        async with self.factory() as session:
            row = await session.execute(
                text("SELECT last_success_at FROM cve_sync_state WHERE source = :s"),
                {"s": source},
            )
            first = row.first()
            return first[0] if first else None

    async def _record_run(self, source: str, *, ok: bool, items: int, error: str | None) -> None:
        async with self.factory() as session, session.begin():
            await session.execute(
                text(
                    """
                    INSERT INTO cve_sync_state
                        (source, last_run_at, last_success_at, last_error, items_last_run)
                    VALUES (:s, now(), CASE WHEN :ok THEN now() END, :e, :n)
                    ON CONFLICT (source) DO UPDATE SET
                        last_run_at = now(),
                        last_success_at = CASE WHEN :ok THEN now()
                                               ELSE cve_sync_state.last_success_at END,
                        last_error = :e,
                        items_last_run = CASE WHEN :ok THEN :n
                                              ELSE cve_sync_state.items_last_run END
                    """
                ),
                {"s": source, "ok": ok, "e": error, "n": items},
            )

    async def store(self, source: str, batch: Batch) -> int:
        """Upsert the records of one source (in chunks, one transaction per chunk)."""
        stmt = upsert_sql(source)
        rows = [_params(r, source) for r in batch.records]
        for i in range(0, len(rows), 200):
            async with self.factory() as session, session.begin():
                await session.execute(stmt, rows[i : i + 200])
        return len(rows)

    # ---- relevance and retention --------------------------------------------------------------
    async def recompute(self) -> int:
        """Apply the relevance mapping to every row. Returns the number of rows changed."""
        if self.relevance is None:
            return 0
        async with self.factory() as session:
            res = await session.execute(
                text(
                    "SELECT cve_id, vendor, product, title, description, cpes, in_kev, cvss_score, "
                    "relevance, matched_services, tags, rank_score FROM cve"
                )
            )
            rows = res.all()
        updates: list[dict[str, Any]] = []
        for r in rows:
            a = self.relevance.assess(
                cve_id=r.cve_id,
                vendor=r.vendor,
                product=r.product,
                title=r.title,
                description=r.description,
                cpes=r.cpes,
            )
            score = float(r.cvss_score) if r.cvss_score is not None else None
            new = {
                "id": r.cve_id,
                "rel": a.relevance,
                "svc": a.services,
                "tags": a.tags,
                "rank": rank_score(a.relevance, r.in_kev, score),
            }
            if (r.relevance, list(r.matched_services), list(r.tags), r.rank_score) != (
                new["rel"], new["svc"], new["tags"], new["rank"]
            ):  # fmt: skip
                updates.append(new)
        stmt = text(
            """
            UPDATE cve SET relevance = :rel, matched_services = :svc, tags = :tags,
                rank_score = :rank
            WHERE cve_id = :id
            """
        )
        for i in range(0, len(updates), 500):
            async with self.factory() as session, session.begin():
                await session.execute(stmt, updates[i : i + 500])
        return len(updates)

    async def prune(self) -> int:
        """Retention: drop CVEs that are neither in KEV nor relevant after RETENTION_DAYS."""
        async with self.factory() as session, session.begin():
            res = await session.execute(
                text(
                    """
                    DELETE FROM cve
                    WHERE NOT in_kev AND relevance = 'none'
                      AND COALESCE(published_at, first_seen_at)
                          < now() - make_interval(days => :d)
                    """
                ),
                {"d": RETENTION_DAYS},
            )
            return int(res.rowcount or 0)  # type: ignore[attr-defined]

    async def maintenance(self) -> None:
        changed = await self.recompute()
        pruned = await self.prune()
        if changed or pruned:
            log.info("cve relevance updated for %d rows, %d pruned", changed, pruned)

    # ---- one source -----------------------------------------------------------------------
    async def _fetch(self, source: str, since: datetime | None) -> Batch:
        now = datetime.now(UTC)
        floor = now - MAX_LOOKBACK
        start = max(since - OVERLAP, floor) if since else now - FIRST_LOOKBACK
        if source == "kev":
            if not await self._reserve("kev")():
                raise SourceError("quota_exhausted")
            return await sources.fetch_kev(self.client)
        if source == "nvd":
            return await sources.fetch_nvd(
                self.client,
                since=start,
                until=now,
                api_key=self.s.nvd_api_key,
                reserve=self._reserve("nvd"),
                sleep=self._sleep,
            )
        return await sources.fetch_github(
            self.client,
            since=start.date(),
            token=self.s.github_token,
            reserve=self._reserve("github"),
        )

    async def sync_source(self, source: str) -> int:
        """Fetch and store one source. Returns the number of CVEs written; never raises."""
        since = await self._last_success(source)
        try:
            batch = await self._fetch(source, since)
            count = await self.store(source, batch)
        except SourceError as exc:
            self._failed(source, exc.kind)
            await self._record_run(source, ok=False, items=0, error=exc.kind)
            return 0
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # database trouble: log the type only
            self._failed(source, "error")
            log.warning("cve %s store failed (%s)", source, type(exc).__name__)
            return 0
        self.last_error.pop(source, None)
        self._retry_at.pop(source, None)
        await self._record_run(source, ok=True, items=count, error=None)
        log.info("cve %s: %d stored, %d skipped as invalid", source, count, batch.skipped)
        return count

    def _failed(self, source: str, kind: str) -> None:
        self.last_error[source] = kind
        self._retry_at[source] = datetime.now(UTC) + RETRY_AFTER_ERROR
        log.warning("cve %s sync failed: %s", source, kind)

    async def run_once(self) -> int:
        """Sync every source that is due. Returns how many CVEs were written."""
        total = 0
        now = datetime.now(UTC)
        for source in SOURCES:
            if self._retry_at.get(source, now) > now:
                continue
            last = await self._last_success(source)
            if last is not None and now - last < RUN_EVERY:
                continue
            total += await self.sync_source(source)
        if total:
            await self.maintenance()
        return total

    # ---- "Test key" -----------------------------------------------------------------------
    async def run_key_test(self, provider: str) -> dict[str, Any]:
        """One tiny quota-counted request with the key. Never raises, never stores CVEs."""
        error: str | None = None
        key = self.s.nvd_api_key if provider == "nvd" else self.s.github_token
        if not key:
            error = "no_key"
        elif not await self._reserve(provider)():
            error = "quota_exhausted"
        else:
            try:
                if provider == "nvd":
                    await sources.fetch_json(
                        self.client,
                        sources.NVD_URL,
                        max_bytes=sources.NVD_MAX_BYTES,
                        params={"resultsPerPage": "1"},
                        headers={"apiKey": key},
                    )
                else:
                    await sources.fetch_json(
                        self.client,
                        sources.GITHUB_URL,
                        max_bytes=sources.GITHUB_MAX_BYTES,
                        params={"per_page": "1", "type": "reviewed"},
                        headers={
                            "Accept": "application/vnd.github+json",
                            "Authorization": f"Bearer {key}",
                        },
                    )
                self.last_error.pop(provider, None)
                self._retry_at.pop(provider, None)
            except SourceError as exc:
                error = exc.kind
        result = {
            "ok": error is None,
            "error": error,
            "checked_at": datetime.now(UTC).isoformat(),
        }
        self.test_result[provider] = result
        return result

    # ---- status for the API (no secrets) ----------------------------------------------------
    async def status(self) -> dict[str, dict[str, Any]]:
        async with self.factory() as session:
            rows = await session.execute(
                text(
                    "SELECT source, last_run_at, last_success_at, last_error, items_last_run "
                    "FROM cve_sync_state"
                )
            )
            states = {r.source: r for r in rows}
        out: dict[str, dict[str, Any]] = {}
        for source in SOURCES:
            st = states.get(source)
            out[source] = {
                "enabled": self.s.cve_watch_enabled,
                "last_run_at": st.last_run_at.isoformat() if st and st.last_run_at else None,
                "last_success_at": (
                    st.last_success_at.isoformat() if st and st.last_success_at else None
                ),
                "items_last_run": st.items_last_run if st else 0,
                "last_error": self.last_error.get(source) or (st.last_error if st else None),
            }
        out["nvd"]["configured"] = bool(self.s.nvd_api_key)
        out["nvd"]["daily_quota"] = self.s.cve_nvd_daily_quota
        out["nvd"]["test"] = self.test_result.get("nvd")
        out["github"]["configured"] = bool(self.s.github_token)
        out["github"]["daily_quota"] = self.s.cve_github_daily_quota
        out["github"]["test"] = self.test_result.get("github")
        return out

    async def run(self, publish: Callable[[dict[str, dict[str, Any]]], Awaitable[None]]) -> None:
        if not self.s.cve_watch_enabled:
            log.info("CVE watch is disabled (CVE_WATCH_ENABLED=false)")
        first = True
        while True:
            try:
                if first:  # a new relevance mapping applies at once, without waiting for a sync
                    first = False
                    await self.maintenance()
                if self.s.cve_watch_enabled:
                    await self.run_once()
                await publish(await self.status())
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("cve watch cycle failed (%s)", type(exc).__name__)
            await asyncio.sleep(CHECK_INTERVAL_S)

    async def aclose(self) -> None:
        await self.client.aclose()

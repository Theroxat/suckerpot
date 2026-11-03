"""Verifier role: fetch links for the network and report what came back (design M32 8.3, N18).

Only with ``NETWORK_VERIFIER=true`` AND the VPN egress mode AND the collector enabled. This worker
never opens a connection to a task URL. It checks each leased task locally, then queues the URL
as a ``fetch_targets`` row with ``origin='network_verify'`` and depth 0; the collector (VPN only,
every M21 guard, never recursive) fetches it. Once the collector finished, or after 5 hours, the
result goes back to the hub.

Task states in ``network_verify_tasks``:
``received`` (leased, not yet decided), ``queued`` (fetch target made), ``done`` (outcome known,
not reported), ``refused`` / ``skipped`` (decided locally, not reported), ``reported``.

Statuses: ``off``, ``verifier_needs_vpn``, ``verifier_needs_collector``, ``egress_closed``,
``self_terms_unavailable``, ``not_verifier`` (role not granted, retried daily), ``hub_no_verify``
(pre-M32 hub, retried daily), ``ok``.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from urllib.parse import urlsplit

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db.blocklist_values import is_never_host
from suckerpot_netproto import models as wire
from suckerpot_netproto.enums import FAMILIES_V1

from ingest.egress import EgressGate, gate_open

from .builder import TermsSource, file_type_of, mentions_self
from .client import HubClient, HubError, HubNoVerify
from .config import NetworkSettings

log = logging.getLogger(__name__)

ORIGIN = "network_verify"
LEASE_MAX = wire.MAX_VERIFY_TASKS
OUTSTANDING_MAX = 20  # leased but unreported tasks held at once
# A reused fetch target only vouches for a task when its last attempt falls inside the hub's
# lease window (6 hours): an older result says nothing about the file as it is now.
FETCH_FRESH = timedelta(hours=6)
RESULT_TIMEOUT = timedelta(hours=5)  # the hub's lease is 6 hours: report before it ends
RETRY_AFTER = timedelta(hours=24)
MAX_URL = 2048

OFF = "off"
NEEDS_VPN = "verifier_needs_vpn"
NEEDS_COLLECTOR = "verifier_needs_collector"
EGRESS_CLOSED = "egress_closed"
TERMS_UNAVAILABLE = "self_terms_unavailable"
NOT_VERIFIER = "not_verifier"
NO_VERIFY = "hub_no_verify"
OK = "ok"

OPEN_STATES = ("received", "queued", "done", "refused", "skipped")
LOCAL_DECISIONS = ("refused", "skipped")


class StaleFetch(Exception):
    """The reusable fetch target holds only an old result: never attest from it."""


@dataclass(slots=True)
class TaskRow:
    hub_id: str
    url: str
    host: str
    state: str
    received_at: datetime
    lease_until: datetime
    fetch_target_id: int | None = None
    outcome: str | None = None
    sha256: str | None = None
    size: int | None = None
    file_type: str | None = None
    family: str | None = None
    reported_at: datetime | None = None


@dataclass(slots=True)
class FetchView:
    """What the collector (and analyzer) recorded for one fetch target."""

    status: str
    last_error: str | None = None
    sha256: str | None = None
    size: int | None = None
    kind: str | None = None
    arch: str | None = None
    family: str | None = None
    analysis_status: str | None = None


@dataclass(frozen=True, slots=True)
class Outcome:
    outcome: str
    sha256: str | None = None
    size: int | None = None
    file_type: str | None = None
    family: str | None = None


class VerifyStore(Protocol):
    async def open_tasks(self) -> list[TaskRow]: ...
    async def has_task(self, hub_id: str) -> bool: ...
    async def add_task(self, row: TaskRow) -> None: ...
    async def update_task(self, hub_id: str, **values: Any) -> None: ...
    async def queue_fetch(self, url: str, host: str, scheme: str, now: datetime) -> int | None: ...
    async def fetch_view(self, target_id: int) -> FetchView | None: ...
    async def count_since(self, since: datetime, host: str | None = None) -> int: ...
    async def counts(self) -> dict[str, int]: ...


TASK_COLUMNS = (
    "hub_id", "url", "host", "state", "fetch_target_id", "outcome", "sha256", "size",
    "file_type", "family", "received_at", "lease_until", "reported_at",
)  # fmt: skip
_UPDATABLE = frozenset(TASK_COLUMNS) - {"hub_id", "url", "host", "received_at"}


class SqlVerifyStore:
    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self.factory = factory

    async def open_tasks(self) -> list[TaskRow]:
        cols = ", ".join(TASK_COLUMNS)
        async with self.factory() as session:
            rows = await session.execute(
                text(
                    f"SELECT {cols} FROM network_verify_tasks "  # noqa: S608
                    "WHERE reported_at IS NULL AND state = ANY(:s) ORDER BY received_at LIMIT 500"
                ),
                {"s": list(OPEN_STATES)},
            )
            return [TaskRow(**r._asdict()) for r in rows]

    async def has_task(self, hub_id: str) -> bool:
        async with self.factory() as session:
            row = await session.execute(
                text("SELECT 1 FROM network_verify_tasks WHERE hub_id = :i"), {"i": hub_id}
            )
            return row.first() is not None

    async def add_task(self, row: TaskRow) -> None:
        cols = ", ".join(TASK_COLUMNS)
        marks = ", ".join(f":{c}" for c in TASK_COLUMNS)
        values = {c: getattr(row, c) for c in TASK_COLUMNS}
        async with self.factory() as session, session.begin():
            await session.execute(
                text(
                    f"INSERT INTO network_verify_tasks ({cols}) VALUES ({marks}) "  # noqa: S608
                    "ON CONFLICT (hub_id) DO NOTHING"
                ),
                values,
            )

    async def update_task(self, hub_id: str, **values: Any) -> None:
        if not values:
            return
        if set(values) - _UPDATABLE:
            raise ValueError("unknown task column")
        sets = ", ".join(f"{k} = :{k}" for k in values)
        async with self.factory() as session, session.begin():
            await session.execute(
                text(f"UPDATE network_verify_tasks SET {sets} WHERE hub_id = :hub_id"),  # noqa: S608
                {**values, "hub_id": hub_id},
            )

    async def queue_fetch(self, url: str, host: str, scheme: str, now: datetime) -> int | None:
        """Insert the verification target (depth 0), reusing an existing row for the same URL.

        Raises ``StaleFetch`` when the existing row holds a result older than ``FETCH_FRESH``.
        """
        async with self.factory() as session, session.begin():
            await session.execute(
                text(
                    """
                    INSERT INTO fetch_targets
                        (url, scheme, host, depth, status, first_seen, next_attempt_at, origin)
                    VALUES (:url, :scheme, :host, 0, 'pending', :now, :now, 'network_verify')
                    ON CONFLICT (url) DO NOTHING
                    """
                ),
                {"url": url, "scheme": scheme, "host": host, "now": now},
            )
            row = (
                await session.execute(
                    text("SELECT id, status, last_attempt_at FROM fetch_targets WHERE url = :url"),
                    {"url": url},
                )
            ).first()
        if row is None:
            return None
        if row.status != "pending" and (
            row.last_attempt_at is None or row.last_attempt_at < now - FETCH_FRESH
        ):
            raise StaleFetch
        return int(row.id)

    async def fetch_view(self, target_id: int) -> FetchView | None:
        async with self.factory() as session:
            row = (
                await session.execute(
                    text(
                        """
                        SELECT ft.status, ft.last_error, ft.last_sha256 AS sha256,
                               sm.size, sm.kind, sm.arch, sm.family, sm.analysis_status
                        FROM fetch_targets ft LEFT JOIN samples sm ON sm.sha256 = ft.last_sha256
                        WHERE ft.id = :i
                        """
                    ),
                    {"i": target_id},
                )
            ).first()
        return None if row is None else FetchView(**row._asdict())

    async def count_since(self, since: datetime, host: str | None = None) -> int:
        sql = (
            "SELECT count(*) FROM network_verify_tasks "
            "WHERE received_at >= :since AND state IN ('queued', 'done', 'reported')"
        )
        params: dict[str, Any] = {"since": since}
        if host is not None:
            sql += " AND host = :host"
            params["host"] = host
        async with self.factory() as session:
            return int((await session.execute(text(sql), params)).scalar_one())

    async def counts(self) -> dict[str, int]:
        async with self.factory() as session:
            rows = await session.execute(
                text("SELECT state, count(*) AS n FROM network_verify_tasks GROUP BY state")
            )
            return {r.state: int(r.n) for r in rows}


def outcome_of(view: FetchView | None, now: datetime, received_at: datetime) -> Outcome | None:
    """The result to report for a fetch target, or ``None`` while the collector is still at it."""
    if view is None:
        return None
    waited = now - received_at
    if view.status == "fetched" and view.sha256:
        size = view.size or 0
        if size > wire.MAX_VERIFY_FILE_SIZE:
            return Outcome("too_large")
        if size < 1:
            return Outcome("http_error")
        if view.kind is None and view.analysis_status == "pending" and waited < RESULT_TIMEOUT:
            return None  # the analyzer has not typed the file yet
        family = view.family if view.family in FAMILIES_V1 else None
        return Outcome(
            "fetched",
            sha256=view.sha256,
            size=size,
            file_type=file_type_of(view.kind, view.arch) or "other",
            family=family,
        )
    if view.status == "gone":
        return Outcome("http_error")
    if view.status == "too_large":
        return Outcome("too_large")
    if view.status in ("refused", "unsupported"):
        return Outcome("refused")
    if view.status == "failed":
        return Outcome("timeout" if view.last_error == "timeout" else "unreachable")
    return None  # pending (including a full quarantine, which the collector retries)


def local_refusal(url: str, terms: Any) -> str | None:
    """A reason code when this node must not fetch the task URL at all, else ``None``."""
    if not url or len(url) > MAX_URL:
        return "length"
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        _ = parts.port
    except ValueError:
        return "url"
    if parts.scheme not in ("http", "https") or not host:
        return "scheme"
    if parts.username is not None or parts.password is not None:
        return "credentials"
    if is_never_host(host):
        return "never_list"
    if terms is not None and mentions_self(url, terms):
        return "self"
    return None


class Verifier:
    def __init__(
        self,
        settings: NetworkSettings,
        store: VerifyStore,
        terms: TermsSource | None,
        *,
        gate: EgressGate | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.settings = settings
        self.store = store
        self.terms = terms
        self._gate = gate
        self._clock = clock
        self.state = OFF
        self._retry_at: datetime | None = None

    def precondition(self) -> str | None:
        """The status that stops the role before any hub call, or ``None`` when it may run."""
        if not self.settings.verifier:
            return OFF
        if self.settings.egress_mode != "vpn":
            return NEEDS_VPN
        if not self.settings.collector_enabled:
            return NEEDS_COLLECTOR
        if not gate_open(self._gate):  # no host: false in direct mode, false while closed
            return EGRESS_CLOSED
        return None

    async def cycle(self, hub: HubClient) -> str:
        now = self._clock()
        blocked = self.precondition()
        if blocked is not None:
            self.state = blocked
            return blocked
        if self._retry_at is not None and now < self._retry_at:
            return self.state
        self._retry_at = None
        self.state = OK
        try:
            await self._advance(now)
            await self._report(hub, now)
            await self._lease(hub, now)
        except HubNoVerify:
            self._retry_at, self.state = now + RETRY_AFTER, NO_VERIFY
            return self.state
        except HubError as exc:
            if exc.code != "not_verifier":
                raise
            self._retry_at, self.state = now + RETRY_AFTER, NOT_VERIFIER
            return self.state
        return self.state

    # -- collector results -------------------------------------------------------------------

    async def _advance(self, now: datetime) -> None:
        for task in await self.store.open_tasks():
            if task.state != "queued":
                continue
            found: Outcome | None = None
            if task.fetch_target_id is not None:
                found = outcome_of(
                    await self.store.fetch_view(task.fetch_target_id), now, task.received_at
                )
            if found is None and now - task.received_at >= RESULT_TIMEOUT:
                found = Outcome("timeout")
            if found is None:
                continue
            await self.store.update_task(
                task.hub_id, state="done", outcome=found.outcome, sha256=found.sha256,
                size=found.size, file_type=found.file_type, family=found.family,
            )  # fmt: skip

    async def _report(self, hub: HubClient, now: datetime) -> None:
        ready: list[TaskRow] = []
        for task in await self.store.open_tasks():
            if task.state not in ("done", *LOCAL_DECISIONS):
                continue
            if task.lease_until <= now:
                # The hub no longer accepts this answer. Keep the row only until it is pruned.
                await self.store.update_task(task.hub_id, state="skipped", reported_at=now)
                continue
            ready.append(task)
        for start in range(0, len(ready), wire.MAX_VERIFY_RESULTS):
            chunk = ready[start : start + wire.MAX_VERIFY_RESULTS]
            items: list[dict[str, Any]] = []
            for t in chunk:
                try:
                    items.append(result_item(t))
                except ValueError:  # a malformed row is never sent as it is
                    await self.store.update_task(t.hub_id, outcome="skipped")
                    t.outcome = "skipped"
                    items.append(result_item(t))
            await hub.verify_results(items)
            for task in chunk:
                await self.store.update_task(task.hub_id, state="reported", reported_at=now)

    # -- leases ------------------------------------------------------------------------------

    async def _lease(self, hub: HubClient, now: datetime) -> None:
        day_start = now.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
        budget = self.settings.verify_daily_cap - await self.store.count_since(day_start)
        outstanding = len(await self.store.open_tasks())
        room = min(LEASE_MAX, budget, OUTSTANDING_MAX - outstanding)
        if room <= 0:
            return
        terms = await self.terms.get() if self.terms is not None else None
        if terms is None:
            self.state = TERMS_UNAVAILABLE
            return
        leased = await hub.verify_tasks(room)
        for task in leased.tasks[:room]:
            if await self.store.has_task(task.id):
                continue
            await self._take(task, terms, now, day_start)

    async def _take(self, task: wire.VerifyTask, terms: Any, now: datetime, day: datetime) -> None:
        lease_until = datetime.strptime(task.lease_until, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        host = (urlsplit(task.url).hostname or "")[:255].lower()
        row = TaskRow(
            hub_id=task.id, url=task.url, host=host, state="received", received_at=now,
            lease_until=lease_until,
        )  # fmt: skip
        if (reason := local_refusal(task.url, terms)) is not None:
            log.info("verification task refused locally (%s)", reason)
            row.state, row.outcome = "refused", "refused"
        elif (
            await self.store.count_since(day) >= self.settings.verify_daily_cap
            or await self.store.count_since(day, host) >= self.settings.verify_host_daily_cap
        ):
            row.state, row.outcome = "skipped", "skipped"
        await self.store.add_task(row)
        if row.state != "received":
            return
        scheme = urlsplit(task.url).scheme
        try:
            target_id = await self.store.queue_fetch(task.url, host, scheme, now)
        except StaleFetch:
            await self.store.update_task(task.id, state="done", outcome="skipped")
            return
        if target_id is None:
            await self.store.update_task(task.id, state="done", outcome="unreachable")
            return
        await self.store.update_task(task.id, state="queued", fetch_target_id=target_id)


def result_item(task: TaskRow) -> dict[str, Any]:
    """The wire item for a decided task, validated by the netproto model before it is sent."""
    outcome = task.outcome or "skipped"
    item: dict[str, Any] = {"id": task.hub_id, "outcome": outcome}
    if outcome == "fetched":
        item.update(sha256=task.sha256, size=task.size, file_type=task.file_type)
        if task.family:
            item["family"] = task.family
    wire.VerifyResult.model_validate(item)
    return item

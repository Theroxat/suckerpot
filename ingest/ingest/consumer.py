"""Redis Streams consumer loop (one consumer group, one stream per sensor).

Redis commands used (ACL user ``ingest``): XGROUP CREATE, XREADGROUP, XACK, XAUTOCLAIM,
XTRIM (plus AUTH/HELLO performed implicitly by the client on connect).

Every stream (``events:ssh``, ``events:telnet``, ...) has its own group state: ACK, reclaim and
trim are per stream. Single-consumer assumption: after each committed and acknowledged batch
the stream is trimmed with ``XTRIM MINID ~ <last acked id>``, but only once that stream's
pending list has been drained, so entries that were never read cannot be trimmed away. Run
exactly one ingest instance.

Defences against a misbehaving producer: an event whose ``sensor`` differs from the stream
suffix is dropped (counted); entry ids far in the future are reported and never used as a
trim target (an explicit future id would otherwise make MINID trimming wipe the stream).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Sequence
from typing import Any

from redis.asyncio import Redis
from redis.exceptions import RedisError, ResponseError
from sqlalchemy.exc import DBAPIError, SQLAlchemyError, StatementError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_common import Event

from ingest.config import Settings
from ingest.diskguard import DiskGuard
from ingest.enrichment.enricher import Enricher
from ingest.writer import write_batch

log = logging.getLogger(__name__)

PREVIEW_CHARS = 200
MAX_ATTEMPTS = 5
FUTURE_ID_SLACK_MS = 24 * 3600 * 1000
WARN_INTERVAL_S = 60.0

Message = tuple[bytes | str, dict[Any, Any]]
Parsed = tuple[list[tuple[bytes | str, Event]], list[Any], int]


def preview(fields: dict[Any, Any] | None) -> str:
    text = repr(fields)
    return text if len(text) <= PREVIEW_CHARS else text[:PREVIEW_CHARS] + "...<truncated>"


def stream_sensor(stream: str) -> str | None:
    """Sensor name implied by a stream name (``events:ssh`` gives ``ssh``), if any."""
    return stream.rsplit(":", 1)[1] if ":" in stream else None


def parse_messages(messages: Sequence[Message], expected_sensor: str | None = None) -> Parsed:
    """Validate messages.

    Returns (valid (id, event) pairs, ids to drop, number dropped for a sensor mismatch).
    """
    good: list[tuple[bytes | str, Event]] = []
    bad: list[Any] = []
    mismatched = 0
    for msg_id, fields in messages:
        try:
            ev = Event.from_stream_fields(fields)
        except Exception:
            log.warning("invalid message %r skipped: %s", msg_id, preview(fields))
            bad.append(msg_id)
            continue
        if expected_sensor is not None and str(ev.sensor) != expected_sensor:
            mismatched += 1
            bad.append(msg_id)
            continue
        good.append((msg_id, ev))
    return good, bad, mismatched


class Consumer:
    def __init__(
        self,
        settings: Settings,
        redis: Redis,
        factory: async_sessionmaker[AsyncSession],
        enricher: Enricher | None = None,
        guard: DiskGuard | None = None,
    ) -> None:
        self.enricher = enricher
        self.guard = guard
        self.s = settings
        self.redis = redis
        self.factory = factory
        self.stop = asyncio.Event()
        self.attempts: dict[tuple[str, Any], int] = {}
        # Streams whose pending list is not yet fully drained: trimming them is unsafe.
        self.draining: set[str] = set()
        self.sensor_mismatches = 0
        self._last_warn: dict[str, float] = {}

    def heartbeat(self) -> None:
        try:
            self.s.heartbeat_path.touch()
        except OSError:
            log.exception("cannot touch heartbeat file")

    def _warn(self, key: str, msg: str, *args: Any) -> None:
        """Rate-limited warning (one per key and minute)."""
        now = time.monotonic()
        if now - self._last_warn.get(key, -WARN_INTERVAL_S) >= WARN_INTERVAL_S:
            self._last_warn[key] = now
            log.warning(msg, *args)

    async def ensure_groups(self) -> None:
        for stream in self.s.streams:
            try:
                await self.redis.xgroup_create(stream, self.s.group, id="0", mkstream=True)
                log.info("created consumer group %s on %s", self.s.group, stream)
            except ResponseError as exc:
                if "BUSYGROUP" not in str(exc):
                    raise

    async def reclaim_stale(self, stream: str, min_idle_ms: int | None = None) -> int:
        """Take over entries pending for any consumer on ``stream`` (XAUTOCLAIM)."""
        idle = self.s.claim_idle_ms if min_idle_ms is None else min_idle_ms
        start: bytes | str = "0-0"
        claimed = 0
        while not self.stop.is_set():
            res = await self.redis.xautoclaim(
                stream,
                self.s.group,
                self.s.consumer,
                min_idle_time=idle,
                start_id=start,
                count=self.s.batch_size,
            )
            start, messages = res[0], res[1]
            claimed += len(messages)
            if start in (b"0-0", "0-0"):
                break
        if claimed:
            log.info("reclaimed %d pending entries on %s", claimed, stream)
        return claimed

    def _check_future_ids(self, stream: str, ids: Sequence[Any]) -> None:
        limit = int(time.time() * 1000) + FUTURE_ID_SLACK_MS
        if any(_id_key(i)[0] > limit for i in ids):
            self._warn("future-id:" + stream, "entry id far in the future on %s", stream)

    async def process(self, stream: str, messages: Sequence[Message]) -> None:
        """Validate, write, ack and trim one batch of ``stream``. Raises on write failure."""
        self._check_future_ids(stream, [m[0] for m in messages])
        live: list[Message] = []
        dead: list[Any] = []
        for msg in messages:
            n = self.attempts.get((stream, msg[0]), 0)
            if n >= MAX_ATTEMPTS:
                log.error("dead-lettering %r on %s after %d failed attempts", msg[0], stream, n)
                dead.append(msg[0])
            else:
                live.append(msg)
        await self._ack(stream, dead)
        for mid in dead:
            self.attempts.pop((stream, mid), None)
        acked: list[Any] = list(dead)
        try:
            if live:
                acked += await self._process_live(stream, live)
        except Exception as exc:
            if _counts_as_attempt(exc):
                for mid, _ in live:
                    key = (stream, mid)
                    self.attempts[key] = self.attempts.get(key, 0) + 1
            raise
        for mid, _ in live:
            self.attempts.pop((stream, mid), None)
        await self._trim(stream, acked)

    async def _process_live(self, stream: str, messages: Sequence[Message]) -> list[Any]:
        """Returns the ids acknowledged."""
        good, bad, mismatched = parse_messages(messages, stream_sensor(stream))
        if mismatched:
            self.sensor_mismatches += mismatched
            self._warn(
                "mismatch:" + stream,
                "dropped %d event(s) on %s whose sensor differs from the stream (total %d)",
                mismatched,
                stream,
                self.sensor_mismatches,
            )
        done: list[Any] = []
        if good:
            try:
                await self._write([ev for _, ev in good])
            except StatementError as exc:
                if not _is_data_error(exc):
                    raise
                if len(good) == 1:
                    log.error("dropping event rejected by database: %s", _err_name(exc))
                    bad.append(good[0][0])
                else:
                    bad += await self._write_individually(stream, good, done)
            else:
                done = [i for i, _ in good]
                await self._ack(stream, done)
        await self._ack(stream, bad)
        return done + bad

    async def _write_individually(
        self, stream: str, good: list[tuple[bytes | str, Event]], done: list[Any]
    ) -> list[Any]:
        """Write events one by one. Returns ids dropped as bad data (caller ACKs them)."""
        dropped: list[Any] = []
        for msg_id, ev in good:
            try:
                await self._write([ev])
            except StatementError as exc:
                if not _is_data_error(exc):
                    raise
                log.error("dropping event rejected by database: %s", _err_name(exc))
                dropped.append(msg_id)
            else:
                await self._ack(stream, [msg_id])
                done.append(msg_id)
        return dropped

    async def _write(self, events: list[Event]) -> None:
        if self.enricher is None and self.guard is None:
            await write_batch(self.factory, events)
        else:
            await write_batch(self.factory, events, self.enricher, self.guard)

    async def _trim(self, stream: str, ids: Sequence[Any]) -> None:
        if stream in self.draining:
            return
        limit = int(time.time() * 1000) + FUTURE_ID_SLACK_MS
        usable = [i for i in ids if _id_key(i)[0] <= limit]  # never trim to a forged future id
        if not usable:
            return
        last = max(usable, key=_id_key)
        last_s = last.decode() if isinstance(last, bytes) else str(last)
        try:
            await self.redis.xtrim(stream, minid=last_s, approximate=True)
        except RedisError as exc:
            log.warning("XTRIM failed on %s (%s)", stream, type(exc).__name__)

    async def _ack(self, stream: str, ids: Sequence[Any]) -> None:
        if ids:
            await self.redis.xack(stream, self.s.group, *ids)

    async def _read(self) -> list[tuple[str, list[Message]]]:
        """One XREADGROUP over all streams (draining ones are read from "0", not blocking)."""
        draining = [st for st in self.s.streams if st in self.draining]
        ids: dict[Any, Any]
        if draining:
            ids = dict.fromkeys(draining, "0")
        else:
            ids = dict.fromkeys(self.s.streams, ">")
        res = await self.redis.xreadgroup(
            self.s.group,
            self.s.consumer,
            ids,
            count=self.s.batch_size,
            block=None if draining else self.s.block_ms,
        )
        out: list[tuple[str, list[Message]]] = []
        for name, msgs in res or []:
            if msgs:
                key = name.decode() if isinstance(name, bytes) else str(name)
                out.append((key, list(msgs)))
        if draining:
            returned = {k for k, _ in out}
            self.draining -= {st for st in draining if st not in returned}
        return out

    async def run(self) -> None:
        await self.ensure_groups()
        # Single consumer: everything pending, whoever it was delivered to, is ours now.
        for stream in self.s.streams:
            await self.reclaim_stale(stream, min_idle_ms=0)
        self.heartbeat()
        self.draining = set(self.s.streams)
        last_reclaim = time.monotonic()
        backoff = 1.0
        while not self.stop.is_set():
            try:
                if (
                    not self.draining
                    and time.monotonic() - last_reclaim >= self.s.reclaim_interval_s
                ):
                    last_reclaim = time.monotonic()
                    for stream in self.s.streams:
                        if await self.reclaim_stale(stream) > 0:
                            self.draining.add(stream)
                for stream, messages in await self._read():
                    await self.process(stream, messages)
                # Heartbeat only after a successful read (and commit, when there was data).
                self.heartbeat()
                backoff = 1.0
            except (RedisError, SQLAlchemyError, OSError) as exc:
                log.error("batch failed (%s), retrying in %.0fs", type(exc).__name__, backoff)
                self.draining = set(self.s.streams)  # unacked entries stay pending: re-read
                await self._sleep(backoff)
                backoff = min(backoff * 2, 30.0)
        log.info("consumer stopped")

    async def _sleep(self, seconds: float) -> None:
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self.stop.wait(), timeout=seconds)


def _id_key(msg_id: Any) -> tuple[int, int]:
    text = msg_id.decode() if isinstance(msg_id, bytes) else str(msg_id)
    ms, _, seq = text.partition("-")
    return int(ms), int(seq or 0)


def _sqlstate(exc: BaseException) -> str:
    return str(getattr(getattr(exc, "orig", None), "sqlstate", None) or "")


def _err_name(exc: StatementError) -> str:
    return type(exc.orig).__name__ if exc.orig is not None else type(exc).__name__


def _is_data_error(exc: StatementError) -> bool:
    """True for errors caused by the event content (not by the connection/server state)."""
    if exc.connection_invalidated if isinstance(exc, DBAPIError) else False:
        return False
    if not isinstance(exc, DBAPIError):
        return True  # StatementError: the statement could not be built/bound from this data
    return _sqlstate(exc).startswith(("22", "23"))


def _counts_as_attempt(exc: Exception) -> bool:
    """Only failures caused by the message itself count toward dead-lettering.

    That is SQLSTATE class 22 (data exception) or 23 (integrity violation) and statement
    errors that are not driver errors. Everything else (outages, timeouts, permissions,
    deadlocks) retries forever, which turns the heartbeat stale and the container unhealthy.
    """
    if isinstance(exc, DBAPIError):
        return _sqlstate(exc).startswith(("22", "23"))
    return isinstance(exc, StatementError)

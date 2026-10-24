"""Redis Streams consumer loop.

Redis commands used (ACL user ``ingest``): XGROUP CREATE, XREADGROUP, XACK, XAUTOCLAIM,
XTRIM (plus AUTH/HELLO performed implicitly by the client on connect).

Single-consumer assumption: after each committed and acknowledged batch the stream is trimmed
with ``XTRIM MINID ~ <last acked id>``, which also drops entries older than that id that some
other consumer might not have read yet. Run exactly one ingest instance.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Sequence
from typing import Any

from redis.asyncio import Redis
from redis.exceptions import RedisError, ResponseError
from sqlalchemy.exc import DBAPIError, SQLAlchemyError, StatementError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_common import Event

from ingest.config import Settings
from ingest.writer import write_batch

log = logging.getLogger(__name__)

PREVIEW_CHARS = 200
MAX_ATTEMPTS = 5

Message = tuple[bytes | str, dict[Any, Any]]


def preview(fields: dict[Any, Any]) -> str:
    text = repr(fields)
    return text if len(text) <= PREVIEW_CHARS else text[:PREVIEW_CHARS] + "...<truncated>"


def parse_messages(
    messages: Sequence[Message],
) -> tuple[list[tuple[bytes | str, Event]], list[Any]]:
    """Validate messages. Returns (valid (id, event) pairs, ids of bad messages)."""
    good: list[tuple[bytes | str, Event]] = []
    bad: list[Any] = []
    for msg_id, fields in messages:
        try:
            good.append((msg_id, Event.from_stream_fields(fields)))
        except Exception:
            log.warning("invalid message %r skipped: %s", msg_id, preview(fields))
            bad.append(msg_id)
    return good, bad


class Consumer:
    def __init__(
        self,
        settings: Settings,
        redis: Redis,
        factory: async_sessionmaker[AsyncSession],
    ) -> None:
        self.s = settings
        self.redis = redis
        self.factory = factory
        self.stop = asyncio.Event()
        self.attempts: dict[Any, int] = {}

    def heartbeat(self) -> None:
        try:
            self.s.heartbeat_path.touch()
        except OSError:
            log.exception("cannot touch heartbeat file")

    async def ensure_group(self) -> None:
        try:
            await self.redis.xgroup_create(self.s.stream, self.s.group, id="0", mkstream=True)
            log.info("created consumer group %s", self.s.group)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def reclaim_stale(self) -> None:
        """Take over messages left pending by dead consumers (XAUTOCLAIM)."""
        start: bytes | str = "0-0"
        claimed = 0
        while not self.stop.is_set():
            res = await self.redis.xautoclaim(
                self.s.stream,
                self.s.group,
                self.s.consumer,
                min_idle_time=self.s.claim_idle_ms,
                start_id=start,
                count=self.s.batch_size,
            )
            start, messages = res[0], res[1]
            claimed += len(messages)
            if start in (b"0-0", "0-0"):
                break
        if claimed:
            log.info("reclaimed %d stale pending messages", claimed)

    async def process(self, messages: Sequence[Message]) -> None:
        """Validate, write, acknowledge and trim one batch. Raises if the write fails."""
        live: list[Message] = []
        dead: list[Any] = []
        for msg in messages:
            n = self.attempts.get(msg[0], 0)
            if n >= MAX_ATTEMPTS:
                log.error("dead-lettering message %r after %d failed attempts", msg[0], n)
                dead.append(msg[0])
            else:
                live.append(msg)
        await self._ack(dead)
        for mid in dead:
            self.attempts.pop(mid, None)
        acked: list[Any] = list(dead)
        try:
            acked += await self._process_live(live)
        except Exception as exc:
            if _counts_as_attempt(exc):
                for mid, _ in live:
                    self.attempts[mid] = self.attempts.get(mid, 0) + 1
            raise
        for mid, _ in live:
            self.attempts.pop(mid, None)
        await self._trim(acked)

    async def _process_live(self, messages: Sequence[Message]) -> list[Any]:
        """Returns the ids acknowledged."""
        good, bad = parse_messages(messages)
        done: list[Any] = []
        if good:
            try:
                await write_batch(self.factory, [ev for _, ev in good])
            except StatementError as exc:
                if not _is_data_error(exc):
                    raise
                if len(good) == 1:
                    log.error("dropping event rejected by database: %s", _err_name(exc))
                    bad.append(good[0][0])
                else:
                    bad += await self._write_individually(good, done)
            else:
                done = [i for i, _ in good]
                await self._ack(done)
        await self._ack(bad)
        return done + bad

    async def _write_individually(
        self, good: list[tuple[bytes | str, Event]], done: list[Any]
    ) -> list[Any]:
        """Write events one by one. Returns ids dropped as bad data (caller ACKs them)."""
        dropped: list[Any] = []
        for msg_id, ev in good:
            try:
                await write_batch(self.factory, [ev])
            except StatementError as exc:
                if not _is_data_error(exc):
                    raise
                log.error("dropping event rejected by database: %s", _err_name(exc))
                dropped.append(msg_id)
            else:
                await self._ack([msg_id])
                done.append(msg_id)
        return dropped

    async def _trim(self, ids: Sequence[Any]) -> None:
        if not ids:
            return
        last = max(ids, key=_id_key)
        last_s = last.decode() if isinstance(last, bytes) else str(last)
        try:
            await self.redis.xtrim(self.s.stream, minid=last_s, approximate=True)
        except RedisError as exc:
            log.warning("XTRIM failed (%s)", type(exc).__name__)

    async def _ack(self, ids: Sequence[Any]) -> None:
        if ids:
            await self.redis.xack(self.s.stream, self.s.group, *ids)

    async def _read(self, pending: bool) -> list[Message]:
        res = await self.redis.xreadgroup(
            self.s.group,
            self.s.consumer,
            {self.s.stream: "0" if pending else ">"},
            count=self.s.batch_size,
            block=None if pending else self.s.block_ms,
        )
        if not res:
            return []
        return list(res[0][1])

    async def run(self) -> None:
        await self.ensure_group()
        await self.reclaim_stale()
        self.heartbeat()
        pending = True  # first drain our own pending entries (incl. just-claimed ones)
        backoff = 1.0
        while not self.stop.is_set():
            try:
                messages = await self._read(pending)
                if messages:
                    await self.process(messages)
                else:
                    pending = False
                # Heartbeat only after a successful read (and commit, when there was data).
                self.heartbeat()
                backoff = 1.0
            except (RedisError, SQLAlchemyError, OSError) as exc:
                log.error("batch failed (%s), retrying in %.0fs", type(exc).__name__, backoff)
                pending = True  # unacked messages stay in our PEL: re-read them
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
    """Failures that can be caused by the message itself (not by an outage) count toward retries."""
    if isinstance(exc, DBAPIError):
        code = _sqlstate(exc)
        return bool(code) and not code.startswith(("08", "53", "57"))
    return isinstance(exc, StatementError)

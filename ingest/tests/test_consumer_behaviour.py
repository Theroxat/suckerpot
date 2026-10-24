from pathlib import Path
from typing import Any

import pytest
from redis.exceptions import ResponseError
from sqlalchemy.exc import DBAPIError, StatementError

from ingest.config import Settings
from ingest.consumer import MAX_ATTEMPTS, Consumer

from .helpers import make_event


class FakeRedis:
    def __init__(self, batches: list[list[Any]] | None = None, trim_error: bool = False) -> None:
        self.acked: list[Any] = []
        self.trimmed: list[dict[str, Any]] = []
        self.batches = batches or []
        self.trim_error = trim_error
        self.reads = 0

    async def xack(self, stream: str, group: str, *ids: Any) -> int:
        self.acked.extend(ids)
        return len(ids)

    async def xtrim(self, stream: str, **kwargs: Any) -> int:
        if self.trim_error:
            raise ResponseError("NOPERM")
        self.trimmed.append(kwargs)
        return 0

    async def xreadgroup(self, *args: Any, **kwargs: Any) -> Any:
        self.reads += 1
        if self.batches:
            return [[b"events", self.batches.pop(0)]]
        return []


def fields() -> dict[Any, Any]:
    return dict(make_event("connect").to_stream_fields())


def consumer(redis: FakeRedis, tmp_path: Path) -> Consumer:
    s = Settings.from_env({"INGEST_HEARTBEAT_PATH": str(tmp_path / "hb")})
    return Consumer(s, redis, None)  # type: ignore[arg-type]


async def test_trim_uses_last_acked_id(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    async def ok(_f: Any, _e: Any) -> None: ...

    monkeypatch.setattr("ingest.consumer.write_batch", ok)
    r = FakeRedis()
    c = consumer(r, tmp_path)
    await c.process([(b"9-0", fields()), (b"10-1", fields()), (b"10-0", {})])
    assert r.trimmed == [{"minid": "10-1", "approximate": True}]


async def test_trim_failure_is_not_fatal(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    async def ok(_f: Any, _e: Any) -> None: ...

    monkeypatch.setattr("ingest.consumer.write_batch", ok)
    r = FakeRedis(trim_error=True)
    await consumer(r, tmp_path).process([(b"1-0", fields())])
    assert r.acked == [b"1-0"]


async def test_dead_letter_after_max_attempts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def boom(_f: Any, _e: Any) -> None:
        raise DBAPIError("stmt", {}, _Orig("XX000"))

    monkeypatch.setattr("ingest.consumer.write_batch", boom)
    r = FakeRedis()
    c = consumer(r, tmp_path)
    for _ in range(MAX_ATTEMPTS):
        with pytest.raises(DBAPIError):
            await c.process([(b"1-0", fields())])
    assert r.acked == []
    await c.process([(b"1-0", fields())])  # 6th delivery: dead-lettered, not written
    assert r.acked == [b"1-0"]
    assert b"1-0" not in c.attempts


async def test_outage_errors_do_not_count(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    async def down(_f: Any, _e: Any) -> None:
        raise DBAPIError("stmt", {}, _Orig(None))

    monkeypatch.setattr("ingest.consumer.write_batch", down)
    c = consumer(FakeRedis(), tmp_path)
    for _ in range(MAX_ATTEMPTS + 2):
        with pytest.raises(DBAPIError):
            await c.process([(b"1-0", fields())])
    assert c.attempts == {}


async def test_statement_error_single_event_is_data_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def bad(_f: Any, _e: Any) -> None:
        raise StatementError("cannot bind", "stmt", {}, ValueError("x"))

    monkeypatch.setattr("ingest.consumer.write_batch", bad)
    r = FakeRedis()
    await consumer(r, tmp_path).process([(b"1-0", fields())])
    assert r.acked == [b"1-0"]


async def test_heartbeat_only_after_successful_work(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = {"n": 0}

    async def flaky(_f: Any, _e: Any) -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("db down")

    async def noop() -> None: ...

    monkeypatch.setattr("ingest.consumer.write_batch", flaky)
    r = FakeRedis(batches=[[(b"1-0", fields())], [(b"1-0", fields())]])
    c = consumer(r, tmp_path)
    beats: list[int] = []
    at_sleep: list[int] = []

    def spy() -> None:
        beats.append(1)

    async def fake_sleep(_s: float) -> None:
        at_sleep.append(len(beats))

    orig_read = r.xreadgroup

    async def read_then_stop(*a: Any, **k: Any) -> Any:
        res = await orig_read(*a, **k)
        if not res:
            c.stop.set()
        return res

    c.heartbeat = spy  # type: ignore[method-assign]
    c._sleep = fake_sleep  # type: ignore[method-assign,assignment]
    c.ensure_group = noop  # type: ignore[method-assign]
    c.reclaim_stale = noop  # type: ignore[method-assign]
    r.xreadgroup = read_then_stop  # type: ignore[method-assign]
    await c.run()
    assert at_sleep == [1]  # only the startup beat existed when the first batch failed
    assert len(beats) >= 3  # startup, committed batch, then the empty read


class _Orig(Exception):
    def __init__(self, sqlstate: str | None) -> None:
        super().__init__("db error")
        self.sqlstate = sqlstate

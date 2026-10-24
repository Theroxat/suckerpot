from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import ResponseError
from redis.exceptions import TimeoutError as RedisTimeoutError

from suckerpot_common import Event, EventPublisher


def ev(i: int = 0) -> Event:
    return Event(
        ts=datetime(2026, 10, 24, tzinfo=UTC),
        sensor="web",  # type: ignore[arg-type]
        session_id=f"s{i}",
        src_ip="198.51.100.9",  # type: ignore[arg-type]
        src_port=5000 + i,
        dst_port=80,
        type="connect",  # type: ignore[arg-type]
    )


class FakePipe:
    def __init__(self, calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]]) -> None:
        self.calls = calls
        self.queued: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        self.transaction: bool | None = None

    def xadd(self, *args: Any, **kwargs: Any) -> FakePipe:
        self.queued.append(("xadd", args, kwargs))
        return self

    async def execute(self, raise_on_error: bool = True) -> list[Any]:
        self.calls.extend(self.queued)
        return ["1-0"] * len(self.queued)


class FakeRedis:
    """Records every command; any attribute other than the allowed ones raises."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        self.closed = False

    async def xadd(self, *args: Any, **kwargs: Any) -> str:
        self.calls.append(("xadd", args, kwargs))
        return "1-0"

    def pipeline(self, transaction: bool = True) -> FakePipe:
        pipe = FakePipe(self.calls)
        pipe.transaction = transaction
        return pipe

    async def aclose(self) -> None:
        self.closed = True


def pub(fake: FakeRedis, **kw: Any) -> EventPublisher:
    return EventPublisher(host="redis", client=fake, **kw)


async def test_publish_uses_xadd_maxlen_approx() -> None:
    fake = FakeRedis()
    event = ev()
    await pub(fake, maxlen=1234).publish(event)
    assert len(fake.calls) == 1
    name, args, kwargs = fake.calls[0]
    assert name == "xadd"
    assert args == ("events", event.to_stream_fields())
    assert kwargs == {"maxlen": 1234, "approximate": True}


async def test_publish_many_pipeline() -> None:
    fake = FakeRedis()
    await pub(fake, stream="custom").publish_many(ev(i) for i in range(3))
    assert [c[0] for c in fake.calls] == ["xadd"] * 3
    assert all(c[1][0] == "custom" for c in fake.calls)
    assert all(c[2]["approximate"] is True and c[2]["maxlen"] == 10_000 for c in fake.calls)


async def test_publish_many_empty_is_noop() -> None:
    fake = FakeRedis()
    await pub(fake).publish_many([])
    assert fake.calls == []


async def test_close() -> None:
    fake = FakeRedis()
    await pub(fake).close()
    assert fake.closed


async def test_published_fields_parse_back() -> None:
    fake = FakeRedis()
    event = ev(7)
    await pub(fake).publish(event)
    assert Event.from_stream_fields(fake.calls[0][1][1]) == event


def test_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDIS_HOST", "redis")
    monkeypatch.setenv("REDIS_USER", "sensor")
    monkeypatch.setenv("REDIS_PASSWORD", "x")
    monkeypatch.setenv("EVENTS_STREAM", "ev2")
    p = EventPublisher.from_env()
    assert p._stream == "ev2"
    kwargs = p._redis.connection_pool.connection_kwargs
    assert kwargs["host"] == "redis"
    assert kwargs["port"] == 6379
    assert kwargs["username"] == "sensor"


def test_from_env_requires_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REDIS_HOST", raising=False)
    with pytest.raises(KeyError):
        EventPublisher.from_env()


class FailingRedis(FakeRedis):
    def __init__(self, exc: Exception) -> None:
        super().__init__()
        self.exc = exc

    async def xadd(self, *args: Any, **kwargs: Any) -> str:
        raise self.exc

    def pipeline(self, transaction: bool = True) -> FakePipe:
        pipe = FakePipe(self.calls)
        exc = self.exc

        async def boom(raise_on_error: bool = True) -> list[Any]:
            raise exc

        pipe.execute = boom  # type: ignore[method-assign]
        return pipe


ERRORS = [
    ResponseError("OOM command not allowed when used memory > 'maxmemory'."),
    ResponseError("NOPERM this user has no permissions to run the 'xadd' command"),
    RedisConnectionError("connection refused"),
    RedisTimeoutError("timed out"),
    OSError("network down"),
]


@pytest.mark.parametrize("exc", ERRORS, ids=lambda e: type(e).__name__)
async def test_publish_never_raises(exc: Exception) -> None:
    p = pub(FailingRedis(exc))
    assert await p.publish(ev()) is False
    assert await p.publish(ev()) is False
    assert p.dropped == 2
    assert p.published == 0
    assert p.dropped_by_error == {type(exc).__name__: 2}


@pytest.mark.parametrize("exc", ERRORS, ids=lambda e: type(e).__name__)
async def test_publish_many_never_raises(exc: Exception) -> None:
    p = pub(FailingRedis(exc))
    assert await p.publish_many([ev(1), ev(2), ev(3)]) == 0
    assert p.dropped == 3


async def test_partial_pipeline_failure_flags() -> None:
    class Pipe(FakePipe):
        async def execute(self, raise_on_error: bool = True) -> list[Any]:
            assert raise_on_error is False
            return ["1-0", ResponseError("OOM command not allowed"), "2-0"]

    class R(FakeRedis):
        def pipeline(self, transaction: bool = True) -> FakePipe:
            return Pipe(self.calls)

    p = pub(R())
    assert await p.publish_batch([ev(1), ev(2), ev(3)]) == [True, False, True]
    assert (p.published, p.dropped) == (2, 1)


async def test_log_rate_limited(caplog: pytest.LogCaptureFixture) -> None:
    p = pub(FailingRedis(RedisConnectionError("x")))
    with caplog.at_level("WARNING", logger="suckerpot.publisher"):
        for _ in range(50):
            await p.publish(ev())
    assert len(caplog.records) == 1
    assert p.dropped == 50


async def test_close_never_raises() -> None:
    class Bad(FakeRedis):
        async def aclose(self) -> None:
            raise RedisConnectionError("x")

    await pub(Bad()).close()


def test_default_maxlen_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDIS_HOST", "redis")
    monkeypatch.delenv("EVENTS_MAXLEN", raising=False)
    assert EventPublisher.from_env()._maxlen == 10_000
    monkeypatch.setenv("EVENTS_MAXLEN", "500")
    assert EventPublisher.from_env()._maxlen == 500


def test_socket_timeouts_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDIS_HOST", "redis")
    kw = EventPublisher.from_env()._redis.connection_pool.connection_kwargs
    assert kw["socket_timeout"] <= 2.0
    assert kw["socket_connect_timeout"] <= 2.0


async def test_stream_override_per_call() -> None:
    fake = FakeRedis()
    p = pub(fake, stream="events:ssh")
    await p.publish(ev(1))
    await p.publish(ev(2), stream="events:web")
    await p.publish_many([ev(3)], stream="events:rdp")
    assert await p.publish_batch([ev(4)], stream="events:telnet") == [True]
    await p.publish_many([ev(5)])
    assert [c[1][0] for c in fake.calls] == [
        "events:ssh",
        "events:web",
        "events:rdp",
        "events:telnet",
        "events:ssh",
    ]


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def sized(i: int, type_: str = "command", n: int = 0) -> Event:
    return Event(
        ts=datetime(2026, 10, 24, tzinfo=UTC),
        sensor="ssh",  # type: ignore[arg-type]
        session_id=f"s{i}",
        src_ip="198.51.100.9",  # type: ignore[arg-type]
        src_port=1,
        dst_port=22,
        type=type_,  # type: ignore[arg-type]
        data={"input": "x" * n},
    )


def budgeted(**kw: Any) -> tuple[EventPublisher, FakeRedis, Clock]:
    fake, clock = FakeRedis(), Clock()
    p = EventPublisher(host="r", client=fake, clock=clock, **kw)
    return p, fake, clock


def size_of(e: Event) -> int:
    return len(e.to_stream_fields()["event"].encode())


async def test_budget_drops_and_counts_without_raising() -> None:
    e = sized(1, n=100)
    sz = size_of(e)
    p, fake, _ = budgeted(max_bytes_per_sec=1000, burst_bytes=sz * 10)
    results = [await p.publish(e) for _ in range(20)]
    # ordinary events stop at the 10% reserve: floor = sz, so 9 pass
    assert results.count(True) == 9
    assert p.dropped == 11
    assert p.dropped_bytes == 11 * sz
    assert p.dropped_by_reason == {"byte_budget": 11}
    assert p.published_bytes == 9 * sz
    assert len(fake.calls) == 9
    assert p.stats()["dropped_by_reason"] == {"byte_budget": 11}


async def test_priority_types_use_reserve() -> None:
    e = sized(1, n=100)
    sz = size_of(e)
    p, _, _ = budgeted(max_bytes_per_sec=1000, burst_bytes=sz * 40)
    while await p.publish(e):
        pass
    assert await p.publish(sized(2, "login_attempt", 100)) is True
    assert await p.publish(sized(3, "disconnect", 100)) is True
    assert await p.publish(sized(4, "command", 100)) is False


async def test_refill_over_time() -> None:
    e = sized(1, n=100)
    sz = size_of(e)
    p, _, clock = budgeted(max_bytes_per_sec=sz, burst_bytes=sz * 10)
    while await p.publish(e):
        pass
    assert await p.publish(e) is False
    clock.t += 5  # +5 events worth of tokens
    ok = [await p.publish(e) for _ in range(6)]
    assert ok.count(True) == 5
    clock.t += 10_000  # refill is capped at the burst
    ok = [await p.publish(e) for _ in range(20)]
    assert ok.count(True) == 9


async def test_batch_partial_admission_keeps_order() -> None:
    e = sized(1, n=100)
    sz = size_of(e)
    p, fake, _ = budgeted(max_bytes_per_sec=1, burst_bytes=sz * 10)
    batch = [sized(i, n=100) for i in range(12)]
    flags = await p.publish_batch(batch)
    assert flags == [True] * 9 + [False] * 3
    assert len(fake.calls) == 9
    assert p.dropped == 3


async def test_batch_all_dropped_makes_no_redis_call() -> None:
    p, fake, _ = budgeted(max_bytes_per_sec=1, burst_bytes=10)
    assert await p.publish_many([sized(1, n=100)]) == 0
    assert fake.calls == []


async def test_zero_rate_disables_limiter() -> None:
    p, _, _ = budgeted(max_bytes_per_sec=0, burst_bytes=1)
    assert all([await p.publish(sized(i, n=1000)) for i in range(50)])
    assert p.dropped == 0


async def test_redis_error_counted_in_reason() -> None:
    p = EventPublisher(host="r", client=FailingRedis(RedisConnectionError("x")))
    await p.publish(ev())
    assert p.dropped_by_reason == {"redis_error": 1}


def test_budget_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDIS_HOST", "redis")
    monkeypatch.setenv("EVENTS_MAX_BYTES_PER_SEC", "123")
    monkeypatch.setenv("EVENTS_MAX_BYTES_BURST", "4567")
    p = EventPublisher.from_env()
    assert (p._rate, p._burst) == (123.0, 4567.0)
    monkeypatch.delenv("EVENTS_MAX_BYTES_PER_SEC")
    monkeypatch.delenv("EVENTS_MAX_BYTES_BURST")
    p = EventPublisher.from_env()
    assert (p._rate, p._burst) == (200_000.0, 2_000_000.0)

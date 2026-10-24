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

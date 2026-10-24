import json
from typing import Any

import pytest

from ingest.diskguard import DiskGuard, shrink_data

MB = 1024 * 1024


class FakeSession:
    def __init__(self, owner: "FakeFactory") -> None:
        self.owner = owner

    async def __aenter__(self) -> "FakeSession":
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def scalar(self, *_a: Any, **_k: Any) -> int:
        self.owner.calls += 1
        if self.owner.fail:
            raise RuntimeError("db down")
        return self.owner.size


class FakeFactory:
    def __init__(self, size: int) -> None:
        self.size = size
        self.calls = 0
        self.fail = False

    def __call__(self) -> FakeSession:
        return FakeSession(self)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def make(size_mb: int) -> tuple[DiskGuard, FakeFactory, Clock, list[dict[str, Any]]]:
    factory = FakeFactory(size_mb * MB)
    clock = Clock()
    seen: list[dict[str, Any]] = []

    async def sink(detail: dict[str, Any]) -> None:
        seen.append(detail)

    guard = DiskGuard(factory, 100 * MB, clock=clock, on_status=sink)  # type: ignore[arg-type]
    return guard, factory, clock, seen


async def test_check_is_cached_for_the_interval() -> None:
    guard, factory, clock, _ = make(10)
    assert not await guard.is_degraded()
    assert not await guard.is_degraded()
    assert factory.calls == 1
    clock.now += 31
    await guard.is_degraded()
    assert factory.calls == 2


async def test_enters_above_95_and_leaves_below_90() -> None:
    guard, factory, clock, seen = make(96)
    assert await guard.is_degraded()
    factory.size = 92 * MB
    clock.now += 31
    assert await guard.is_degraded()  # hysteresis: still degraded between 90 and 95
    factory.size = 89 * MB
    clock.now += 31
    assert not await guard.is_degraded()
    assert [s["degraded"] for s in seen] == [True, True, False]
    assert seen[-1]["max_bytes"] == 100 * MB and seen[0]["percent"] == 96.0


async def test_exactly_95_percent_is_not_degraded() -> None:
    guard, _, _, _ = make(95)
    assert not await guard.is_degraded()


async def test_failed_check_keeps_state_and_never_raises() -> None:
    guard, factory, clock, _ = make(97)
    assert await guard.is_degraded()
    factory.fail = True
    clock.now += 31
    assert await guard.is_degraded()


async def test_ok_state_is_published_once() -> None:
    guard, _, clock, seen = make(10)
    for _ in range(3):
        await guard.is_degraded()
        clock.now += 31
    assert len(seen) == 1 and seen[0]["degraded"] is False


def test_shrink_keeps_keys_and_caps_values_and_total() -> None:
    data = {"input": "x" * 5000, "cwd": "/root", "n": 7, "ok": True, "extra": {"a": "b" * 900}}
    out = shrink_data(data)
    assert out["input"] == "x" * 256 and out["cwd"] == "/root" and out["n"] == 7
    assert out["ok"] is True and out["_truncated"] is True
    assert isinstance(out["extra"], str) and len(out["extra"]) <= 256
    assert len(json.dumps(out)) <= 1100


def test_shrink_respects_the_total_budget() -> None:
    out = shrink_data({f"k{i}": "v" * 200 for i in range(50)})
    assert len(json.dumps(out)) <= 1100 and out["_truncated"] is True


def test_degrade_rows_only_touches_command_and_http_events() -> None:
    guard, _, _, _ = make(10)
    rows: list[dict[str, Any]] = [
        {"type": "command", "data": {"input": "y" * 2000}},
        {"type": "http_request", "data": {"path": "/" + "p" * 2000}},
        {"type": "login_attempt", "data": {"username": "u" * 2000}},
    ]
    guard.degrade_rows(rows)
    assert len(rows[0]["data"]["input"]) == 256 and len(rows[1]["data"]["path"]) == 256
    assert len(rows[2]["data"]["username"]) == 2000
    assert guard.degraded_writes == 2


@pytest.mark.parametrize("n", [0, 1])
def test_empty_or_tiny_data(n: int) -> None:
    assert shrink_data({}) == {"_truncated": True}

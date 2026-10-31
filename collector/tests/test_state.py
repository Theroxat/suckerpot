from datetime import timedelta

import pytest

from collector import fetch as fx
from collector.fetch import FetchResult
from collector.service import RETRY_DELAYS, CollectorService, Target


def target(attempts: int) -> Target:
    return Target(1, "http://files.example.test/x", "files.example.test", attempts, 0)


@pytest.mark.parametrize(
    ("attempts", "status", "delay"),
    [
        (0, "pending", timedelta(minutes=15)),
        (1, "pending", timedelta(hours=1)),
        (2, "pending", timedelta(hours=6)),
        (3, "failed", None),
    ],
)
def test_retry_ladder(attempts: int, status: str, delay: timedelta | None) -> None:
    for outcome in (fx.TIMEOUT, fx.NETWORK, fx.HTTP_5XX):
        got_status, got_delay, _ = CollectorService._next_state(
            target(attempts), FetchResult(outcome)
        )
        assert (got_status, got_delay) == (status, delay)
    assert len(RETRY_DELAYS) == 3


@pytest.mark.parametrize(
    ("outcome", "status"),
    [
        (fx.HTTP_4XX, "gone"),
        (fx.EMPTY, "gone"),
        (fx.TOO_LARGE, "too_large"),
        (fx.REFUSED, "refused"),
        (fx.REDIRECT_LIMIT, "refused"),
        (fx.BAD_REDIRECT, "refused"),
        (fx.QUARANTINE_FULL, "pending"),
    ],
)
def test_final_states(outcome: str, status: str) -> None:
    assert CollectorService._next_state(target(0), FetchResult(outcome))[0] == status

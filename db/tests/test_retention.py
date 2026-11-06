import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from suckerpot_db.retention import (
    AGGREGATES,
    COMPRESS_AFTER_DAYS,
    LOCK_NOT_AVAILABLE,
    MIN_RETENTION_DAYS,
    REFRESH_RETRY_DELAYS,
    RetentionError,
    _refresh,
    retention_days,
)


def test_default_is_90_days() -> None:
    assert retention_days({}) == 90
    assert retention_days({"RETENTION_DAYS": "  "}) == 90


@pytest.mark.parametrize("value", ["7", "30", "90", "3650"])
def test_valid_values(value: str) -> None:
    assert retention_days({"RETENTION_DAYS": value}) == int(value)


@pytest.mark.parametrize("value", ["6", "0", "-1", "3651", "ninety", "1.5"])
def test_invalid_values_are_rejected(value: str) -> None:
    with pytest.raises(RetentionError, match="RETENTION_DAYS"):
        retention_days({"RETENTION_DAYS": value})


def test_compression_never_outlives_the_minimum_retention() -> None:
    assert COMPRESS_AFTER_DAYS <= MIN_RETENTION_DAYS


def test_every_aggregate_has_a_bucket() -> None:
    assert set(AGGREGATES) == {
        "events_hourly",
        "events_daily_tags",
        "events_daily_country",
        "events_daily_ip",
    }


class _PgError(Exception):
    def __init__(self, sqlstate: str) -> None:
        super().__init__(sqlstate)
        self.sqlstate = sqlstate


class _Conn:
    """Fails with the given SQLSTATEs first, then succeeds."""

    def __init__(self, *failures: str) -> None:
        self.failures = list(failures)
        self.calls = 0

    def execute(self, statement: object, params: object = None) -> None:
        self.calls += 1
        if self.failures:
            raise DBAPIError(
                "CALL refresh_continuous_aggregate", {}, _PgError(self.failures.pop(0))
            )


def test_refresh_waits_out_a_concurrent_refresh_policy() -> None:
    conn = _Conn(LOCK_NOT_AVAILABLE, LOCK_NOT_AVAILABLE)
    waits: list[float] = []
    _refresh(conn, text("CALL x()"), {}, sleep=waits.append)  # type: ignore[arg-type]
    assert conn.calls == 3
    assert waits == list(REFRESH_RETRY_DELAYS[:2])


def test_refresh_gives_up_after_the_last_retry() -> None:
    conn = _Conn(*[LOCK_NOT_AVAILABLE] * (len(REFRESH_RETRY_DELAYS) + 1))
    with pytest.raises(DBAPIError):
        _refresh(conn, text("CALL x()"), {}, sleep=lambda _: None)  # type: ignore[arg-type]
    assert conn.calls == len(REFRESH_RETRY_DELAYS) + 1


def test_refresh_raises_other_errors_at_once() -> None:
    conn = _Conn("42P01")
    waits: list[float] = []
    with pytest.raises(DBAPIError):
        _refresh(conn, text("CALL x()"), {}, sleep=waits.append)  # type: ignore[arg-type]
    assert conn.calls == 1 and waits == []

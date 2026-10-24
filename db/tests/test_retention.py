import pytest

from suckerpot_db.retention import (
    AGGREGATES,
    COMPRESS_AFTER_DAYS,
    MIN_RETENTION_DAYS,
    RetentionError,
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

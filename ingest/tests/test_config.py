from pathlib import Path

import pytest

from ingest.config import Settings


def test_defaults() -> None:
    s = Settings.from_env({"INGEST_CONSUMER": "c1"})
    assert (s.redis_host, s.redis_port, s.redis_user) == ("redis", 6379, "ingest")
    assert (s.stream, s.group, s.consumer) == ("events", "ingest", "c1")
    assert (s.batch_size, s.block_ms) == (100, 1000)
    assert s.heartbeat_path == Path("/tmp/ingest-heartbeat")


def test_overrides() -> None:
    s = Settings.from_env(
        {
            "REDIS_HOST": "r",
            "REDIS_PORT": "6380",
            "REDIS_PASSWORD": "x",
            "EVENTS_STREAM": "ev2",
            "INGEST_BATCH_SIZE": "10",
        }
    )
    assert (s.redis_host, s.redis_port, s.redis_password, s.stream, s.batch_size) == (
        "r",
        6380,
        "x",
        "ev2",
        10,
    )


@pytest.mark.parametrize("value", ["0", "501", "-1"])
def test_batch_bounds(value: str) -> None:
    with pytest.raises(ValueError, match="INGEST_BATCH_SIZE"):
        Settings.from_env({"INGEST_BATCH_SIZE": value})

from pathlib import Path

import pytest

from ingest.config import Settings


def test_stable_default_consumer_name() -> None:
    assert Settings.from_env({}).consumer == "ingest-1"


def test_defaults() -> None:
    s = Settings.from_env({"INGEST_CONSUMER": "c1"})
    assert (s.redis_host, s.redis_port, s.redis_user) == ("redis", 6379, "ingest")
    assert (s.group, s.consumer) == ("ingest", "c1")
    assert s.streams == ("events:ssh", "events:telnet", "events:web", "events:rdp")
    assert (s.batch_size, s.block_ms) == (100, 1000)
    assert s.heartbeat_path == Path("/tmp/ingest-heartbeat")


def test_overrides() -> None:
    s = Settings.from_env(
        {
            "REDIS_HOST": "r",
            "REDIS_PORT": "6380",
            "REDIS_PASSWORD": "x",
            "INGEST_STREAMS": "events:a, events:b,events:a",
            "INGEST_BATCH_SIZE": "10",
        }
    )
    assert (s.redis_host, s.redis_port, s.redis_password, s.streams, s.batch_size) == (
        "r",
        6380,
        "x",
        ("events:a", "events:b"),
        10,
    )


@pytest.mark.parametrize("value", ["0", "501", "-1"])
def test_batch_bounds(value: str) -> None:
    with pytest.raises(ValueError, match="INGEST_BATCH_SIZE"):
        Settings.from_env({"INGEST_BATCH_SIZE": value})


@pytest.mark.parametrize("value", ["", " , ", "events:ssh,bad name", "x" * 65, "a;b"])
def test_invalid_streams(value: str) -> None:
    with pytest.raises(ValueError, match=r"INGEST_STREAMS|stream"):
        Settings.from_env({"INGEST_STREAMS": value})

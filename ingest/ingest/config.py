"""Configuration read from environment variables."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

DEFAULT_STREAMS = "events:ssh,events:telnet,events:web,events:rdp"
_STREAM_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


def parse_streams(value: str) -> tuple[str, ...]:
    """Comma-separated stream names (deduplicated, order kept)."""
    names = list(dict.fromkeys(n.strip() for n in value.split(",") if n.strip()))
    if not names:
        raise ValueError("INGEST_STREAMS must list at least one stream")
    for n in names:
        if not _STREAM_RE.match(n):
            raise ValueError(f"invalid stream name in INGEST_STREAMS: {n!r}")
    return tuple(names)


@dataclass(frozen=True, slots=True)
class Settings:
    redis_host: str
    redis_port: int
    redis_user: str
    redis_password: str
    streams: tuple[str, ...]
    group: str
    consumer: str
    batch_size: int
    block_ms: int
    claim_idle_ms: int
    reclaim_interval_s: float
    heartbeat_path: Path

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        e = os.environ if env is None else env
        batch = int(e.get("INGEST_BATCH_SIZE", "100"))
        if not 1 <= batch <= 500:
            raise ValueError("INGEST_BATCH_SIZE must be between 1 and 500")
        return cls(
            redis_host=e.get("REDIS_HOST", "redis"),
            redis_port=int(e.get("REDIS_PORT", "6379")),
            redis_user=e.get("REDIS_USER", "ingest"),
            redis_password=e.get("REDIS_PASSWORD", ""),
            streams=parse_streams(e.get("INGEST_STREAMS", DEFAULT_STREAMS)),
            group=e.get("INGEST_GROUP", "ingest"),
            consumer=e.get("INGEST_CONSUMER") or "ingest-1",
            batch_size=batch,
            block_ms=int(e.get("INGEST_BLOCK_MS", "1000")),
            claim_idle_ms=int(e.get("INGEST_CLAIM_IDLE_MS", "60000")),
            reclaim_interval_s=float(e.get("INGEST_RECLAIM_INTERVAL_S", "60")),
            heartbeat_path=Path(e.get("INGEST_HEARTBEAT_PATH", "/tmp/ingest-heartbeat")),  # noqa: S108
        )

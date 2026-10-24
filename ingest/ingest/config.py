"""Configuration read from environment variables."""

from __future__ import annotations

import os
import socket
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Settings:
    redis_host: str
    redis_port: int
    redis_user: str
    redis_password: str
    stream: str
    group: str
    consumer: str
    batch_size: int
    block_ms: int
    claim_idle_ms: int
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
            stream=e.get("EVENTS_STREAM", "events"),
            group=e.get("INGEST_GROUP", "ingest"),
            consumer=e.get("INGEST_CONSUMER") or socket.gethostname(),
            batch_size=batch,
            block_ms=int(e.get("INGEST_BLOCK_MS", "1000")),
            claim_idle_ms=int(e.get("INGEST_CLAIM_IDLE_MS", "60000")),
            heartbeat_path=Path(e.get("INGEST_HEARTBEAT_PATH", "/tmp/ingest-heartbeat")),  # noqa: S108
        )

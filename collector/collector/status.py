"""Heartbeat file and published status rows shared by the collector and the analyzer."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

MAX_HEARTBEAT_AGE_S = 90.0


def beat(path: Path) -> None:
    """Touch the heartbeat file (on the container's tmpfs) read by the healthcheck."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    now = time.time()
    os.utime(path, (now, now))


def heartbeat_age(path: Path) -> float | None:
    try:
        return time.time() - path.stat().st_mtime
    except OSError:
        return None


async def publish_status(
    factory: async_sessionmaker[AsyncSession], name: str, detail: dict[str, Any]
) -> None:
    async with factory() as session, session.begin():
        await session.execute(
            text(
                """
                INSERT INTO enrichment_status (name, detail, updated_at)
                VALUES (:name, CAST(:detail AS jsonb), now())
                ON CONFLICT (name) DO UPDATE SET detail = EXCLUDED.detail, updated_at = now()
                """
            ),
            {"name": name, "detail": json.dumps(detail)},
        )

"""Publish enrichment status for the API's settings page (no secrets)."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


async def publish_status(
    factory: async_sessionmaker[AsyncSession], name: str, detail: dict[str, Any]
) -> None:
    async with factory() as session, session.begin():
        await session.execute(
            text(
                """
                INSERT INTO enrichment_status (name, detail, updated_at)
                VALUES (:n, CAST(:d AS jsonb), now())
                ON CONFLICT (name) DO UPDATE SET detail = CAST(:d AS jsonb), updated_at = now()
                """
            ),
            {"n": name, "d": json.dumps(detail)},
        )

"""Async engine and session factory helpers."""

from __future__ import annotations

import os
from collections.abc import Mapping
from urllib.parse import quote

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


def database_url_from_env(env: Mapping[str, str] | None = None) -> str:
    """Build a ``postgresql+asyncpg`` URL from the POSTGRES_* variables.

    User and password are percent-encoded so any character is safe.
    """
    e = os.environ if env is None else env
    user = quote(e.get("POSTGRES_USER", "suckerpot"), safe="")
    password = quote(e.get("POSTGRES_PASSWORD", ""), safe="")
    host = e.get("POSTGRES_HOST", "db")
    port = int(e.get("POSTGRES_PORT", "5432"))
    name = quote(e.get("POSTGRES_DB", "suckerpot"), safe="")
    host_part = f"[{host}]" if ":" in host else host
    return f"postgresql+asyncpg://{user}:{password}@{host_part}:{port}/{name}"


def create_engine(url: str | None = None, *, pool_size: int = 5) -> AsyncEngine:
    """Create an async engine (URL defaults to the environment)."""
    return create_async_engine(
        url or database_url_from_env(),
        pool_size=pool_size,
        max_overflow=5,
        pool_pre_ping=True,
        connect_args={"server_settings": {"timezone": "UTC"}},
    )


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Session factory with ``expire_on_commit=False``."""
    return async_sessionmaker(engine, expire_on_commit=False)

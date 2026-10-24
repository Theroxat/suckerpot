"""ASGI entry point: ``uvicorn api.main:app``."""

from __future__ import annotations

import asyncio
import contextlib
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db import create_engine, create_session_factory

from api.live import LiveHub, LivePoller, live_router
from api.routes import health_router, router
from api.spa import install_security_headers, install_spa

TRUE_VALUES = {"1", "true", "yes", "on"}
DEFAULT_WEB_DIST = "/app/web"


def create_app(
    session_factory: async_sessionmaker[AsyncSession] | None = None,
    *,
    enable_docs: bool | None = None,
    web_dist_dir: Path | None = None,
    enable_live: bool = True,
) -> FastAPI:
    """Build the app. Tests pass their own session factory; production builds one from env."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = None
        factory = session_factory
        if factory is None:
            engine = create_engine()
            factory = create_session_factory(engine)
        app.state.session_factory = factory
        hub: LiveHub = app.state.hub
        poller_task = None
        if enable_live:
            poller_task = asyncio.create_task(LivePoller(factory, hub).run())
        try:
            yield
        finally:
            hub.close_all()
            if poller_task is not None:
                poller_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await poller_task
            if engine is not None:
                await engine.dispose()

    if enable_docs is None:
        enable_docs = os.environ.get("API_ENABLE_DOCS", "false").strip().lower() in TRUE_VALUES
    app = FastAPI(
        title="API",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if enable_docs else None,
        redoc_url="/redoc" if enable_docs else None,
        openapi_url="/openapi.json" if enable_docs else None,
    )
    install_security_headers(app, enable_docs=enable_docs)
    app.include_router(health_router)
    app.include_router(router, prefix="/api/v1")
    app.include_router(live_router, prefix="/api/v1")
    app.state.hub = LiveHub()

    dist = (
        web_dist_dir
        if web_dist_dir is not None
        else Path(os.environ.get("WEB_DIST_DIR", DEFAULT_WEB_DIST))
    )
    if (dist / "index.html").is_file():
        install_spa(app, dist)
    return app


app = create_app()

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
from starlette.middleware.trustedhost import TrustedHostMiddleware
from suckerpot_db import create_engine, create_session_factory

from api.analytics import router as analytics_router
from api.auth import AuthMiddleware, AuthService, AuthSettings, allowed_hosts_from_env
from api.auth import router as auth_router
from api.cves import router as cves_router
from api.indicators import router as indicators_router
from api.insights import router as insights_router
from api.live import LiveHub, LivePoller, live_router
from api.malware import router as malware_router
from api.provider_keys import install as install_provider_keys
from api.provider_keys import router as provider_keys_router
from api.routes import health_router, router
from api.settings import router as settings_router
from api.spa import install_security_headers, install_spa
from api.trends import router as trends_router

TRUE_VALUES = {"1", "true", "yes", "on"}
DEFAULT_WEB_DIST = "/app/web"


def create_app(
    session_factory: async_sessionmaker[AsyncSession] | None = None,
    *,
    enable_docs: bool | None = None,
    web_dist_dir: Path | None = None,
    enable_live: bool = True,
    auth_settings: AuthSettings | None = None,
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
    # Auth is added before the header middleware so that 401/403 responses carry the headers too.
    auth = AuthService(auth_settings if auth_settings is not None else AuthSettings.from_env())
    app.state.auth = auth
    app.add_middleware(AuthMiddleware, auth=auth)
    install_security_headers(app, enable_docs=enable_docs)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts_from_env())
    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(health_router)
    app.include_router(router, prefix="/api/v1")
    app.include_router(live_router, prefix="/api/v1")
    app.include_router(analytics_router, prefix="/api/v1")
    app.include_router(insights_router, prefix="/api/v1")
    app.include_router(trends_router, prefix="/api/v1")
    app.include_router(cves_router, prefix="/api/v1")
    app.include_router(malware_router, prefix="/api/v1")
    app.include_router(indicators_router, prefix="/api/v1")
    app.include_router(settings_router, prefix="/api/v1")
    app.include_router(provider_keys_router, prefix="/api/v1")
    install_provider_keys(app)
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

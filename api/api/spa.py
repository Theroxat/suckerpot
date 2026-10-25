"""Static SPA serving and security headers."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from starlette.staticfiles import StaticFiles
from starlette.types import Scope

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Resource-Policy": "same-origin",
}
DOC_PATHS = ("/docs", "/redoc")
IMMUTABLE = "public, max-age=31536000, immutable"


class ImmutableStaticFiles(StaticFiles):
    """Hashed build assets: cache for a year."""

    async def get_response(self, path: str, scope: Scope) -> Response:
        response = await super().get_response(path, scope)
        if response.status_code == 200:
            response.headers["Cache-Control"] = IMMUTABLE
        return response


def install_security_headers(app: FastAPI, *, enable_docs: bool) -> None:
    @app.middleware("http")
    async def headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        for key, value in SECURITY_HEADERS.items():
            response.headers[key] = value
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        # Swagger UI/ReDoc load scripts from a CDN; only relax the policy for those pages.
        # A route may set a stricter policy of its own (the weekly report page): keep it.
        if "content-security-policy" not in response.headers and not (
            enable_docs and request.url.path in DOC_PATHS
        ):
            response.headers["Content-Security-Policy"] = CSP
        return response


def _is_api_path(path: str) -> bool:
    # "feeds" is the opt-in blocklist feed (api.feeds): never answer it with the web app.
    return (
        path in ("api", "feeds", "healthz") or path.startswith("api/") or path.startswith("feeds/")
    )


def install_spa(app: FastAPI, dist: Path) -> None:
    """Serve ``dist`` (a built SPA). Must be called after every API route is registered."""
    root = dist.resolve()
    index = root / "index.html"
    assets = root / "assets"
    if assets.is_dir():
        app.mount("/assets", ImmutableStaticFiles(directory=assets), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa(full_path: str) -> FileResponse:
        if _is_api_path(full_path):
            raise HTTPException(status_code=404, detail="Not Found")
        try:
            candidate = (root / full_path).resolve()
            servable = bool(full_path) and candidate.is_file() and candidate.is_relative_to(root)
        except (ValueError, OSError):  # NUL byte, over-long name, ...
            servable = False
        if servable and candidate != index:
            return FileResponse(candidate, headers={"Cache-Control": "public, max-age=3600"})
        return FileResponse(index, headers={"Cache-Control": "no-cache"})

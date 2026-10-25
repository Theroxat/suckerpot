"""Only the weekly report page may keep a policy of its own; everything else gets the global one."""

import httpx
from fastapi import FastAPI, Response

from api.spa import CSP, install_security_headers

OWN = "default-src 'none'"
PATHS = (
    "/api/v1/reports/2026-10-12/html",
    "/api/v1/reports/2026-10-12",
    "/api/v1/reports/2026-10-12/html/extra",
    "/api/v1/alerts/status",
    "/other",
)


def build() -> FastAPI:
    app = FastAPI()
    install_security_headers(app, enable_docs=False)

    def page() -> Response:
        return Response("x", headers={"Content-Security-Policy": OWN})

    for path in PATHS:
        app.add_api_route(path, page)
    return app


async def test_the_csp_survives_only_on_the_report_page() -> None:
    transport = httpx.ASGITransport(app=build())
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        kept = await c.get(PATHS[0])
        assert kept.headers["content-security-policy"] == OWN
        for path in PATHS[1:]:
            assert (await c.get(path)).headers["content-security-policy"] == CSP, path

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from api.main import create_app


@pytest.fixture
async def client(tmp_path: Path) -> AsyncIterator[httpx.AsyncClient]:
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "app-abc123.js").write_text("console.log(1)")
    (tmp_path / "index.html").write_text("<!doctype html><title>app</title>")
    (tmp_path / "favicon.svg").write_text("<svg/>")
    secret = tmp_path.parent / "outside-secret.txt"
    secret.write_text("secret")
    app = create_app(None, web_dist_dir=tmp_path, enable_live=False, enable_docs=False)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c,
    ):
        yield c


async def test_index_and_deep_links_fall_back(client: httpx.AsyncClient) -> None:
    for path in ("/", "/attacks", "/sessions/abc-1", "/trends/x/y"):
        r = await client.get(path)
        assert r.status_code == 200 and "<title>app</title>" in r.text
        assert r.headers["cache-control"] == "no-cache"


async def test_assets_are_immutable(client: httpx.AsyncClient) -> None:
    r = await client.get("/assets/app-abc123.js")
    assert r.status_code == 200
    assert (
        "immutable" in r.headers["cache-control"]
        and "max-age=31536000" in r.headers["cache-control"]
    )
    missing = await client.get("/assets/nope.js")
    assert missing.status_code == 404


async def test_root_files_served(client: httpx.AsyncClient) -> None:
    r = await client.get("/favicon.svg")
    assert r.text == "<svg/>"


async def test_api_404_stays_json(client: httpx.AsyncClient) -> None:
    for path in ("/api/v1/nope", "/api/nope", "/api", "/api/v1/live"):
        r = await client.get(path)
        assert r.status_code == 404
        assert r.json() == {"detail": "Not Found"}


async def test_healthz_not_shadowed(client: httpx.AsyncClient) -> None:
    r = await client.get("/healthz")
    assert r.headers["content-type"].startswith("application/json")


async def test_path_traversal_does_not_leak(client: httpx.AsyncClient) -> None:
    for path in (
        "/..%2foutside-secret.txt",
        "/%2e%2e/outside-secret.txt",
        "/../outside-secret.txt",
    ):
        r = await client.get(path)
        assert "secret" not in r.text


async def test_non_get_not_allowed(client: httpx.AsyncClient) -> None:
    assert (await client.post("/")).status_code == 405


async def test_security_headers_everywhere(client: httpx.AsyncClient) -> None:
    for path in ("/", "/assets/app-abc123.js", "/api/v1/nope", "/healthz"):
        r = await client.get(path)
        h = r.headers
        csp = h["content-security-policy"]
        assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp
        assert "connect-src 'self' ws: wss:" in csp and "img-src 'self' data:" in csp
        assert h["x-content-type-options"] == "nosniff"
        assert h["referrer-policy"] == "no-referrer"
        assert "geolocation=()" in h["permissions-policy"]
        assert not any("suckerpot" in f"{k}{v}".lower() for k, v in h.items())


async def test_no_spa_without_dist(tmp_path: Path) -> None:
    app = create_app(None, web_dist_dir=tmp_path / "missing", enable_live=False)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/")
    assert r.status_code == 404 and r.json() == {"detail": "Not Found"}

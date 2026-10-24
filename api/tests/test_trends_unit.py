"""Trends and malware request validation and helpers (no database)."""

from collections.abc import AsyncIterator
from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from suckerpot_db import create_session_factory

from api.cursor import InvalidCursorError, encode_cursor
from api.main import create_app
from api.malware import _cursor, _parse_cursor, host_of


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    engine = create_async_engine(
        "postgresql+asyncpg://u:p@127.0.0.1:1/d", connect_args={"timeout": 1}
    )
    app = create_app(create_session_factory(engine), enable_live=False)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t/api/v1"
        ) as c:
            yield c
    await engine.dispose()


@pytest.mark.parametrize(
    "url",
    [
        "/trends/new",  # field is required
        "/trends/new?field=country",
        "/trends/new?field=url&days=0",
        "/trends/new?field=url&days=31",
        "/trends/new?field=url&limit=0",
        "/trends/new?field=url&limit=201",
        "/trends/tags?bucket=2h",
        "/trends/tags?since=2026-10-24T10:00:00",
        "/trends/tags?bucket=5m&since=2026-10-01T00:00:00Z&until=2026-10-20T00:00:00Z",
        "/trends/tags?since=2026-01-01T00:00:00Z&until=2026-10-24T00:00:00Z",
        "/malware?limit=0",
        "/malware?limit=201",
        "/malware?tool=a%20b",
        "/malware?q=" + "x" * 129,
        "/malware/detail",
        "/malware/detail?url=",
    ],
)
async def test_validation_errors(client: httpx.AsyncClient, url: str) -> None:
    assert (await client.get(url)).status_code == 422


@pytest.mark.parametrize(
    "cursor", ["!!!", encode_cursor(["x"]), encode_cursor(["2026-01-01", "k"])]
)
async def test_malware_bad_cursor_is_400(client: httpx.AsyncClient, cursor: str) -> None:
    assert (await client.get("/malware", params={"cursor": cursor})).status_code == 400


def test_host_of() -> None:
    assert host_of("http://192.0.2.50:8080/x.sh") == "192.0.2.50"
    assert host_of("ftp://Example.test/a") == "example.test"
    assert host_of("not a url") == ""
    assert host_of("http://[bad/x") == ""
    assert len(host_of("http://" + "a" * 600 + ".test/")) == 255


def test_malware_cursor_roundtrip() -> None:
    ts = datetime(2026, 10, 24, 10, 0, tzinfo=UTC)
    key = "0" * 32
    assert _parse_cursor(_cursor(ts, key)) == (ts, key)
    with pytest.raises(InvalidCursorError):
        _parse_cursor(encode_cursor(["2026-10-24T10:00:00", key]))  # naive timestamp

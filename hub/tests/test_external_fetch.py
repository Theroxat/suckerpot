"""The external source file, its licence guard and the fetcher (design M36 T2, X4).

No test reaches abuse.ch: bodies come from fixtures through ``httpx.MockTransport``.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from sqlalchemy import text

from hub.config import ConfigError, Settings
from hub.external_feed import fetch
from hub.external_feed.fetch import FetchError, parse_feodo_json, refresh
from hub.external_feed.sources import (
    FORBIDDEN_IDS,
    SOURCES_FILE,
    Source,
    SourceError,
    load_sources,
    selected,
)

from .conftest import Env, make_settings

HUB = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"


def feodo_row(ip: str, port: int | None = 443, malware: str | None = "Dridex") -> dict[str, Any]:
    row: dict[str, Any] = {
        "ip_address": ip,
        "port": port,
        "status": "online",
        "hostname": None,
        "as_number": 64500,
        "as_name": "EXAMPLE-AS",
        "country": "NL",
        "first_seen": "2026-10-30 10:00:00",
        "last_online": "2026-11-01",
        "malware": malware,
    }
    return row


FIXTURE = [
    feodo_row("203.0.113.45", 443),
    feodo_row("203.0.113.45", 8080),
    feodo_row("198.51.100.9", 447, malware="Mirai"),
    feodo_row("192.0.2.77", None, malware=None),
    feodo_row("2001:db8::45", 443),
]


def body(rows: list[Any] | dict[str, Any] | None = None) -> bytes:
    return json.dumps(FIXTURE if rows is None else rows).encode()


def source(**over: Any) -> Source:
    base: dict[str, Any] = {
        "id": "feodotracker",
        "name": "abuse.ch Feodo Tracker",
        "licence": "CC0-1.0",
        "publish": True,
        "url": FEODO_URL,
        "page": "https://feodotracker.abuse.ch/blocklist/",
        "format": "feodo-json",
        "max_bytes": 4096,
        "min_count": 2,
    }
    return Source(**{**base, **over})


def client_for(handler: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)


def ok(content: bytes) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == FEODO_URL
        assert request.headers["user-agent"] == "Mozilla/5.0 (compatible)"
        return httpx.Response(200, content=content)

    return handler


def write_sources(tmp_path: Path, **over: Any) -> Path:
    entry: dict[str, Any] = {
        "id": "feodotracker",
        "name": "x",
        "licence": "CC0-1.0",
        "publish": True,
        "url": FEODO_URL,
        "format": "feodo-json",
        "max_bytes": 1000,
        "min_count": 1,
    }
    entry.update(over)
    path = tmp_path / "external.yaml"
    path.write_text(yaml.safe_dump({"sources": [entry]}))
    return path


# --- the source file and its licence guard ----------------------------------------------------


def test_the_shipped_source_is_feodo_tracker_cc0() -> None:
    sources = load_sources()
    assert [s.id for s in sources] == ["feodotracker"]
    feodo = sources[0]
    assert feodo.licence == "CC0-1.0" and feodo.publish is True
    assert feodo.url == FEODO_URL and feodo.host == "feodotracker.abuse.ch"
    assert 0 < feodo.max_bytes <= 8 * 1024 * 1024 and feodo.min_count >= 1


def test_the_shipped_file_names_no_restricted_source() -> None:
    doc = yaml.safe_load(SOURCES_FILE.read_text())
    for raw in doc["sources"]:
        assert raw["id"] not in FORBIDDEN_IDS
        host = raw["url"].split("/")[2].lower()
        assert not any(w in host for w in ("urlhaus", "threatfox", "bazaar"))
        assert raw["publish"] is False or raw["licence"] == "CC0-1.0"


@pytest.mark.parametrize("sid", ["urlhaus", "threatfox", "malwarebazaar", "URLhaus", "my-urlhaus"])
@pytest.mark.parametrize("publish", [True, False])
def test_restricted_ids_are_refused_whatever_the_flags(
    tmp_path: Path, sid: str, publish: bool
) -> None:
    path = write_sources(tmp_path, id=sid, publish=publish)
    with pytest.raises(SourceError, match="forbidden_source"):
        load_sources(path)


@pytest.mark.parametrize(
    "url",
    [
        "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "https://threatfox.abuse.ch/export/json/recent/",
        "https://bazaar.abuse.ch/export/",
        "https://urlhaus-api.abuse.ch/v1/urls/recent/",
    ],
)
def test_restricted_hosts_are_refused_under_a_harmless_id(tmp_path: Path, url: str) -> None:
    with pytest.raises(SourceError, match="forbidden_source"):
        load_sources(write_sources(tmp_path, id="feodotracker", url=url, publish=False))


def test_publish_needs_cc0(tmp_path: Path) -> None:
    for licence in ("proprietary", "CC-BY-4.0", "", "cc0-1.0"):
        with pytest.raises(SourceError, match="not_cc0"):
            load_sources(write_sources(tmp_path, licence=licence))
    # A source that is not published may declare another licence (it is never republished)...
    sources = load_sources(write_sources(tmp_path, licence="proprietary", publish=False))
    assert sources[0].publish is False
    # ...but it can never be selected for publication.
    with pytest.raises(SourceError, match="unknown_source"):
        selected(("feodotracker",), write_sources(tmp_path, licence="proprietary", publish=False))


@pytest.mark.parametrize(
    "url",
    [
        "http://feodotracker.abuse.ch/x.json",
        "https://user:pw@feodotracker.abuse.ch/x.json",
        "https://feodotracker.abuse.ch:8443/x.json",
        "https://feodotracker.abuse.ch/x.json?k=1",
    ],
)
def test_source_url_must_be_plain_https(tmp_path: Path, url: str) -> None:
    with pytest.raises(SourceError, match="bad_url"):
        load_sources(write_sources(tmp_path, url=url))


def test_selected_refuses_unknown_names() -> None:
    assert [s.id for s in selected(("feodotracker",))] == ["feodotracker"]
    with pytest.raises(SourceError):
        selected(("sslbl",))


def test_config_refuses_restricted_sources_even_when_off() -> None:
    for name in ("urlhaus", "threatfox", "malwarebazaar"):
        with pytest.raises(ConfigError, match="HUB_EXTERNAL_SOURCES"):
            Settings.from_env({"HUB_EXTERNAL_SOURCES": f"feodotracker,{name}"})


def test_config_defaults_and_guards() -> None:
    s = Settings.from_env({})
    assert (s.external_feed_mode, s.external_sources, s.external_interval_min) == (
        "off",
        ("feodotracker",),
        60,
    )
    with pytest.raises(ConfigError):
        Settings.from_env({"HUB_EXTERNAL_FEED_MODE": "on"})
    with pytest.raises(ConfigError, match="HUB_FEED_MODE"):
        Settings.from_env({"HUB_EXTERNAL_FEED_MODE": "publish"})
    with pytest.raises(ConfigError):
        Settings.from_env({"HUB_EXTERNAL_INTERVAL_MIN": "10"})
    with pytest.raises(ConfigError):
        Settings.from_env({"HUB_EXTERNAL_FEED_MODE": "publish", "HUB_FEED_MODE": "review",
                           "HUB_EXTERNAL_SOURCES": "nope"})  # fmt: skip
    ok_env = {"HUB_EXTERNAL_FEED_MODE": "publish", "HUB_FEED_MODE": "review"}
    assert Settings.from_env(ok_env).external_feed_mode == "publish"


# --- parsing ----------------------------------------------------------------------------------


def test_feodo_rows_are_merged_canonical_and_sorted() -> None:
    rows = parse_feodo_json(body(), allow_documentation=True)
    assert {r.value for r in rows} == {
        "192.0.2.77",
        "198.51.100.9",
        "203.0.113.45",
        "2001:db8::45",
    }
    by = {r.value: r for r in rows}
    assert by["203.0.113.45"].ports == (443, 8080) and by["203.0.113.45"].family == 4
    assert by["2001:db8::45"].family == 6 and by["192.0.2.77"].ports == ()
    assert by["198.51.100.9"].families == ("mirai",)  # only names the protocol knows
    assert by["203.0.113.45"].families == ()  # "Dridex" is not a v1 family


def test_the_wrapped_form_is_accepted() -> None:
    rows = parse_feodo_json(body({"blocklist": FIXTURE}), allow_documentation=True)
    assert len(rows) == 4


def test_documentation_and_private_addresses_need_the_flag_or_are_dropped() -> None:
    assert parse_feodo_json(body()) == []  # documentation ranges are not global
    private = ".".join(("10", "1", "2", "3"))
    rows = parse_feodo_json(body([feodo_row(private), feodo_row("8.8.4.4")]))
    assert [r.value for r in rows] == ["8.8.4.4"]


@pytest.mark.parametrize(
    "bad",
    [
        b"not json",
        b"{}",
        b'"text"',
        json.dumps([1]).encode(),
        json.dumps([{"port": 1}]).encode(),
        json.dumps([{"ip_address": 7}]).encode(),
        json.dumps([{"ip_address": "not-an-ip"}]).encode(),
        json.dumps([{"ip_address": "203.0.113.1", "port": "443"}]).encode(),
        json.dumps([{"ip_address": "203.0.113.1", "port": 70000}]).encode(),
        json.dumps([{"ip_address": "203.0.113.1", "port": True}]).encode(),
        json.dumps([{"ip_address": "203.0.113.1", "malware": 5}]).encode(),
    ],
)
def test_malformed_input_is_refused(bad: bytes) -> None:
    with pytest.raises(FetchError):
        parse_feodo_json(bad, allow_documentation=True)


def test_too_few_addresses_refuse_the_source() -> None:
    with pytest.raises(FetchError, match="too_few"):
        fetch.parse_source(source(min_count=10), body(), allow_documentation=True)


# --- download ---------------------------------------------------------------------------------


async def test_a_good_download_parses() -> None:
    async with client_for(ok(body())) as c:
        rows = await fetch.fetch_source(c, source(), allow_documentation=True)
    assert len(rows) == 4


@pytest.mark.parametrize(
    ("handler", "code"),
    [
        (
            lambda r: httpx.Response(302, headers={"location": "https://x.example.org/"}),
            "http_status",
        ),
        (lambda r: httpx.Response(404), "http_status"),
        (
            lambda r: httpx.Response(200, headers={"content-length": "999999"}, content=b"[]"),
            "too_large",
        ),
        (lambda r: httpx.Response(200, content=b"x" * 5000), "too_large"),
        (lambda r: httpx.Response(200, content=b"<html>"), "bad_json"),
    ],
)
async def test_bad_downloads_are_refused(handler: Any, code: str) -> None:
    async with client_for(handler) as c:
        with pytest.raises(FetchError, match=code):
            await fetch.fetch_source(c, source(), allow_documentation=True)


async def test_a_network_error_is_a_short_code() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("secret detail")

    async with client_for(boom) as c:
        with pytest.raises(FetchError) as exc:
            await fetch.fetch_source(c, source(), allow_documentation=True)
    assert str(exc.value) == "network"


# --- schedule and storage (database) ---------------------------------------------------------


def ext_settings(tmp_path: Path, **over: Any) -> Settings:
    return make_settings(
        feed_mode="auto",
        external_feed_mode="publish",
        feed_dir=str(tmp_path / "feeds"),
        **over,
    )


async def stored(env: Env) -> dict[str, Any]:
    async with env.worker() as ses:
        rows = (await ses.execute(text("SELECT * FROM external_entries"))).all()
    return {r.value: r for r in rows}


async def run(env: Env, s: Settings, handler: Any, now: datetime = NOW, **kw: Any) -> Any:
    async with client_for(handler) as c, env.worker() as ses:
        return await refresh(ses, s, now, client=c, sources=[source(max_bytes=65536)], **kw)


@pytest.mark.integration
async def test_mode_off_contacts_nothing(env: Env, tmp_path: Path) -> None:
    def never(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no request may be made")

    for s in (
        make_settings(feed_mode="auto"),
        make_settings(external_feed_mode="publish", feed_mode="off"),
    ):
        assert await run(env, s, never) == {}
    assert await stored(env) == {}


@pytest.mark.integration
async def test_success_stores_rows_and_state(env: Env, tmp_path: Path) -> None:
    s = ext_settings(tmp_path)
    assert await run(env, s, ok(body())) == {"feodotracker": "updated:4"}
    rows = await stored(env)
    assert set(rows) == {"203.0.113.45", "198.51.100.9", "192.0.2.77", "2001:db8::45"}
    assert rows["203.0.113.45"].first_seen == NOW.date() == rows["203.0.113.45"].last_seen
    async with env.worker() as ses:
        st = (await ses.execute(text("SELECT * FROM external_feed_state"))).one()
    assert st.last_ok_at == NOW and st.last_error is None and st.entry_count == 4


@pytest.mark.integration
async def test_interval_is_respected_and_first_seen_is_kept(env: Env, tmp_path: Path) -> None:
    s = ext_settings(tmp_path, external_interval_min=60)
    await run(env, s, ok(body()))
    assert await run(env, s, ok(body()), NOW + timedelta(minutes=30)) == {"feodotracker": "fresh"}
    later = NOW + timedelta(days=2)
    assert (await run(env, s, ok(body()), later))["feodotracker"] == "updated:4"
    row = (await stored(env))["203.0.113.45"]
    assert row.first_seen == NOW.date() and row.last_seen == later.date()


@pytest.mark.integration
async def test_an_address_the_source_dropped_leaves_within_one_cycle(
    env: Env, tmp_path: Path
) -> None:
    s = ext_settings(tmp_path)
    await run(env, s, ok(body()))
    changed = [FIXTURE[0], FIXTURE[2], FIXTURE[4], feodo_row("192.0.2.200")]
    await run(env, s, ok(body(changed)), NOW + timedelta(hours=2))
    assert set(await stored(env)) == {
        "203.0.113.45",
        "198.51.100.9",
        "2001:db8::45",
        "192.0.2.200",
    }


@pytest.mark.integration
@pytest.mark.parametrize(
    ("handler", "code"),
    [
        (
            lambda r: httpx.Response(302, headers={"location": "https://x.example.org/"}),
            "http_status",
        ),
        (lambda r: httpx.Response(200, content=b"x" * 70000), "too_large"),
        (lambda r: httpx.Response(200, content=b"[1]"), "bad_row"),
        (lambda r: httpx.Response(200, content=b"nope"), "bad_json"),
        (lambda r: httpx.Response(200, content=b"[]"), "too_few"),
        (lambda r: httpx.Response(500), "http_status"),
    ],
)
async def test_every_failure_keeps_the_last_good_copy(
    env: Env, tmp_path: Path, handler: Any, code: str
) -> None:
    s = ext_settings(tmp_path)
    await run(env, s, ok(body()))
    before = await stored(env)
    out = await run(env, s, handler, NOW + timedelta(hours=2))
    assert out == {"feodotracker": f"failed:{code}"}
    assert set(await stored(env)) == set(before)
    async with env.worker() as ses:
        st = (await ses.execute(text("SELECT * FROM external_feed_state"))).one()
    assert st.last_error == code and st.last_ok_at == NOW and st.entry_count == 4


@pytest.mark.integration
async def test_a_list_that_shrinks_over_half_is_refused(env: Env, tmp_path: Path) -> None:
    s = ext_settings(tmp_path)
    many = [feodo_row(f"203.0.113.{i}") for i in range(1, 41)]
    await run(env, s, ok(body(many)))
    out = await run(env, s, ok(body(many[:15])), NOW + timedelta(hours=2))
    assert out == {"feodotracker": "failed:shrunk"}
    assert len(await stored(env)) == 40
    out = await run(env, s, ok(body(many[:25])), NOW + timedelta(hours=4))
    assert out == {"feodotracker": "updated:25"}


# --- static: only the listed host ---------------------------------------------------------------


def test_the_fetcher_names_only_hosts_of_the_source_file() -> None:
    allowed = set(re.findall(r"https?://([A-Za-z0-9.-]+)", SOURCES_FILE.read_text()))
    for name in ("fetch.py", "sources.py", "job.py", "select.py", "readme.py"):
        source_text = (HUB / "hub" / "external_feed" / name).read_text()
        urls = set(re.findall(r"https?://([A-Za-z0-9.-]+)", source_text))
        assert urls <= allowed, (name, urls - allowed)


def test_the_fetcher_uses_no_credentials() -> None:
    text_ = (HUB / "hub" / "external_feed" / "fetch.py").read_text()
    assert "auth_key" not in text_.lower() and "abusech" not in text_.lower()

"""The CDN and Tor range fetcher (design M30 sections 5.3 and 7.4): bounded, fail closed."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import pytest
from sqlalchemy import text

from hub.feeds import external, job
from hub.feeds.external import RangesError, Source, load_sources, parse_prefixes, refresh

from .conftest import Env, make_settings

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
DOC = "https://lists.example.org/"


def src(**over: Any) -> Source:
    base: dict[str, Any] = {
        "name": "tor",
        "urls": (DOC + "a",),
        "format": "lines",
        "every_hours": 24,
        "max_bytes": 4096,
        "min_count": 2,
    }
    return Source(**{**base, **over})


def settings(**over: Any) -> Any:
    return make_settings(feed_mode="auto", **over)


# --- the configured sources ---------------------------------------------------------------------


def test_the_shipped_sources_are_well_formed() -> None:
    sources = load_sources()
    names = {s.name for s in sources}
    assert "tor" in names and any(n.startswith("cdn:") for n in names)
    for s in sources:
        assert s.name == "tor" or s.name.startswith("cdn:")
        assert s.urls and all(urlsplit(u).scheme == "https" for u in s.urls)
        assert 0 < s.max_bytes <= 32 * 1024 * 1024 and s.min_count > 0


def test_a_source_url_must_be_plain_https(tmp_path: Path) -> None:
    for bad in (
        "http://x.example.org/a",
        "https://u:p@x.example.org/a",
        "https://x.example.org/a?k=1",
    ):
        f = tmp_path / "r.yaml"
        f.write_text(
            f"sources:\n  - name: tor\n    urls: ['{bad}']\n    format: lines\n"
            "    every_hours: 24\n    max_bytes: 10\n    min_count: 1\n"
        )
        with pytest.raises(ValueError):
            load_sources(f)


# --- parsing ------------------------------------------------------------------------------------


def test_lines_are_canonical_unique_and_sorted() -> None:
    body = b"# a comment\n198.51.100.9\n\n203.0.113.0/24  # trailing\n198.51.100.9\n2001:db8::/32\n"
    assert parse_prefixes(src(), [body]) == ["198.51.100.9/32", "2001:db8::/32", "203.0.113.0/24"]


@pytest.mark.parametrize(
    ("body", "code"),
    [
        (b"0.0.0.0/0\n198.51.100.1\n", "prefix_too_wide"),
        (b"2001:db8::/8\n198.51.100.1\n", "prefix_too_wide"),
        (b"198.51.100.1\nnot-an-address\n", "bad_prefix"),
        (b"198.51.100.1\n", "too_few"),
        (b"\xff\xfe\n", "bad_encoding"),
    ],
)
def test_a_bad_list_is_refused_as_a_whole(body: bytes, code: str) -> None:
    with pytest.raises(RangesError, match=code):
        parse_prefixes(src(), [body])


def test_json_paths_filter_by_field() -> None:
    s = src(
        format="json",
        json_paths=(
            external.JsonPath("prefixes", "ip_prefix", (("service", "CLOUDFRONT"),)),
            external.JsonPath("addresses"),
        ),
    )
    body = json.dumps(
        {
            "prefixes": [
                {"ip_prefix": "198.51.100.0/24", "service": "CLOUDFRONT"},
                {"ip_prefix": "192.0.2.0/24", "service": "EC2"},
            ],
            "addresses": ["203.0.113.0/24"],
        }
    ).encode()
    assert parse_prefixes(s, [body]) == ["198.51.100.0/24", "203.0.113.0/24"]
    with pytest.raises(RangesError, match="bad_json"):
        parse_prefixes(s, [b'{"prefixes": 3, "addresses": []}'])
    with pytest.raises(RangesError, match="bad_json"):
        parse_prefixes(s, [b"[]"])


# --- fetching and storing -----------------------------------------------------------------------


def lines(count: int) -> bytes:
    return "".join(f"198.51.100.{i}\n" for i in range(1, count + 1)).encode()


def fake_ranges_transport(
    overrides: dict[str, Callable[[], httpx.Response]] | None = None,
) -> httpx.MockTransport:
    """Answers every shipped source with small documentation-range data."""
    tor = "".join(f"203.0.113.{i}\n" for i in range(1, 201)).encode()
    cloudflare = b"203.0.113.208/29\n203.0.113.216/29\n203.0.113.224/28\n203.0.113.240/29\n203.0.113.248/29\n"
    cloudflare6 = b"2001:db8:1::/48\n2001:db8:2::/48\n"
    fastly = json.dumps(
        {
            "addresses": [f"192.0.2.{i}/32" for i in range(200, 206)],
            "ipv6_addresses": ["2001:db8:3::/48"],
        }
    ).encode()
    cloudfront = json.dumps(
        {
            "prefixes": [
                {"ip_prefix": f"198.51.100.{i}/32", "service": "CLOUDFRONT"}
                for i in range(100, 130)
            ]
            + [{"ip_prefix": "203.0.113.250/32", "service": "AMAZON"}],
            "ipv6_prefixes": [{"ipv6_prefix": "2001:db8:4::/48", "service": "CLOUDFRONT"}],
        }
    ).encode()
    table = {
        "check.torproject.org": tor,
        "www.cloudflare.com/ips-v4": cloudflare,
        "www.cloudflare.com/ips-v6": cloudflare6,
        "api.fastly.com": fastly,
        "ip-ranges.amazonaws.com": cloudfront,
    }

    def handle(request: httpx.Request) -> httpx.Response:
        key = request.url.host + (
            request.url.path if request.url.host == "www.cloudflare.com" else ""
        )
        if overrides and request.url.host in overrides:
            return overrides[request.url.host]()
        return httpx.Response(200, content=table[key])

    return httpx.MockTransport(handle)


def client(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)


async def stored(env: Env, name: str) -> list[str]:
    async with env.worker() as s:
        rows = await s.execute(
            text("SELECT prefix FROM feed_auto_ranges WHERE source = :n ORDER BY prefix"),
            {"n": name},
        )
        return [r[0] for r in rows]


@pytest.mark.integration
async def test_every_shipped_source_is_stored_and_unlocks_the_feed_job(
    env: Env, feed_dir: Path, key_file: Path
) -> None:
    s = settings(feed_dir=str(feed_dir), feed_signing_key_file=str(key_file))
    async with env.worker() as ses:  # nothing stored: the feed job fails closed
        res = await job.run_once(ses, s, NOW, force=True)
        assert res.state == "failed" and res.error_code == "ranges_stale"
    async with (
        httpx.AsyncClient(transport=fake_ranges_transport()) as http,
        env.worker() as ses,
    ):
        out = await refresh(ses, s, NOW, client=http)
    assert set(out) == {x.name for x in load_sources()}
    assert all(v.startswith("updated:") for v in out.values()), out
    assert len(await stored(env, "tor")) == 200
    assert "203.0.113.250/32" not in await stored(env, "cdn:cloudfront")  # other services dropped
    async with env.worker() as ses:
        res = await job.run_once(ses, s, NOW, force=True)
        assert res.error_code != "ranges_stale"


@pytest.mark.integration
async def test_a_failed_fetch_keeps_the_last_copy_and_backs_off(env: Env) -> None:
    s = settings()
    source = src(min_count=2)
    calls: list[str] = []

    def ok(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=lines(5))

    def down(r: httpx.Request) -> httpx.Response:
        calls.append(str(r.url))
        return httpx.Response(503)

    async with env.worker() as ses:
        assert (await refresh(ses, s, NOW, client=client(ok), sources=[source]))[
            "tor"
        ] == "updated:5"
    later = NOW + timedelta(days=1, hours=1)
    async with env.worker() as ses:
        out = await refresh(ses, s, later, client=client(down), sources=[source])
        assert out["tor"] == "failed:http_status"
        again = await refresh(
            ses, s, later + timedelta(hours=1), client=client(down), sources=[source]
        )
        assert again["tor"] == "backoff"
        retry = await refresh(
            ses, s, later + timedelta(hours=7), client=client(down), sources=[source]
        )
        assert retry["tor"] == "failed:http_status"
    assert len(calls) == 2
    assert len(await stored(env, "tor")) == 5


@pytest.mark.integration
async def test_a_fresh_copy_is_not_fetched_again(env: Env) -> None:
    s = settings()
    source = src()
    calls: list[int] = []

    def ok(_r: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(200, content=lines(5))

    async with env.worker() as ses:
        await refresh(ses, s, NOW, client=client(ok), sources=[source])
        out = await refresh(ses, s, NOW + timedelta(hours=5), client=client(ok), sources=[source])
    assert out["tor"] == "fresh" and len(calls) == 1


@pytest.mark.integration
@pytest.mark.parametrize(
    ("answer", "code"),
    [
        (
            lambda: httpx.Response(302, headers={"location": "https://other.example.net/x"}),
            "http_status",
        ),
        (lambda: httpx.Response(200, content=b"x" * 5000), "too_large"),
        (lambda: httpx.Response(200, content=lines(3)), "shrunk"),
        (lambda: httpx.Response(200, content=b"0.0.0.0/0\n" + lines(30)), "prefix_too_wide"),
        (lambda: httpx.Response(200, content=b""), "too_few"),
    ],
)
async def test_bad_answers_change_nothing(
    env: Env, answer: Callable[[], httpx.Response], code: str
) -> None:
    s = settings()
    source = src(max_bytes=4096)
    async with env.worker() as ses:
        first = await refresh(
            ses,
            s,
            NOW,
            client=client(lambda _r: httpx.Response(200, content=lines(40))),
            sources=[source],
        )
        assert first["tor"] == "updated:40"
        out = await refresh(
            ses, s, NOW + timedelta(days=2), client=client(lambda _r: answer()), sources=[source]
        )
    assert out["tor"] == f"failed:{code}"
    assert len(await stored(env, "tor")) == 40


@pytest.mark.integration
async def test_a_stream_over_the_cap_without_content_length_is_cut(env: Env) -> None:
    async def body() -> Any:
        for _ in range(100):
            yield b"198.51.100.1\n" * 20

    def big(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body())

    async with env.worker() as ses:
        out = await refresh(ses, settings(), NOW, client=client(big), sources=[src(max_bytes=1000)])
    assert out["tor"] == "failed:too_large"


@pytest.mark.integration
async def test_nothing_is_contacted_when_off_or_disabled(env: Env) -> None:
    def boom(_r: httpx.Request) -> httpx.Response:
        raise AssertionError("no request expected")

    async with env.worker() as ses:
        for s in (make_settings(feed_mode="off"), settings(external_ranges_enabled=False)):
            assert await refresh(ses, s, NOW, client=client(boom), sources=[src()]) == {}


@pytest.mark.integration
async def test_one_source_never_fetched_stops_the_feed_job(
    env: Env, feed_dir: Path, key_file: Path
) -> None:
    """Security review M1: fresh copies of some sources must not hide that another one (here a
    CDN, then Tor) was never fetched. Its addresses would otherwise be published."""
    from .seed import shipped_ranges

    s = settings(feed_dir=str(feed_dir), feed_signing_key_file=str(key_file))
    await shipped_ranges(env.worker, NOW.date(), skip=frozenset({"cdn:fastly"}))
    async with env.worker() as ses:
        res = await job.run_once(ses, s, NOW, force=True)
    assert res.state == "failed" and res.error_code == "ranges_stale"
    async with env.worker() as ses:
        await ses.execute(text("DELETE FROM feed_auto_ranges"))
        await ses.commit()
    await shipped_ranges(env.worker, NOW.date(), skip=frozenset({"tor"}))
    async with env.worker() as ses:
        res = await job.run_once(ses, s, NOW, force=True)
    assert res.state == "failed" and res.error_code == "ranges_stale"
    await shipped_ranges(env.worker, NOW.date())
    async with env.worker() as ses:
        res = await job.run_once(ses, s, NOW, force=True)
    assert res.error_code != "ranges_stale"


@pytest.mark.integration
async def test_a_copy_older_than_thirty_days_stops_the_feed_job(
    env: Env, feed_dir: Path, key_file: Path
) -> None:
    s = settings(feed_dir=str(feed_dir), feed_signing_key_file=str(key_file))
    old = NOW.date() - timedelta(days=31)
    async with env.worker() as ses:
        await ses.execute(
            text("INSERT INTO feed_auto_ranges VALUES ('tor', '203.0.113.9/32', :d)"), {"d": old}
        )
        await ses.commit()
        res = await job.run_once(ses, s, NOW, force=True)
    assert res.state == "failed" and res.error_code == "ranges_stale"

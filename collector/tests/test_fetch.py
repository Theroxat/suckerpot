import gzip
import hashlib
import stat
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from suckerpot_egress import EgressClosed, egress_client

from collector import fetch as fx
from collector.config import CollectorSettings
from collector.fetch import Fetcher, FetchResult
from collector.store import Quarantine
from tests.fakes import FakeProxy, Reply, open_gate

HOST = "http://files.example.test"
BODY = b"#!/bin/sh\n# synthetic script\necho ok\n" * 20


def settings(**kw: object) -> CollectorSettings:
    base: dict[str, object] = {
        "max_bytes": 64 * 1024,
        "timeout_s": 5,
        "connect_timeout_s": 2,
        "max_redirects": 3,
        "host_interval_s": 0.0,
    }
    base.update(kw)
    return CollectorSettings(**base)  # type: ignore[arg-type]


@pytest.fixture
def q(tmp_path: Path) -> Quarantine:
    store = Quarantine(tmp_path / "q")
    store.prepare()
    return store


async def run(
    q: Quarantine,
    handler: Callable[[str, dict[str, str]], Reply],
    url: str,
    *,
    s: CollectorSettings | None = None,
    budget: int = 10**9,
    gate_open: bool = True,
) -> tuple[FetchResult, FakeProxy]:
    s = s or settings()
    proxy = FakeProxy(handler)
    async with proxy.running():
        gate = await open_gate(proxy.url, open_=gate_open)
        client = egress_client(
            gate,
            timeout=httpx.Timeout(s.timeout_s, connect=s.connect_timeout_s),
            verify=False,
        )
        async with client:
            result = await Fetcher(client, q, s).fetch(url, budget=budget)
    return result, proxy


async def test_download_is_stored_read_only_with_generic_headers(q: Quarantine) -> None:
    result, proxy = await run(q, lambda url, h: Reply(body=BODY), f"{HOST}/install.sh")
    assert result.outcome == fx.OK
    assert result.stored is not None
    assert result.stored.sha256 == hashlib.sha256(BODY).hexdigest()
    assert stat.S_IMODE(result.stored.path.stat().st_mode) == 0o400
    (url, headers) = proxy.seen[0]
    assert url == f"{HOST}/install.sh"
    assert headers["user-agent"] == "Wget/1.21.4"
    assert headers["accept-encoding"] == "identity"
    assert not {"cookie", "referer", "x-forwarded-for"} & headers.keys()
    assert "sucker" not in " ".join(headers.values()).lower()


async def test_content_encoding_is_stored_as_received(q: Quarantine) -> None:
    packed = gzip.compress(BODY)
    result, _ = await run(
        q, lambda u, h: Reply(body=packed, headers={"Content-Encoding": "gzip"}), f"{HOST}/a"
    )
    assert result.stored is not None
    assert result.stored.path.read_bytes() == packed  # never decompressed


async def test_redirect_chain_is_followed_by_hand(q: Quarantine) -> None:
    def handler(url: str, h: dict[str, str]) -> Reply:
        if url.endswith("/start"):
            return Reply(302, headers={"Location": "/mid"})
        if url.endswith("/mid"):
            return Reply(301, headers={"Location": "http://cdn.example.test/final"})
        return Reply(body=BODY)

    result, proxy = await run(q, handler, f"{HOST}/start")
    assert result.outcome == fx.OK
    assert result.redirects == 2
    assert [u for u, _ in proxy.seen] == [
        f"{HOST}/start",
        f"{HOST}/mid",
        "http://cdn.example.test/final",
    ]


@pytest.mark.parametrize(
    "location",
    ["http://127.0.0.1:9/x", "http://169.254.169.254/", "http://[::1]/", "http://3232235777/",
     "http://intranet/x", "http://printer.local/", "file:///etc/passwd"],
)  # fmt: skip
async def test_redirect_to_a_private_target_is_refused_and_never_requested(
    q: Quarantine, location: str
) -> None:
    result, proxy = await run(
        q, lambda u, h: Reply(302, headers={"Location": location}), f"{HOST}/x"
    )
    assert result.outcome == fx.REFUSED
    assert result.detail
    assert [u for u, _ in proxy.seen] == [f"{HOST}/x"]  # the second hop was never sent


async def test_redirect_limit(q: Quarantine) -> None:
    result, proxy = await run(
        q, lambda u, h: Reply(302, headers={"Location": "/again"}), f"{HOST}/x"
    )
    assert result.outcome == fx.REDIRECT_LIMIT
    assert len(proxy.seen) == 4  # first request plus three hops


async def test_redirect_without_location(q: Quarantine) -> None:
    result, _ = await run(q, lambda u, h: Reply(302), f"{HOST}/x")
    assert result.outcome == fx.BAD_REDIRECT


async def test_start_url_is_validated_before_any_request(q: Quarantine) -> None:
    result, proxy = await run(
        q,
        lambda u, h: Reply(body=BODY),
        "http://10.0.0.5/x",  # gitleaks:allow
    )
    assert result.outcome == fx.REFUSED
    assert result.detail == "ip_forbidden"
    assert proxy.seen == []


async def test_body_over_the_cap_is_cut_and_cleaned_up(q: Quarantine) -> None:
    big = b"A" * (200 * 1024)
    result, _ = await run(q, lambda u, h: Reply(body=big, chunked=True), f"{HOST}/big")
    assert result.outcome == fx.TOO_LARGE
    assert list(q.incoming.iterdir()) == []
    assert [p for p in q.root.rglob("*") if p.is_file()] == []


async def test_a_short_content_length_cannot_smuggle_more_bytes(q: Quarantine) -> None:
    big = b"B" * (200 * 1024)
    result, _ = await run(q, lambda u, h: Reply(body=big, declared_length=10), f"{HOST}/lie")
    # The size is what was actually read, and it never goes past the cap.
    assert result.stored is None or result.stored.size <= 64 * 1024


async def test_declared_oversize_is_refused_early(q: Quarantine) -> None:
    result, _ = await run(q, lambda u, h: Reply(body=b"x", declared_length=10**9), f"{HOST}/huge")
    assert result.outcome == fx.TOO_LARGE


async def test_quarantine_budget_stops_the_download(q: Quarantine) -> None:
    result, _ = await run(q, lambda u, h: Reply(body=BODY), f"{HOST}/a", budget=100)
    assert result.outcome == fx.QUARANTINE_FULL
    assert list(q.incoming.iterdir()) == []
    none, proxy = await run(q, lambda u, h: Reply(body=BODY), f"{HOST}/a", budget=0)
    assert none.outcome == fx.QUARANTINE_FULL
    assert proxy.seen == []


@pytest.mark.parametrize(
    ("status", "outcome"),
    [
        (404, fx.HTTP_4XX),
        (403, fx.HTTP_4XX),
        (410, fx.HTTP_4XX),
        (500, fx.HTTP_5XX),
        (503, fx.HTTP_5XX),
    ],
)
async def test_http_errors(q: Quarantine, status: int, outcome: str) -> None:
    result, _ = await run(q, lambda u, h: Reply(status, body=b"nope"), f"{HOST}/x")
    assert result.outcome == outcome
    assert result.stored is None  # failure bodies are not kept
    assert outcome in fx.RETRYABLE or outcome == fx.HTTP_4XX


async def test_empty_body(q: Quarantine) -> None:
    result, _ = await run(q, lambda u, h: Reply(body=b""), f"{HOST}/empty")
    assert result.outcome == fx.EMPTY


async def test_total_time_is_capped(q: Quarantine) -> None:
    s = settings(timeout_s=5)
    object.__setattr__(s, "timeout_s", 1)
    result, _ = await run(q, lambda u, h: Reply(body=BODY, delay=3), f"{HOST}/slow", s=s)
    assert result.outcome == fx.TIMEOUT
    assert list(q.incoming.iterdir()) == []


async def test_dead_proxy_is_a_network_error(q: Quarantine) -> None:
    proxy = FakeProxy(lambda u, h: Reply())
    async with proxy.running():
        gate = await open_gate(proxy.url)
    # the proxy is stopped now: connection refused
    s = settings()
    async with egress_client(gate, timeout=httpx.Timeout(2.0)) as client:
        result = await Fetcher(client, q, s).fetch(f"{HOST}/x", budget=10**9)
    assert result.outcome == fx.NETWORK


async def test_closed_gate_sends_nothing_and_raises(q: Quarantine) -> None:
    proxy = FakeProxy(lambda u, h: Reply(body=BODY))
    async with proxy.running():
        gate = await open_gate(proxy.url, open_=False)
        async with egress_client(gate, timeout=httpx.Timeout(2.0)) as client:
            with pytest.raises(EgressClosed):
                await Fetcher(client, q, settings()).fetch(f"{HOST}/x", budget=10**9)
    assert proxy.seen == []
    assert list(q.incoming.iterdir()) == []


async def test_gate_closing_mid_redirect_stops_the_chain(q: Quarantine) -> None:
    proxy = FakeProxy(lambda u, h: Reply(302, headers={"Location": "/next"}))
    async with proxy.running():
        gate = await open_gate(proxy.url)

        def close_after_first(url: str, h: dict[str, str]) -> Reply:
            gate._status = type(gate._status)(False, "tunnel_down", None, gate._status.checked_at)
            return Reply(302, headers={"Location": "/next"})

        proxy.handler = close_after_first
        async with egress_client(gate, timeout=httpx.Timeout(2.0)) as client:
            with pytest.raises(EgressClosed):
                await Fetcher(client, q, settings()).fetch(f"{HOST}/x", budget=10**9)
    assert len(proxy.seen) == 1

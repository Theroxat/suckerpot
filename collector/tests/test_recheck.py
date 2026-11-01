"""Takedown re-checks (M27): schedule, classification and the single bounded GET.

The fake proxy is also the origin (127.0.0.1 only): nothing leaves the test process.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from suckerpot_egress import EgressClosed, egress_client

from collector import recheck as rc
from collector.config import CollectorSettings
from collector.recheck import (
    Probe,
    ProxySideError,
    classify_body,
    next_http_at,
    outcome_for_status,
    probe,
)
from collector.store import Quarantine
from tests.fakes import FakeProxy, Reply, open_gate

HOST = "http://files.example.test"
BODY = b"#!/bin/sh\n# synthetic payload\necho one\n" * 10
OTHER = b"#!/bin/sh\n# a different synthetic payload\necho two\n" * 10
SHA = hashlib.sha256(BODY).hexdigest()
T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


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


def leftovers(q: Quarantine) -> list[Path]:
    """Every file under the quarantine root, the .incoming directory included."""
    return [p for p in q.root.rglob("*") if p.is_file()]


async def run(
    q: Quarantine,
    handler: Callable[[str, dict[str, str]], Reply],
    url: str = f"{HOST}/install.sh",
    *,
    prev_sha: str | None = SHA,
    prev_kind: str | None = "script",
    budget: int = 10**9,
    s: CollectorSettings | None = None,
    gate_open: bool = True,
) -> tuple[Probe, FakeProxy]:
    s = s or settings()
    proxy = FakeProxy(handler)
    async with proxy.running():
        gate = await open_gate(proxy.url, open_=gate_open)
        client = egress_client(
            gate, timeout=httpx.Timeout(s.timeout_s, connect=s.connect_timeout_s), verify=False
        )
        async with client:
            result = await probe(
                client, q, s, url, prev_sha=prev_sha, prev_kind=prev_kind, budget=budget
            )
    return result, proxy


# ---- schedule (pure, fixed clocks) --------------------------------------------------------------


def test_the_schedule_walks_the_offsets_then_goes_daily() -> None:
    rep = T0
    step, at = next_http_at(0, rep, "up", rep)  # baseline ran at the report time
    assert (step, at) == (1, rep + timedelta(hours=1))
    step, at = next_http_at(1, rep, "up", rep + timedelta(hours=1))
    assert (step, at) == (2, rep + timedelta(hours=6))
    step, at = next_http_at(3, rep, "up", rep + timedelta(hours=24, minutes=1))
    assert (step, at) == (4, rep + timedelta(hours=48))
    now = rep + timedelta(hours=48, minutes=2)
    step, at = next_http_at(4, rep, "up", now)
    assert (step, at) == (5, now + timedelta(hours=24))
    step, at = next_http_at(5, rep, "up", at)
    assert step == 6


def test_a_down_target_is_rechecked_every_72_hours() -> None:
    now = T0 + timedelta(days=10)
    assert next_http_at(7, T0, "down", now) == (8, now + timedelta(hours=72))
    assert next_http_at(7, T0, "changed", now)[1] == now + timedelta(hours=24)


def test_a_late_target_gets_one_baseline_then_the_next_future_slot() -> None:
    reported = T0 - timedelta(hours=10)  # slots 0, 1 and 2 are already past
    step, at = next_http_at(0, reported, "unknown", T0)
    assert (step, at) == (3, reported + timedelta(hours=24))
    old = T0 - timedelta(days=9)  # every slot is past: straight to the daily rhythm
    step, at = next_http_at(0, old, "unknown", T0)
    assert at == T0 + timedelta(hours=24) and step >= len(rc.HTTP_OFFSETS)


def test_the_step_counter_stays_small() -> None:
    step, _ = next_http_at(rc.MAX_STEP, T0, "up", T0 + timedelta(days=90))
    assert step == rc.MAX_STEP


# ---- classification (pure) ----------------------------------------------------------------------


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_classify_body_table() -> None:
    assert classify_body(SHA, SHA, BODY[:512], len(BODY), "script") == rc.SAME
    assert classify_body(SHA, sha(b""), b"", 0, "script") == rc.EMPTY
    assert classify_body(SHA, sha(OTHER), OTHER[:512], len(OTHER), "script") == rc.CHANGED
    assert (
        classify_body(SHA, sha(OTHER), OTHER[:512], len(OTHER), "script", room=False)
        == rc.CHANGED_NOT_STORED
    )
    page = b"<!DOCTYPE HTML><html><body>This account has been suspended</body></html>"
    assert classify_body(SHA, sha(page), page, len(page), "script") == rc.SUSPENDED
    assert classify_body(SHA, sha(page), page, len(page), "html") == rc.CHANGED
    assert classify_body(None, sha(OTHER), OTHER, len(OTHER), None) == rc.CHANGED


@pytest.mark.parametrize(
    ("status", "outcome"),
    [
        (404, "http_404"),
        (410, "http_410"),
        (403, "http_4xx"),
        (500, "http_5xx"),
        (304, "bad_redirect"),
    ],
)
def test_status_outcomes(status: int, outcome: str) -> None:
    assert outcome_for_status(status) == outcome


# ---- the one bounded GET ------------------------------------------------------------------------


async def test_same_hash_leaves_nothing_in_quarantine(q: Quarantine) -> None:
    result, proxy = await run(q, lambda u, h: Reply(body=BODY))
    assert result.outcome == rc.SAME
    assert result.sha256 == SHA and result.stored is None
    assert leftovers(q) == []  # .incoming included
    assert len(proxy.seen) == 1


async def test_changed_file_is_committed_read_only(q: Quarantine) -> None:
    result, _ = await run(q, lambda u, h: Reply(body=OTHER))
    assert result.outcome == rc.CHANGED
    assert result.stored is not None
    assert result.stored.sha256 == sha(OTHER)
    assert result.stored.path.read_bytes() == OTHER
    assert result.stored.path.stat().st_mode & 0o777 == 0o400
    assert [p for p in leftovers(q)] == [result.stored.path]


async def test_a_suspended_page_is_not_stored(q: Quarantine) -> None:
    page = b"<html><head><title>Suspended</title></head></html>"
    result, _ = await run(q, lambda u, h: Reply(body=page))
    assert result.outcome == rc.SUSPENDED
    assert result.stored is None
    assert leftovers(q) == []


async def test_a_full_quarantine_hashes_without_writing(q: Quarantine) -> None:
    result, _ = await run(q, lambda u, h: Reply(body=OTHER), budget=0)
    assert result.outcome == rc.CHANGED_NOT_STORED
    assert result.sha256 == sha(OTHER)
    assert leftovers(q) == []
    # Room for a few bytes only: same result, and the temp file is gone.
    result, _ = await run(q, lambda u, h: Reply(body=OTHER), budget=16)
    assert result.outcome == rc.CHANGED_NOT_STORED
    assert leftovers(q) == []


async def test_oversize_is_up_unhashed(q: Quarantine) -> None:
    big = b"A" * (80 * 1024)
    result, _ = await run(q, lambda u, h: Reply(body=big, chunked=True))
    assert result.outcome == rc.UP_UNHASHED
    assert result.sha256 is None and result.stored is None
    assert leftovers(q) == []


async def test_empty_body(q: Quarantine) -> None:
    result, _ = await run(q, lambda u, h: Reply(body=b""))
    assert result.outcome == rc.EMPTY
    assert leftovers(q) == []


@pytest.mark.parametrize(
    ("status", "outcome"),
    [(404, "http_404"), (410, "http_410"), (403, "http_4xx"), (503, "http_5xx")],
)
async def test_error_statuses(q: Quarantine, status: int, outcome: str) -> None:
    result, _ = await run(q, lambda u, h: Reply(status=status, body=b"gone"))
    assert result.outcome == outcome
    assert result.http_status == status
    assert leftovers(q) == []


async def test_redirect_to_a_private_address_is_refused(q: Quarantine) -> None:
    def handler(url: str, h: dict[str, str]) -> Reply:
        return Reply(302, headers={"Location": "http://10.0.0.5/x"})  # gitleaks:allow

    result, proxy = await run(q, handler)
    assert result.outcome == rc.REFUSED
    assert len(proxy.seen) == 1  # the private hop was never requested


async def test_redirect_limit_and_bad_redirect(q: Quarantine) -> None:
    result, _ = await run(q, lambda u, h: Reply(302, headers={"Location": "/again"}))
    assert result.outcome == rc.REDIRECT_LIMIT
    result, _ = await run(q, lambda u, h: Reply(302))
    assert result.outcome == rc.BAD_REDIRECT


async def test_generic_identity_and_no_extra_requests(q: Quarantine) -> None:
    result, proxy = await run(q, lambda u, h: Reply(body=BODY))
    (url, headers) = proxy.seen[0]
    assert url == f"{HOST}/install.sh"  # exactly the recorded URL, no other path
    assert headers["user-agent"] == "Wget/1.21.4"
    assert headers["accept-encoding"] == "identity"
    assert not {"cookie", "referer", "x-forwarded-for"} & headers.keys()
    assert "sucker" not in " ".join(headers.values()).lower()
    assert result.outcome == rc.SAME


async def test_a_slow_host_times_out(q: Quarantine) -> None:
    result, _ = await run(
        q, lambda u, h: Reply(body=BODY, delay=3.0), s=settings(timeout_s=1, connect_timeout_s=1)
    )
    assert result.outcome == rc.TIMEOUT


async def test_a_closed_gate_sends_nothing(q: Quarantine) -> None:
    proxy = FakeProxy(lambda u, h: Reply(body=BODY))
    async with proxy.running():
        gate = await open_gate(proxy.url, open_=False)
        client = egress_client(gate, timeout=httpx.Timeout(5.0), verify=False)
        async with client:
            with pytest.raises(EgressClosed):
                await probe(
                    client, q, settings(), f"{HOST}/a", prev_sha=SHA, prev_kind=None, budget=1
                )
    assert proxy.seen == []


async def test_a_dead_proxy_is_our_side_not_the_targets(q: Quarantine) -> None:
    gate = await open_gate("http://127.0.0.1:1")
    client = egress_client(gate, timeout=httpx.Timeout(2.0), verify=False)
    async with client:
        with pytest.raises(ProxySideError):
            await probe(client, q, settings(), f"{HOST}/a", prev_sha=SHA, prev_kind=None, budget=1)


async def test_connect_502_means_unreachable(q: Quarantine) -> None:
    result, _ = await run(q, lambda u, h: Reply(status=502), url="https://files.example.test/a")
    assert result.outcome == rc.UNREACHABLE


# ---- selection is confined to the eligible URLs -------------------------------------------------


async def test_the_selection_only_reads_eligible_urls() -> None:
    import inspect

    src = inspect.getsource(rc.Rechecker.due)
    assert "t.kind = 'url' AND t.http_eligible AND t.tracking AND NOT t.demo" in src
    assert "t.track_until > :now" in src
    for forbidden in ("'ip'", "'domain'", "'c2'", "attack_source"):
        assert forbidden not in src

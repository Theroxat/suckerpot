"""Listing checks: outcomes, quotas (own and share) and the closed gate. No network, no database."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from ingest.egress import EgressClosed
from ingest.enrichment.intel import IntelResult
from ingest.enrichment.reputation import AbuseResult, ProviderError
from ingest.takedown import listing
from ingest.takedown.config import TakedownSettings
from ingest.takedown.listing import (
    ListingChecker,
    abuseipdb_outcome,
    urlhaus_outcome,
)
from tests.helpers import fake_gate

NOW = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)
REPORTED = NOW - timedelta(hours=5)


class FakeIntel:
    def __init__(self, *, enabled: bool = True) -> None:
        self._enabled = enabled
        self.calls: list[tuple[str, str, str]] = []
        self.raises: Exception | None = None

    def enabled(self, provider: str) -> bool:
        return self._enabled

    def quota(self, provider: str) -> int:
        return 1000

    async def urlhaus(self, kind: str, value: str) -> IntelResult:
        self.calls.append(("urlhaus", kind, value))
        if self.raises:
            raise self.raises
        return IntelResult("urlhaus", True, url_status="online")

    async def threatfox(self, kind: str, value: str) -> IntelResult:
        self.calls.append(("threatfox", kind, value))
        return IntelResult("threatfox", True)


class FakeRep:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def enabled(self, provider: str) -> bool:
        return True

    def quota(self, provider: str) -> int:
        return 1000

    async def check_abuseipdb(self, ip: str) -> AbuseResult:
        self.calls.append(ip)
        return AbuseResult(40, 3, NOW - timedelta(hours=1))


def target(tid: int, role: str, kind: str, value: str) -> SimpleNamespace:
    return SimpleNamespace(
        id=tid, role=role, kind=kind, value=value, reported_at=REPORTED,
        track_until=REPORTED + timedelta(days=30), listing_step=0,
    )  # fmt: skip


class Harness:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, *, open_: bool = True) -> None:
        self.intel = FakeIntel()
        self.rep = FakeRep()
        self.reserved: list[str] = []
        self.refunded: list[str] = []
        self.recorded: list[tuple[int, str, str, dict[str, Any]]] = []
        self.exhausted: set[str] = set()
        self.rows: list[SimpleNamespace] = []
        self.checker = ListingChecker(
            None,  # type: ignore[arg-type]
            TakedownSettings(),
            self.intel,
            self.rep,
            fake_gate(open_=open_),
        )

        async def reserve(factory: Any, provider: str, limit: int) -> bool:
            if provider in self.exhausted:
                return False
            self.reserved.append(provider)
            return True

        async def refund(factory: Any, provider: str) -> None:
            self.refunded.append(provider)

        async def due(now: datetime, roles: list[str]) -> list[SimpleNamespace]:
            return [r for r in self.rows if r.role in roles]

        async def record(
            t: Any, method: str, outcome: str, detail: dict[str, Any], now: Any
        ) -> None:
            self.recorded.append((t.id, method, outcome, detail))

        monkeypatch.setattr(listing, "reserve_quota", reserve)
        monkeypatch.setattr(listing, "refund_quota", refund)
        monkeypatch.setattr(self.checker, "due", due)
        monkeypatch.setattr(self.checker, "_record", record)


def test_urlhaus_outcomes() -> None:
    assert urlhaus_outcome(IntelResult("urlhaus", False), NOW) == ("not_listed", {})
    assert urlhaus_outcome(IntelResult("urlhaus", True, url_status="online"), NOW)[0] == "online"
    gone = IntelResult("urlhaus", True, url_status="offline", last_online=NOW - timedelta(hours=12))
    assert urlhaus_outcome(gone, NOW) == ("offline", {"last_online_age_h": 12})
    assert urlhaus_outcome(IntelResult("urlhaus", True, url_status="unknown"), NOW)[0] == (
        "unknown_status"
    )


def test_abuseipdb_outcomes() -> None:
    after = AbuseResult(50, 9, REPORTED + timedelta(hours=1))
    assert abuseipdb_outcome(after, REPORTED) == ("reported_after", {"reports": 9})
    assert abuseipdb_outcome(AbuseResult(50, 9, REPORTED - timedelta(days=1)), REPORTED)[0] == (
        "quiet"
    )
    assert abuseipdb_outcome(AbuseResult(0, 0, None), REPORTED)[0] == "not_listed"


async def test_each_role_uses_the_right_lookup_and_both_quotas(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    h = Harness(monkeypatch)
    h.rows = [
        target(1, "payload_url", "url", "http://files.example.net/a.sh"),
        target(2, "payload_host", "ip", "198.51.100.7"),
        target(3, "c2", "ip", "203.0.113.9"),
        target(4, "attack_source", "ip", "192.0.2.44"),
    ]
    assert await h.checker.run(NOW) == 4
    assert h.intel.calls == [
        ("urlhaus", "url", "http://files.example.net/a.sh"),
        ("urlhaus", "ip", "198.51.100.7"),
        ("threatfox", "ip", "203.0.113.9"),
    ]
    assert h.rep.calls == ["192.0.2.44"]
    assert [(r[0], r[1], r[2]) for r in h.recorded] == [
        (1, "urlhaus", "online"),
        (2, "urlhaus", "online"),
        (3, "threatfox", "listed"),
        (4, "abuseipdb", "reported_after"),
    ]
    assert h.reserved.count("takedown_intel") == 3 and h.reserved.count("abusech") == 3
    assert h.reserved.count("takedown_abuseipdb") == 1 and h.reserved.count("abuseipdb") == 1


async def test_an_exhausted_share_quota_makes_no_call(monkeypatch: pytest.MonkeyPatch) -> None:
    h = Harness(monkeypatch)
    h.exhausted = {"takedown_intel"}
    h.rows = [target(1, "payload_url", "url", "http://files.example.net/a.sh")]
    assert await h.checker.run(NOW) == 0
    assert h.intel.calls == [] and h.recorded == []
    assert "abusech" not in h.reserved  # the provider's own quota is not touched


async def test_an_exhausted_provider_quota_gives_the_share_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    h = Harness(monkeypatch)
    h.exhausted = {"abusech"}
    h.rows = [target(1, "c2", "ip", "203.0.113.9")]
    assert await h.checker.run(NOW) == 0
    assert h.intel.calls == []
    assert h.refunded == ["takedown_intel"]


async def test_a_closed_gate_means_no_call_no_quota_no_row(monkeypatch: pytest.MonkeyPatch) -> None:
    h = Harness(monkeypatch, open_=False)
    h.rows = [target(1, "payload_url", "url", "http://files.example.net/a.sh")]
    assert await h.checker.run(NOW) == 0
    assert h.reserved == [] and h.intel.calls == [] and h.recorded == []


async def test_the_gate_closing_mid_call_refunds_and_writes_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    h = Harness(monkeypatch)
    h.intel.raises = EgressClosed("stale")
    h.rows = [target(1, "payload_url", "url", "http://files.example.net/a.sh")]
    assert await h.checker.run(NOW) == 0
    assert h.recorded == []
    assert sorted(h.refunded) == ["abusech", "takedown_intel"]


async def test_a_rejected_key_stops_the_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    h = Harness(monkeypatch)
    h.intel.raises = ProviderError("auth")
    h.rows = [
        target(1, "payload_url", "url", "http://files.example.net/a.sh"),
        target(2, "c2", "ip", "203.0.113.9"),
    ]
    await h.checker.run(NOW)
    assert len(h.intel.calls) == 1  # no second attempt with a rejected key
    assert h.checker.roles() == ["attack_source"]  # abuse.ch is out, AbuseIPDB stays
    assert h.checker._available("abuseipdb")


async def test_a_disabled_provider_is_skipped_without_blocking_the_other(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    h = Harness(monkeypatch)
    h.intel._enabled = False
    assert h.checker.roles() == ["attack_source"]
    h.rows = [target(4, "attack_source", "ip", "192.0.2.44")]
    assert await h.checker.run(NOW) == 1

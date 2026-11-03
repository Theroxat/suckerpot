"""Early reveals (N17), the verifier role (N18) and the multi-key answer check (N19)."""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from suckerpot_netproto import ProtoError, blind, sign
from suckerpot_netproto import models as wire

from ingest.features import FeatureSettings
from ingest.network import identity as ident
from ingest.network.builder import BatchBuilder
from ingest.network.client import HubClient, HubNoVerify, HubUnavailable
from ingest.network.verifier import (
    FetchView,
    StaleFetch,
    TaskRow,
    Verifier,
    local_refusal,
    outcome_of,
    result_item,
)
from ingest.network.worker import NetworkWorker

from .helpers import (
    HUB_KEY,
    NOW,
    SELF_IP,
    FakeGate,
    FakeHub,
    FakeTerms,
    MemoryStore,
    hub_client,
    make_terms,
    settings,
)
from .test_participant import BOX, CONSENT
from .test_worker import Src, member_store

URL = "http://198.51.100.9/x.sh"
URL_B = blind.blind("url", URL)
SELF_URL = f"http://{SELF_IP}/x.sh"
LEASE = (NOW + timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ")


def rig(store: MemoryStore, *, with_terms: bool = True, **kw: Any) -> tuple[NetworkWorker, FakeHub]:
    hub = FakeHub()
    terms = FakeTerms(make_terms(with_terms))
    worker = NetworkWorker(
        FeatureSettings(network_enabled=True),
        settings(**kw),
        store,
        terms,
        BatchBuilder(Src(), terms, allow_documentation=True),
        box=BOX,
        gate=FakeGate(True),  # type: ignore[arg-type]
        client=hub_client(hub),
        clock=lambda: NOW,
        rng=random.Random(2),  # noqa: S311
        allow_documentation=True,
    )
    return worker, hub


def reveal_calls(hub: FakeHub) -> list[tuple[str, str]]:
    return [c for c in hub.calls if c[1] in ("/v1/verify/reveals", "/v1/reveals")]


# -- N17: early reveals ----------------------------------------------------------------------------


async def test_reveals_only_the_listed_hashes_that_are_held() -> None:
    store = member_store()
    store.reveal_pool["url"] = [URL, "http://198.51.100.10/y.sh"]
    worker, hub = rig(store, verify_reveals=True)
    hub.verify_refs = [URL_B, blind.blind("url", "http://198.51.100.11/never-held")]
    await worker.run_once()
    sent = [b for b in hub.bodies if "items" in b and b["items"] and "value" in b["items"][0]]
    assert [i["value"] for b in sent for i in b["items"]] == [URL]
    assert worker.revealed == {NOW.date().isoformat(): 1}


async def test_nothing_listed_means_nothing_sent() -> None:
    store = member_store()
    store.reveal_pool["url"] = [URL]
    worker, hub = rig(store, verify_reveals=True)
    await worker.run_once()
    assert ("POST", "/v1/reveals") not in hub.calls and ("GET", "/v1/verify/reveals") in hub.calls


async def test_flag_off_asks_nothing() -> None:
    store = member_store()
    worker, hub = rig(store, verify_reveals=False)
    await worker.run_once()
    assert reveal_calls(hub) == []


async def test_participant_needs_the_item_in_the_consent() -> None:
    store = member_store()
    store.reveal_pool["url"] = [URL]
    plain = "v2:sources,payloads,c2,files,rechecks:2026-11-03"
    worker, hub = rig(store, stack_mode="participant", consent=plain, verify_reveals=True)
    hub.verify_refs = [URL_B]
    await worker.run_once()
    assert reveal_calls(hub) == []
    worker, hub = rig(store, stack_mode="participant", consent=CONSENT, verify_reveals=True)
    hub.verify_refs = [URL_B]
    await worker.run_once()
    assert ("POST", "/v1/reveals") in hub.calls


async def test_a_link_naming_the_own_address_is_never_revealed() -> None:
    store = member_store()
    store.reveal_pool["url"] = [SELF_URL, URL]
    worker, hub = rig(store, verify_reveals=True)
    hub.verify_refs = [blind.blind("url", SELF_URL), URL_B]
    await worker.run_once()
    values = [i["value"] for b in hub.bodies for i in b.get("items", []) if "value" in i]
    assert values == [URL]


async def test_without_a_known_own_address_nothing_is_revealed() -> None:
    store = member_store()
    store.reveal_pool["url"] = [URL]
    worker, hub = rig(store, with_terms=False, verify_reveals=True)
    hub.verify_refs = [URL_B]
    await worker.run_once()
    assert reveal_calls(hub) == []


async def test_a_pre_m32_hub_is_asked_once_a_day() -> None:
    store = member_store()
    worker, hub = rig(store, verify_reveals=True)
    hub.no_verify = True
    await worker.run_once()
    await worker.run_once()
    assert reveal_calls(hub).count(("GET", "/v1/verify/reveals")) == 1
    assert worker.last_error is None and store.m.last_error_code is None


# -- N19: pinned key set ---------------------------------------------------------------------------


def client_for(hub: FakeHub, keys: str) -> HubClient:
    return HubClient(
        settings(hub_key=keys), ident.generate(), gate=FakeGate(True),  # type: ignore[arg-type]
        client=hub_client(hub), clock=lambda: NOW.timestamp(),
    )  # fmt: skip


ALT_SEED = bytes(range(64, 96))
ALT_KEY = sign.node_key(sign.public_key_of(ALT_SEED))


async def test_either_header_may_verify_under_any_pinned_key() -> None:
    hub = FakeHub()
    hub.alt_seed, hub.primary_signs = ALT_SEED, False  # only the alternate header is valid
    assert (await client_for(hub, f"{HUB_KEY},{ALT_KEY}").info()).hub_key == HUB_KEY
    with pytest.raises(ProtoError):  # a set without the alternate key rejects it
        await client_for(hub, HUB_KEY).info()


async def test_an_answer_signed_by_an_unpinned_key_is_refused() -> None:
    hub = FakeHub()
    hub.bad_signature = True
    with pytest.raises(ProtoError):
        await client_for(hub, f"{HUB_KEY},{ALT_KEY}").info()


async def test_the_info_key_must_be_in_the_pinned_set() -> None:
    store = MemoryStore(desired="member")
    other = sign.node_key(sign.public_key_of(bytes(range(1, 33))))
    worker, hub = rig(store, hub_key=f"{other},{ALT_KEY}")
    await worker.run_once()
    assert store.m.state in ("error", "enrolling") and not hub.enrolled


def test_more_than_three_pinned_keys_are_refused() -> None:
    from ingest.network.config import NetworkSettings

    keys = [sign.node_key(sign.public_key_of(bytes([i] * 32))) for i in range(1, 5)]
    with pytest.raises(ValueError):
        NetworkSettings.from_env(
            {"NETWORK_HUB_URL": "https://hub.example.org", "NETWORK_HUB_KEY": ",".join(keys)}
        )
    ok = NetworkSettings.from_env(
        {"NETWORK_HUB_URL": "https://hub.example.org", "NETWORK_HUB_KEY": ",".join(keys[:3])}
    )
    assert ok.hub_keys == tuple(keys[:3])


# -- N18: the verifier role ------------------------------------------------------------------------


class MemoryVerifyStore:
    def __init__(self) -> None:
        self.tasks: dict[str, TaskRow] = {}
        self.targets: dict[str, int] = {}
        self.views: dict[int, FetchView] = {}
        self.queued: list[tuple[str, str, str]] = []
        self.stale: set[str] = set()

    async def open_tasks(self) -> list[TaskRow]:
        return [
            t for t in self.tasks.values()
            if t.reported_at is None and t.state != "reported"
        ]  # fmt: skip

    async def has_task(self, hub_id: str) -> bool:
        return hub_id in self.tasks

    async def add_task(self, row: TaskRow) -> None:
        self.tasks.setdefault(row.hub_id, row)

    async def update_task(self, hub_id: str, **values: Any) -> None:
        for k, v in values.items():
            setattr(self.tasks[hub_id], k, v)

    async def queue_fetch(self, url: str, host: str, scheme: str, now: datetime) -> int | None:
        if url in self.stale:
            raise StaleFetch
        self.queued.append((url, host, scheme))
        return self.targets.setdefault(url, len(self.targets) + 1)

    async def fetch_view(self, target_id: int) -> FetchView | None:
        return self.views.get(target_id)

    async def count_since(self, since: datetime, host: str | None = None) -> int:
        return sum(
            1 for t in self.tasks.values()
            if t.received_at >= since and t.state in ("queued", "done", "reported")
            and (host is None or t.host == host)
        )  # fmt: skip

    async def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for t in self.tasks.values():
            out[t.state] = out.get(t.state, 0) + 1
        return out


def task(n: int, url: str | None = None) -> dict[str, str]:
    return {"id": f"v_{n:012x}", "url": url or f"http://198.51.100.{n}/x.sh", "lease_until": LEASE}


class Rigged:
    def __init__(self, **kw: Any) -> None:
        base: dict[str, Any] = {"verifier": True, "collector_enabled": True, "egress_mode": "vpn"}
        base.update(kw)
        self.store = MemoryVerifyStore()
        self.hub = FakeHub()
        self.now = NOW
        self.gate = FakeGate(True)
        self.terms = FakeTerms(make_terms())
        self.verifier = Verifier(
            settings(**base), self.store, self.terms,
            gate=self.gate, clock=lambda: self.now,  # type: ignore[arg-type]
        )  # fmt: skip
        self.client = HubClient(
            settings(**base), ident.generate(), gate=self.gate,  # type: ignore[arg-type]
            client=hub_client(self.hub), clock=lambda: NOW.timestamp(),
        )  # fmt: skip

    async def cycle(self) -> str:
        return await self.verifier.cycle(self.client)

    def results(self) -> list[dict[str, Any]]:
        return [
            i for b in self.hub.bodies if b.get("items") and "outcome" in b["items"][0]
            for i in b["items"]
        ]  # fmt: skip


@pytest.mark.parametrize(
    ("kw", "state"),
    [
        ({"verifier": False}, "off"),
        ({"egress_mode": "direct"}, "verifier_needs_vpn"),
        ({"collector_enabled": False}, "verifier_needs_collector"),
    ],
)
async def test_the_role_refuses_without_its_preconditions(kw: dict[str, Any], state: str) -> None:
    r = Rigged(**kw)
    r.hub.verify_tasks = [task(1)]
    assert await r.cycle() == state
    assert r.hub.calls == [] and r.store.queued == []


async def test_a_closed_gate_leases_nothing() -> None:
    r = Rigged()
    r.gate.open = False
    assert await r.cycle() == "egress_closed"
    assert r.hub.calls == []


async def test_a_task_becomes_a_depth_zero_fetch_and_is_reported() -> None:
    r = Rigged()
    r.hub.verify_tasks = [task(1)]
    assert await r.cycle() == "ok"
    assert r.store.queued == [("http://198.51.100.1/x.sh", "198.51.100.1", "http")]
    assert r.results() == []  # nothing to report before the collector finished
    r.store.views[1] = FetchView(
        "fetched", sha256="a" * 64, size=48213, kind="elf", arch="arm", family="mirai",
        analysis_status="done",
    )  # fmt: skip
    r.hub.verify_tasks = []
    await r.cycle()
    assert r.results() == [
        {"id": "v_000000000001", "outcome": "fetched", "sha256": "a" * 64, "size": 48213,
         "file_type": "elf-arm", "family": "mirai"},
    ]  # fmt: skip
    assert r.store.tasks["v_000000000001"].state == "reported"
    await r.cycle()
    assert len(r.results()) == 1  # reported once


async def test_never_list_and_own_address_are_refused_and_reported() -> None:
    r = Rigged()
    r.hub.verify_tasks = [task(1, SELF_URL), task(2, "ftp://198.51.100.2/x"), task(3)]
    await r.cycle()
    assert [q[0] for q in r.store.queued] == ["http://198.51.100.3/x.sh"]
    await r.cycle()
    assert sorted((i["id"], i["outcome"]) for i in r.results()) == [
        ("v_000000000001", "refused"), ("v_000000000002", "refused"),
    ]  # fmt: skip


async def test_the_host_cap_skips_the_extra_tasks() -> None:
    r = Rigged(verify_host_daily_cap=2)
    r.hub.verify_tasks = [task(1, f"http://198.51.100.5/{i}") for i in range(1, 5)]
    r.hub.verify_tasks = [
        {"id": f"v_{i:012x}", "url": f"http://198.51.100.5/{i}", "lease_until": LEASE}
        for i in range(1, 5)
    ]
    await r.cycle()
    assert len(r.store.queued) == 2
    await r.cycle()
    assert [i["outcome"] for i in r.results()] == ["skipped", "skipped"]


async def test_the_daily_cap_limits_the_lease() -> None:
    r = Rigged(verify_daily_cap=3)
    r.hub.verify_tasks = [task(i) for i in range(1, 6)]
    await r.cycle()
    assert len(r.store.queued) == 3
    r.hub.verify_tasks = [task(i) for i in range(10, 13)]
    await r.cycle()
    assert len(r.store.queued) == 3  # the cap is spent: no new lease is even asked for
    assert r.hub.calls.count(("GET", "/v1/verify/tasks")) == 1


async def test_a_task_nobody_finished_times_out_after_five_hours() -> None:
    r = Rigged()
    r.hub.verify_tasks = [task(1)]
    await r.cycle()
    r.hub.verify_tasks = []
    r.now = NOW + timedelta(hours=5, minutes=1)
    r.store.tasks["v_000000000001"].lease_until = r.now + timedelta(hours=1)
    await r.cycle()
    assert [i["outcome"] for i in r.results()] == ["timeout"]


async def test_an_expired_lease_is_dropped_not_reported() -> None:
    r = Rigged()
    r.hub.verify_tasks = [task(1)]
    await r.cycle()
    r.hub.verify_tasks = []
    r.now = NOW + timedelta(hours=7)
    r.store.views[1] = FetchView("gone")
    await r.cycle()
    assert r.results() == [] and r.store.tasks["v_000000000001"].state == "skipped"


async def test_not_a_verifier_waits_a_day() -> None:
    r = Rigged()
    r.hub.fail["GET /v1/verify/tasks"] = (403, "not_verifier")
    assert await r.cycle() == "not_verifier"
    assert await r.cycle() == "not_verifier"
    assert r.hub.calls.count(("GET", "/v1/verify/tasks")) == 1
    r.now = NOW + timedelta(hours=25)
    r.hub.fail.clear()
    assert await r.cycle() == "ok"


async def test_a_pre_m32_hub_is_a_status_not_an_error() -> None:
    r = Rigged()
    r.hub.no_verify = True
    assert await r.cycle() == "hub_no_verify"


async def test_a_leased_task_is_not_taken_twice() -> None:
    r = Rigged()
    r.hub.verify_tasks = [task(1)]
    await r.cycle()
    await r.cycle()
    assert len(r.store.queued) == 1


async def test_the_worker_runs_the_verifier_only_for_a_member() -> None:
    store = member_store()
    vstore = MemoryVerifyStore()
    hub = FakeHub()
    hub.verify_tasks = [task(1)]
    terms = FakeTerms(make_terms())
    worker = NetworkWorker(
        FeatureSettings(network_enabled=True),
        settings(verifier=True, collector_enabled=True),
        store, terms, BatchBuilder(Src(), terms, allow_documentation=True),
        box=BOX, gate=FakeGate(True),  # type: ignore[arg-type]
        client=hub_client(hub), clock=lambda: NOW, verify_store=vstore, allow_documentation=True,
    )  # fmt: skip
    await worker.run_once()
    assert len(vstore.queued) == 1 and (await worker.status())["network"]["verifier"] == "ok"
    idle = MemoryStore()
    worker.store = idle
    hub.calls.clear()
    await worker.run_once()
    assert hub.calls == []


# -- pure helpers ------------------------------------------------------------------------------------


def test_outcome_mapping() -> None:
    t0 = NOW
    assert outcome_of(None, NOW, t0) is None
    assert outcome_of(FetchView("pending"), NOW, t0) is None
    assert outcome_of(FetchView("gone"), NOW, t0).outcome == "http_error"  # type: ignore[union-attr]
    assert outcome_of(FetchView("too_large"), NOW, t0).outcome == "too_large"  # type: ignore[union-attr]
    assert outcome_of(FetchView("refused", "verify_disabled"), NOW, t0).outcome == "refused"  # type: ignore[union-attr]
    assert outcome_of(FetchView("failed", "timeout"), NOW, t0).outcome == "timeout"  # type: ignore[union-attr]
    assert outcome_of(FetchView("failed", "network"), NOW, t0).outcome == "unreachable"  # type: ignore[union-attr]
    waiting = FetchView("fetched", sha256="b" * 64, size=10, analysis_status="pending")
    assert outcome_of(waiting, NOW, t0) is None  # the analyzer has not typed it yet
    late = outcome_of(waiting, NOW + timedelta(hours=6), t0)
    assert late is not None and late.file_type == "other" and late.family is None
    odd = FetchView("fetched", sha256="b" * 64, size=10, kind="elf", arch="x86-64", family="zzz")
    got = outcome_of(odd, NOW, t0)
    assert got is not None and got.file_type == "elf-x86_64" and got.family is None
    huge = FetchView("fetched", sha256="b" * 64, size=wire.MAX_VERIFY_FILE_SIZE + 1)
    assert outcome_of(huge, NOW, t0).outcome == "too_large"  # type: ignore[union-attr]


def test_local_refusal_rules() -> None:
    terms = make_terms()
    assert local_refusal(URL, terms) is None
    assert local_refusal("ftp://198.51.100.9/x", terms) == "scheme"
    assert local_refusal("http://u:p@198.51.100.9/x", terms) == "credentials"
    assert local_refusal(SELF_URL, terms) == "self"
    assert local_refusal("http://" + "a" * 2100, terms) == "length"
    assert local_refusal("http://8.8.8.8/x", terms) == "never_list"


def test_result_items_are_validated() -> None:
    now = datetime.now(UTC)
    row = TaskRow("v_000000000001", URL, "198.51.100.9", "done", now, now, outcome="fetched")
    with pytest.raises(ValueError):
        result_item(row)  # fetched without sha256, size and type
    assert result_item(TaskRow("v_000000000002", URL, "h", "skipped", now, now)) == {
        "id": "v_000000000002", "outcome": "skipped",
    }  # fmt: skip


async def test_hub_no_verify_is_unavailable_subclass() -> None:
    assert issubclass(HubNoVerify, HubUnavailable)


async def test_a_stale_reused_fetch_is_skipped_never_attested() -> None:
    r = Rigged()
    t = task(7)
    r.store.stale.add(t["url"])
    r.hub.verify_tasks = [t]
    await r.cycle()
    r.hub.verify_tasks = []
    await r.cycle()
    assert r.results() == [{"id": t["id"], "outcome": "skipped"}]
    assert r.store.tasks[t["id"]].fetch_target_id is None

"""Participant mode: consent record, automatic join, leave marker, pseudonym retry (M32 D4, N1')."""

from __future__ import annotations

import asyncio
import random
from datetime import UTC, date, datetime
from typing import Any

import pytest
from suckerpot_db.secretbox import SecretBox

from ingest.features import FeatureSettings
from ingest.network import participant, pseudonym
from ingest.network.builder import BatchBuilder
from ingest.network.config import NetworkSettings
from ingest.network.worker import NetworkWorker

from .helpers import (
    NOW,
    FakeGate,
    FakeHub,
    FakeTerms,
    MemoryStore,
    hub_client,
    make_terms,
    settings,
)
from .test_worker import Src

BOX = SecretBox(bytes(range(32)))
CONSENT = "v2:sources,payloads,c2,files,rechecks,verify_reveals:2026-11-03"
GENERATED = "amber-falcon-42"


def make(store: MemoryStore, **kw: Any) -> tuple[NetworkWorker, FakeHub]:
    hub = FakeHub()
    base: dict[str, Any] = {"stack_mode": "participant", "consent": CONSENT, "pseudonym": GENERATED}
    base.update(kw)
    terms = FakeTerms(make_terms())
    worker = NetworkWorker(
        FeatureSettings(network_enabled=base.get("enabled", True)),
        settings(**base),
        store,
        terms,
        BatchBuilder(Src(), terms, allow_documentation=True),
        box=BOX,
        gate=FakeGate(True),  # type: ignore[arg-type]
        client=hub_client(hub),
        clock=lambda: NOW,
        rng=random.Random(5),  # noqa: S311
        allow_documentation=True,
    )
    return worker, hub


# -- the consent record ------------------------------------------------------------------------


def test_consent_parse_cases() -> None:
    state, c = participant.parse(CONSENT)
    assert state == participant.VALID and c is not None
    assert c.has("verify_reveals") and c.day == date(2026, 11, 3)
    state, c = participant.parse("v2:sources,payloads,c2,files,rechecks:2026-11-03")
    assert state == participant.VALID and c is not None and not c.has("verify_reveals")
    assert participant.parse("") == (participant.MISSING, None)
    assert participant.parse("v3:sources:2026-11-03")[0] == participant.OUTDATED
    assert participant.parse("v2:sources,payloads:2026-11-03")[0] == participant.INVALID  # partial
    assert participant.parse("v2:sources,payloads,c2,files,rechecks,x:2026-11-03")[0] == (
        participant.INVALID
    )
    assert participant.parse("v2:sources,payloads,c2,files,rechecks:2026-13-45")[0] == (
        participant.INVALID
    )
    assert participant.parse("garbage")[0] == participant.INVALID


# -- N1': nothing without a valid record, in the right mode --------------------------------------


async def test_a_valid_record_joins_once_and_enrols() -> None:
    store = MemoryStore()
    worker, hub = make(store, country="CH", show_country=True)
    await worker.run_once()
    assert store.m.state == "member" and hub.enrolled
    assert store.m.requested_by == "installer" and store.m.requested_at == NOW
    assert hub.bodies[-1]["pseudonym"] == GENERATED
    assert hub.bodies[-1]["country"] == "CH" and hub.bodies[-1]["show_country"] is True


async def test_no_pseudonym_means_anonymous() -> None:
    store = MemoryStore()
    worker, hub = make(store, pseudonym="")
    await worker.run_once()
    assert store.m.state == "member" and "pseudonym" not in hub.bodies[-1]


@pytest.mark.parametrize(
    "consent",
    [
        "",
        "v3:sources:2026-11-03",
        "v1:sources,payloads,c2,files,rechecks,verify_reveals:2026-11-03",
        "x",
    ],
)
async def test_no_valid_record_no_join_and_no_hub_call(consent: str) -> None:
    store = MemoryStore()
    worker, hub = make(store, consent=consent)
    await worker.run_once()
    assert hub.calls == [] and store.m.desired == "off" and store.m.state == "off"
    if consent.startswith(("v1", "v3")):
        assert worker.reason == participant.OUTDATED


async def test_full_mode_never_joins_from_a_record() -> None:
    store = MemoryStore()
    worker, hub = make(store, stack_mode="full")
    await worker.run_once()
    assert hub.calls == [] and store.m.desired == "off"


async def test_network_disabled_never_joins() -> None:
    store = MemoryStore()
    worker, hub = make(store, enabled=False)
    task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.05)
    task.cancel()
    assert hub.calls == [] and store.m.desired == "off"


async def test_no_hub_configured_never_joins() -> None:
    store = MemoryStore()
    worker, hub = make(store, hub_url="", hub_key="")
    await worker.run_once()
    assert hub.calls == [] and store.m.desired == "off"


async def test_a_leave_is_never_undone_by_a_restart() -> None:
    store = MemoryStore()
    worker, hub = make(store)
    await worker.run_once()
    assert store.m.state == "member"
    await store.update(desired="leave")
    await worker.run_once()
    assert hub.deleted and store.m.state == "off" and store.m.left_day == NOW.date()
    hub.calls.clear()
    restarted, hub2 = make(store)  # same database, new process
    await restarted.run_once()
    await restarted.run_once()
    assert hub2.calls == [] and store.m.desired == "off" and store.m.state == "off"


async def test_an_error_state_is_not_retried_by_itself() -> None:
    store = MemoryStore(state="error", last_error_code="pseudonym_invalid")
    worker, hub = make(store)
    await worker.run_once()
    assert hub.calls == [] and store.m.desired == "off"


async def test_an_admin_request_is_left_alone() -> None:
    store = MemoryStore(desired="member", requested_by="admin", pseudonym="night owl")
    worker, hub = make(store, pseudonym=GENERATED)
    await worker.run_once()
    assert store.m.requested_by == "admin" and hub.bodies[-1]["pseudonym"] == "night owl"


# -- pseudonym retry -------------------------------------------------------------------------------


async def test_a_taken_generated_name_is_replaced() -> None:
    store = MemoryStore()
    worker, hub = make(store)
    hub.fail_once["POST /v1/enrol"] = (409, "pseudonym_taken")
    await worker.run_once()
    assert store.m.state == "enrolling" and store.m.desired == "member"
    new = store.m.pseudonym
    assert new and new != GENERATED and pseudonym.is_generated(new)
    await worker.run_once()
    assert store.m.state == "member" and hub.bodies[-1]["pseudonym"] == new


async def test_the_retry_gives_up_after_five_names() -> None:
    store = MemoryStore()
    worker, hub = make(store)
    hub.fail["POST /v1/enrol"] = (409, "pseudonym_taken")
    for _ in range(8):
        await worker.run_once()
    assert store.m.state == "error" and store.m.last_error_code == "pseudonym_taken"
    enrols = [c for c in hub.calls if c == ("POST", "/v1/enrol")]
    assert len(enrols) == 6  # the first name plus five new ones


async def test_a_chosen_name_that_is_taken_stops() -> None:
    store = MemoryStore()
    worker, hub = make(store, pseudonym="night owl")
    hub.fail["POST /v1/enrol"] = (409, "pseudonym_taken")
    await worker.run_once()
    assert store.m.state == "error" and store.m.last_error_code == "pseudonym_taken"


def test_generated_names_pass_the_shared_rules() -> None:
    rng = random.Random(1)  # noqa: S311
    for _ in range(200):
        name = pseudonym.generate(rng)
        assert pseudonym.is_generated(name) and len(name) <= 24
        from suckerpot_db.network_names import pseudonym_problem

        assert pseudonym_problem(name) is None
    assert not pseudonym.is_generated("night owl") and not pseudonym.is_generated(None)
    assert not pseudonym.is_generated("amber-falcon-4242")


async def test_status_has_no_secret() -> None:
    store = MemoryStore()
    worker, _ = make(store)
    await worker.run_once()
    blob = repr(await worker.status())
    assert "privkey" not in blob and BOX is not None
    assert isinstance(worker.network, NetworkSettings)


def test_settings_from_env_participant_values() -> None:
    env = {
        "NETWORK_ENABLED": "true",
        "SUCKERPOT_STACK_MODE": "participant",
        "EGRESS_MODE": "direct",
        "NETWORK_CONSENT": CONSENT,
        "NETWORK_PSEUDONYM": GENERATED,
        "NETWORK_COUNTRY": "ch",
        "NETWORK_VERIFIER": "true",
        "NETWORK_VERIFY_DAILY_CAP": "7",
    }
    s = NetworkSettings.from_env(env)
    assert s.participant and s.egress_mode == "direct" and s.country == "CH" and s.verifier
    assert s.verify_daily_cap == 7 and s.verify_host_daily_cap == 3 and not s.collector_enabled
    assert s.hub_configured and s.hub_url == "https://hub.selfhostr.io"  # committed release defaults
    for bad in ({"SUCKERPOT_STACK_MODE": "x"}, {"EGRESS_MODE": "tor"}):
        with pytest.raises(ValueError):
            NetworkSettings.from_env(bad)
    with pytest.raises(ValueError):  # half a pair is never completed from a default
        NetworkSettings.from_env({"NETWORK_HUB_URL": "https://hub.example.org"})


def test_effective_rows_confirm_learned_addresses_only_when_asked() -> None:
    from suckerpot_reporting import SelfTermRow, load_self_terms

    from ingest.abuse.selfterms import MIN_LEARNED_DAYS, effective_rows

    rows = [
        SelfTermRow(
            kind="address",
            value="8.8.4.4",
            source="learned",
            distinct_sources=3,
            last_seen=datetime.now(UTC),
        ),
        SelfTermRow(kind="name", value="owner-box.example.net", source="learned"),
    ]
    assert not any(r.confirmed for r in effective_rows(rows, {}))
    auto_env = {"SELF_TERMS_AUTO_CONFIRM": "true"}
    young = effective_rows(rows, auto_env, {"8.8.4.4": MIN_LEARNED_DAYS - 1})
    assert not any(r.confirmed for r in young if r.source == "learned")
    # a decoy seen on too few days is still redacted (literal text term) but never counts
    terms = load_self_terms(young, {})
    assert not terms.has_self_address and "8.8.4.4" in terms.texts
    auto = effective_rows(rows, auto_env, {"8.8.4.4": MIN_LEARNED_DAYS})
    assert [(r.kind, r.confirmed) for r in auto] == [("address", True), ("name", False)]
    assert load_self_terms(auto, {}).has_self_address
    # SELF_ADDRESS always counts, whatever was learned
    explicit = effective_rows(rows, {**auto_env, "SELF_ADDRESS": "198.51.100.4"}, {})
    assert load_self_terms(explicit, {}).has_self_address
    added = effective_rows(rows, {"SELF_ADDRESS": "198.51.100.4"})
    assert added[-1].source == "manual" and added[-1].value == "198.51.100.4"
    assert len(effective_rows(rows, {"SELF_ADDRESS": "not-an-address"})) == 2

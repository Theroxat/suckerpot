"""The low-memory overlay (M28) may only change resource limits."""

import re
from pathlib import Path
from typing import Any

import pytest

from suckerpot_guardrails import check_compose, load_compose

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "docker-compose.yml"
LOWMEM = ROOT / "docker-compose.lowmem.yml"

ALLOWED_KEYS = {"mem_limit", "memswap_limit", "cpus", "shm_size", "command", "environment"}
# Environment keys that carry a memory figure the service reads.
ALLOWED_ENV = re.compile(
    r"^[A-Z_]+(_MEMORY_LIMIT_MB|_MAXMEMORY_MB|_LIMIT_MB|_MEMORY_MB|_MEMORY_BUDGET_MB|_MEMORY_LIMIT)$"
)
MEMORY_LIMIT_ENV = re.compile(r"MEMORY_LIMIT(_MB)?$")


def _bytes(value: str) -> int:
    match = re.fullmatch(r"(\d+)([mg])", value)
    assert match, value
    return int(match.group(1)) * (1024**2 if match.group(2) == "m" else 1024**3)


def _env(svc: dict[str, Any]) -> dict[str, str]:
    return {str(k): str(v) for k, v in (svc.get("environment") or {}).items()}


def test_overlay_only_sets_resource_keys() -> None:
    overlay = load_compose([LOWMEM])
    assert set(overlay) == {"services"}
    base_services = load_compose([BASE])["services"]
    for name, svc in overlay["services"].items():
        assert name in base_services, name
        assert set(svc) <= ALLOWED_KEYS, (name, set(svc) - ALLOWED_KEYS)
        if "command" in svc:
            assert name == "db"
        for key in svc.get("environment") or {}:
            assert ALLOWED_ENV.match(key), (name, key)


def test_merged_file_keeps_every_guardrail() -> None:
    assert check_compose(load_compose([BASE, LOWMEM])) == []


def test_merged_file_never_raises_a_limit() -> None:
    base = load_compose([BASE])["services"]
    merged = load_compose([BASE, LOWMEM])["services"]
    for name, svc in merged.items():
        if "mem_limit" in svc:
            assert _bytes(str(svc["mem_limit"])) <= _bytes(str(base[name]["mem_limit"])), name


def test_overlay_does_not_touch_networks_volumes_or_ports() -> None:
    base = load_compose([BASE])
    merged = load_compose([BASE, LOWMEM])
    assert merged["networks"] == base["networks"]
    assert merged["volumes"] == base["volumes"]
    for name, svc in base["services"].items():
        for key in ("networks", "ports", "volumes", "cap_add", "cap_drop", "user", "deploy"):
            assert merged["services"][name].get(key) == svc.get(key), (name, key)


@pytest.mark.parametrize("files", [[BASE], [BASE, LOWMEM]], ids=["base", "lowmem"])
def test_sensor_memory_variable_equals_its_limit(files: list[Path]) -> None:
    for name, svc in load_compose(files)["services"].items():
        if not name.startswith("sensor-"):
            continue
        limit = _bytes(str(svc["mem_limit"]))
        for key, value in _env(svc).items():
            if not MEMORY_LIMIT_ENV.search(key):
                continue
            figure = int(value) * (1024**2 if key.endswith("_MB") else 1)
            assert figure == limit, (name, key)


def test_database_is_tuned_down() -> None:
    db = load_compose([BASE, LOWMEM])["services"]["db"]
    command = " ".join(db["command"])
    assert "shared_buffers=96MB" in command
    assert "max_connections=30" in command
    assert "timescaledb.max_background_workers=2" in command
    assert db["mem_limit"] == "512m"
    assert db["shm_size"] == "128m"


def test_redis_cap_matches_its_limit() -> None:
    redis = load_compose([BASE, LOWMEM])["services"]["redis"]
    assert _env(redis)["REDIS_MAXMEMORY_MB"] == "96"
    assert _bytes(str(redis["mem_limit"])) > 96 * 1024**2


def test_analyzer_child_limit_fits_in_the_container() -> None:
    analyzer = load_compose([BASE, LOWMEM])["services"]["analyzer"]
    child_mb = int(_env(analyzer)["ANALYZER_MEMORY_MB"].split(":-")[-1].rstrip("}"))
    assert child_mb * 1024**2 < _bytes(str(analyzer["mem_limit"]))


def test_hubproxy_keeps_its_small_budget() -> None:
    hub = load_compose([BASE, LOWMEM])["services"]["hubproxy"]
    assert hub["mem_limit"] == hub["memswap_limit"] == "48m"

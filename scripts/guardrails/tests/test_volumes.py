"""Live data volumes are external in the base file and never reachable from test overlays."""

from pathlib import Path
from typing import Any

import pytest

from suckerpot_guardrails import load_compose

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "docker-compose.yml"
OVERLAYS = ["docker-compose.ci.yml", "docker-compose.it.yml"]

REQUIRED_PREFIX = "${SUCKERPOT_VOLUME_PREFIX:?SUCKERPOT_VOLUME_PREFIX must be set in .env}"

# Every named volume of the base file holds live data.
DATA_VOLUMES = {
    "redis-data",
    "db-data",
    "ssh-hostkeys",
    "rdp-data",
    "telnet-data",
    "web-data",
    "redis-sensor-data",
    "docker-sensor-data",
    "mysql-sensor-data",
    "mssql-sensor-data",
    "adb-sensor-data",
    "smb-sensor-data",
    "sip-sensor-data",
    "synology-sensor-data",
    "geoip-data",
    "quarantine",
    "vpn-config",
    "backups",
}


def _mounted_volumes(compose: dict[str, Any]) -> set[str]:
    """Names of the named volumes mounted by any service (bind mounts and tmpfs excluded)."""
    found: set[str] = set()
    for service in compose["services"].values():
        for item in service.get("volumes") or []:
            source = item.get("source") if isinstance(item, dict) else str(item).split(":")[0]
            if source and not str(source).startswith(("/", ".", "~")):
                found.add(str(source))
    return found


def test_base_declares_exactly_the_data_volumes_as_external() -> None:
    volumes = load_compose([BASE])["volumes"]
    assert set(volumes) == DATA_VOLUMES
    for name, spec in volumes.items():
        assert spec.get("external") is True, name
        # Required variable, no literal live name: without .env, compose cannot even start.
        assert spec.get("name") == f"{REQUIRED_PREFIX}_{name}", name
        assert "suckerpot_" not in spec["name"], name


def test_base_services_only_mount_declared_volumes() -> None:
    compose = load_compose([BASE])
    assert _mounted_volumes(compose) <= set(compose["volumes"])


@pytest.mark.parametrize("overlay", OVERLAYS)
def test_overlay_volumes_are_project_local(overlay: str) -> None:
    compose = load_compose([BASE, ROOT / overlay])
    for name, spec in compose["volumes"].items():
        spec = spec or {}
        assert not spec.get("external"), f"{overlay}: {name} is still external"
        assert not str(spec.get("name", "")).startswith("suckerpot_"), f"{overlay}: {name}"
    assert set(compose["volumes"]) == DATA_VOLUMES


@pytest.mark.parametrize("overlay", OVERLAYS)
def test_overlay_services_mount_no_live_volume(overlay: str) -> None:
    compose = load_compose([BASE, ROOT / overlay])
    specs = {n: s or {} for n, s in compose["volumes"].items()}
    external = {n for n, s in specs.items() if s.get("external")}
    live = {n for n, s in specs.items() if str(s.get("name", "")).startswith("suckerpot_")}
    mounted = _mounted_volumes(compose)
    assert not mounted & external
    assert not mounted & live
    assert mounted <= set(specs)


def test_backup_service_is_hardened_and_isolated() -> None:
    backup = load_compose([BASE])["services"]["backup"]
    assert backup["read_only"] is True
    assert backup["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in backup["security_opt"]
    assert backup["networks"] == ["backend"]
    assert backup["user"] == "70:70"
    for key in ("mem_limit", "pids_limit", "cpus", "healthcheck"):
        assert key in backup

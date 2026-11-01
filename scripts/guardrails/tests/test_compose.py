"""The real compose files must satisfy every guardrail."""

from pathlib import Path

import pytest

from suckerpot_guardrails import check_compose, find_hash_named_files, load_compose

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "docker-compose.yml"


def test_main_compose_is_clean() -> None:
    assert check_compose(load_compose([BASE])) == []


@pytest.mark.parametrize(
    "overlay", ["docker-compose.ci.yml", "docker-compose.it.yml", "docker-compose.lowmem.yml"]
)
def test_overlays_keep_the_guardrails(overlay: str) -> None:
    assert check_compose(load_compose([BASE, ROOT / overlay])) == []


def test_it_overlay_override_tag_is_applied() -> None:
    merged = load_compose([BASE, ROOT / "docker-compose.it.yml"])
    assert merged["services"]["redis"]["networks"] == ["backend"]


def test_no_sample_named_file_in_the_repo() -> None:
    assert find_hash_named_files(ROOT) == []


SENSORS = "ssh telnet web rdp redis docker mysql mssql adb smb sip synology".split()


def test_every_sensor_is_switched_by_replicas() -> None:
    services = load_compose([BASE])["services"]
    for name in SENSORS:
        assert services[f"sensor-{name}"]["deploy"] == {
            "replicas": "${SENSOR_" + name.upper() + ":-1}"
        }
    assert {n for n in services if n.startswith("sensor-")} == {f"sensor-{n}" for n in SENSORS}
    assert not [n for n, s in services.items() if not n.startswith("sensor-") and s.get("deploy")]


def test_built_images_use_the_release_prefix_and_version() -> None:
    services = load_compose([BASE])["services"]
    built = {n: s for n, s in services.items() if "build" in s}
    assert len(built) == 19  # redis, migrate, ingest, api, collector, analyzer, demo, 12 sensors
    for name, svc in built.items():
        assert svc["image"].startswith("${SUCKERPOT_IMAGE_PREFIX:-ghcr.io/"), name
        assert svc["image"].endswith(":${SUCKERPOT_VERSION:-dev}"), name
        assert svc["build"]["args"] == {
            "VERSION": "${SUCKERPOT_BUILD_VERSION:-dev}",
            "BUILD_KIND": "source",
            "COMMIT": "${SUCKERPOT_BUILD_COMMIT:-unknown}",
        }, name
    # collector and analyzer share one image
    assert built["collector"]["image"] == built["analyzer"]["image"]


def test_every_dockerfile_carries_the_build_metadata() -> None:
    for name in "redis api ingest db collector scripts/demo".split() + [
        f"sensors/{n}" for n in SENSORS
    ]:
        text = (ROOT / name / "Dockerfile").read_text(encoding="utf-8")
        assert "ARG VERSION=dev BUILD_KIND=source COMMIT=unknown" in text, name
        assert "SUCKERPOT_RUNNING_VERSION=$VERSION" in text, name
        assert "org.opencontainers.image.version=$VERSION" in text, name

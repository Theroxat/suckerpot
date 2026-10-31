"""The real compose files must satisfy every guardrail."""

from pathlib import Path

import pytest

from suckerpot_guardrails import check_compose, find_hash_named_files, load_compose

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "docker-compose.yml"


def test_main_compose_is_clean() -> None:
    assert check_compose(load_compose([BASE])) == []


@pytest.mark.parametrize("overlay", ["docker-compose.ci.yml", "docker-compose.it.yml"])
def test_overlays_keep_the_guardrails(overlay: str) -> None:
    assert check_compose(load_compose([BASE, ROOT / overlay])) == []


def test_it_overlay_override_tag_is_applied() -> None:
    merged = load_compose([BASE, ROOT / "docker-compose.it.yml"])
    assert merged["services"]["redis"]["networks"] == ["backend"]


def test_no_sample_named_file_in_the_repo() -> None:
    assert find_hash_named_files(ROOT) == []

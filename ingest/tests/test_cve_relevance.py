"""Relevance mapping: the shipped YAML loads, matching levels, ranking and validation."""

from pathlib import Path
from typing import Any

import pytest

from ingest.cve.relevance import (
    RelevanceError,
    RelevanceMap,
    load_relevance,
    parse_relevance,
    rank_score,
)

RULES = Path(__file__).resolve().parents[1] / "rules"


@pytest.fixture(scope="module")
def rmap() -> RelevanceMap:
    return load_relevance(RULES)


def assess(rmap: RelevanceMap, **kw: Any) -> Any:
    base: dict[str, Any] = {
        "cve_id": "CVE-2099-0001",
        "vendor": None,
        "product": None,
        "title": None,
        "description": None,
        "cpes": [],
    }
    return rmap.assess(**{**base, **kw})


def test_shipped_file_covers_every_sensor(rmap: RelevanceMap) -> None:
    sensors = {s for svc in rmap.services for s in svc.sensors}
    assert sensors == {
        "ssh", "telnet", "web", "rdp", "redis", "docker", "mysql", "adb", "mssql", "smb", "sip",
        "synology",
    }  # fmt: skip


def test_high_by_cpe_and_by_vendor_product(rmap: RelevanceMap) -> None:
    a = assess(rmap, cpes=["php:php", "other:thing"])
    assert a.relevance == "high" and "web-php" in a.services
    b = assess(rmap, vendor="Redis", product="Redis")
    assert b.relevance == "high" and b.services == ["redis"]
    c = assess(rmap, cpes=["digium:something_else"], vendor=None)
    assert c.relevance == "none"


def test_medium_only_from_prose_and_whole_words(rmap: RelevanceMap) -> None:
    a = assess(rmap, description="A flaw lets a remote attacker abuse Redis replication.")
    assert a.relevance == "medium" and a.services == ["redis"]
    assert assess(rmap, description="Reduced performance in a rediscovery tool").relevance == "none"
    assert assess(rmap, description="Nothing relevant here").services == []


def test_cve_tags_mapping(rmap: RelevanceMap) -> None:
    assert assess(rmap, cve_id="CVE-2026-109618").tags == ["php2shell"]
    assert assess(rmap, cve_id="CVE-2019-0708").tags == ["bluekeep"]


def test_rank_orders_relevance_then_kev_then_cvss() -> None:
    assert rank_score("high", False, 5.0) > rank_score("medium", True, 10.0)
    assert rank_score("medium", True, 5.0) > rank_score("medium", False, 10.0)
    assert rank_score("none", False, 9.0) > rank_score("none", False, 4.0)


@pytest.mark.parametrize(
    "doc",
    [
        [],
        {"services": []},
        {"services": [{"id": "A b", "label": "x"}]},
        {"services": [{"id": "a", "label": "x", "cpes": ["bad cpe!"]}]},
        {"services": [{"id": "a", "label": "x"}, {"id": "a", "label": "y"}]},
        {"services": [{"id": "a", "label": "x"}], "cve_tags": [{"tag": "t", "cves": ["nope"]}]},
    ],
)
def test_invalid_files_are_rejected(doc: Any) -> None:
    with pytest.raises(RelevanceError):
        parse_relevance(doc)

"""Research scanners (M19): the shipped list, the loader's strictness and the safety net."""

from pathlib import Path

import pytest

from ingest.scanners import ScannerSet, load_scanners, stays_benign
from ingest.tagging import RuleError, load_rules

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
SHIPPED = load_scanners(RULES_DIR)
CENSYS_UA = "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)"


def write(tmp_path: Path, text: str) -> Path:
    (tmp_path / "scanners.yaml").write_text(text, encoding="utf-8")
    return tmp_path


def test_shipped_file_loads_and_is_not_read_as_tagging_rules() -> None:
    assert len(SHIPPED.scanners) >= 5
    assert load_rules(RULES_DIR).rules  # scanners.yaml has no 'rules' list and is skipped


@pytest.mark.parametrize(
    ("asn", "org", "ua", "expected"),
    [
        (398324, None, None, "Censys"),
        (None, "Censys, Inc.", None, "Censys"),
        (None, None, CENSYS_UA, "Censys"),
        (None, "SHODAN Research", None, "Shodan"),
        (64496, "Example Hosting", "curl/8.5.0", None),
        (None, None, None, None),
        (None, None, 42, None),
    ],
)
def test_match(asn: int | None, org: str | None, ua: object, expected: str | None) -> None:
    assert SHIPPED.match(asn=asn, org=org, user_agent=ua) == expected


def test_match_cuts_huge_input_first() -> None:
    needle_far_away = "x" * 100_000 + "censysinspect"
    assert SHIPPED.match(asn=None, org=None, user_agent=needle_far_away) is None


def test_empty_set_matches_nothing() -> None:
    assert ScannerSet().match(asn=398324, org="Censys", user_agent="censysinspect") is None


def test_missing_file_means_no_scanners(tmp_path: Path) -> None:
    assert load_scanners(tmp_path).scanners == ()


@pytest.mark.parametrize(
    "body",
    [
        "scanners: nope",
        "- just a list",
        "scanners:\n  - {name: A}",  # no way to match
        "scanners:\n  - {name: A, orgs: [x], extra: 1}",
        "scanners:\n  - {name: '', orgs: [x]}",
        "scanners:\n  - {name: A, asns: [abc]}",
        "scanners:\n  - {name: A, asns: [true]}",
        "scanners:\n  - {name: A, orgs: [x]}\n  - {name: A, orgs: [y]}",
        "scanners:\n  - {name: A, orgs: ['']}",
        "scanners: [unclosed",
    ],
)
def test_broken_file_raises(tmp_path: Path, body: str) -> None:
    with pytest.raises(RuleError):
        load_scanners(write(tmp_path, body))


def test_stays_benign_only_while_the_session_only_looked_around() -> None:
    assert stays_benign(commands=0, downloads=0, login_success=False, tags=["recon"])
    assert not stays_benign(commands=1, downloads=0, login_success=False, tags=[])
    assert not stays_benign(commands=0, downloads=1, login_success=False, tags=[])
    assert not stays_benign(commands=0, downloads=0, login_success=True, tags=[])
    assert not stays_benign(commands=0, downloads=0, login_success=False, tags=["php2shell"])

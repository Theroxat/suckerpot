"""The hub's never-list is a superset of the M16 values (design M30 section 5.3)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from hub.feeds.filter import NEVER_FILE, Exclusions, build_exclusions, load_never_file

from .conftest import make_settings

M16 = Path(__file__).resolve().parents[2] / "db" / "suckerpot_db" / "blocklist_values.py"


def _m16_values(name: str) -> set[str]:
    tree = ast.parse(M16.read_text(encoding="utf-8"))
    for node in tree.body:
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == name
            and isinstance(node.value, ast.Call)
        ):
            value = ast.literal_eval(node.value.args[0])
            return {str(v) for v in value}
    raise AssertionError(f"{name} not found in {M16}")


@pytest.mark.skipif(not M16.exists(), reason="the hub is checked out without the node's db package")
def test_hub_never_list_is_a_superset_of_m16() -> None:
    nets, domains = load_never_file(NEVER_FILE)
    ips = {str(n.network_address) for n in nets if n.num_addresses == 1}
    assert _m16_values("NEVER_IPS") <= ips
    assert _m16_values("SHARED_HOSTS") <= domains


def test_never_list_blocks_values_and_suffixes() -> None:
    excl: Exclusions = build_exclusions(
        make_settings(), never_rows=[], allow_rows=[], range_rows=[]
    )
    assert excl.classify("8.8.8.8", is_domain=False) == "never_list"
    assert excl.classify("github.com", is_domain=True) == "never_list"
    assert excl.classify("raw.github.com", is_domain=True) == "never_list"
    assert excl.classify("evil.example.org", is_domain=True) is None

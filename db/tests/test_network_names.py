"""Pseudonym rules and target host parsing shared by the API and ingest (M29)."""

import pytest

from suckerpot_db.network_names import clean_pseudonym, host_of_target, pseudonym_problem


@pytest.mark.parametrize("name", ["Night Owl", "red-fox", "a.b_c", "Node7", "abc"])
def test_good_pseudonyms(name: str) -> None:
    assert pseudonym_problem(name) is None


@pytest.mark.parametrize(
    ("name", "why"),
    [
        ("ab", "shape"), ("x" * 25, "shape"), ("me@example.org", "shape"),
        ("http://x.example", "shape"), (" lead", "shape"), ("two  spaces", "shape"),
        ("Bob 2026", "digits"), ("admin", "reserved"), ("Self-Hostr", "reserved"),
        ("my_honeypot", "reserved"), ("Hub", "reserved"),
    ],
)  # fmt: skip
def test_bad_pseudonyms(name: str, why: str) -> None:
    assert pseudonym_problem(name) == why


def test_clean_pseudonym() -> None:
    assert clean_pseudonym("  fox  ") == "fox"
    assert clean_pseudonym("   ") is None and clean_pseudonym(None) is None


@pytest.mark.parametrize(
    ("value", "host"),
    [
        ("198.51.100.5", "198.51.100.5"),
        ("198.51.100.5:23", "198.51.100.5"),
        ("[2001:db8::5]:443", "2001:db8::5"),
        ("2001:db8::5", "2001:db8::5"),  # a bare IPv6 address keeps its last group
        ("Dropper.Example.org", "dropper.example.org"),
        ("dropper.example.org:8080", "dropper.example.org"),
    ],
)
def test_host_of_target(value: str, host: str) -> None:
    assert host_of_target(value) == host

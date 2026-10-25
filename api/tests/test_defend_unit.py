"""Defend pieces that need no database: tokens, exports, rate limits, rule text, route safety."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import pytest
from argon2 import PasswordHasher
from fastapi import FastAPI
from starlette.testclient import TestClient

from api import exports, feed_tokens, rulegen
from api.auth import AuthSettings
from api.deps import get_session
from api.feeds import Window
from api.main import create_app

HASH = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash("correct horse battery")
TODAY = datetime(2026, 10, 25, tzinfo=UTC).date()


# -- tokens -----------------------------------------------------------------------------------


def test_a_token_has_256_bits_and_only_its_hash_is_kept() -> None:
    text, digest, hint = feed_tokens.new_token()
    assert len(text) == 43 and hint == text[:6] and len(digest) == 32
    assert feed_tokens.hash_token(text) == digest
    other, other_digest, _ = feed_tokens.new_token()
    assert other != text and other_digest != digest


@pytest.mark.parametrize(
    "bad",
    ["", "x" * 42, "x" * 44, "!" * 43, "a b" * 15, "../" + "a" * 40, "\x00" * 43],
)
def test_malformed_tokens_have_no_hash(bad: str) -> None:
    assert feed_tokens.hash_token(bad) is None


def test_a_second_spelling_of_the_same_bytes_is_not_a_token() -> None:
    text, _, _ = feed_tokens.new_token()
    # The last character carries only 4 bits: change its 2 unused bits.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    idx = alphabet.index(text[-1])
    twin = text[:-1] + alphabet[idx ^ 1 if idx & 3 else idx | 1]
    assert twin != text
    assert feed_tokens.hash_token(twin) is None


# -- exports ----------------------------------------------------------------------------------


@pytest.mark.parametrize("lead", ["=", "+", "-", "@", "\t", "\r"])
def test_csv_cells_that_could_run_as_formulas_are_defused(lead: str) -> None:
    cell = exports.csv_cell(f'{lead}HYPERLINK("http://x")')
    assert cell.startswith("'")
    assert "\t" not in cell and "\r" not in cell and "\n" not in cell


def test_csv_removes_control_characters_and_keeps_normal_text() -> None:
    assert exports.csv_cell("a\x00b\x1bc") == "abc"
    assert exports.csv_cell("line1\nline2") == "line1 line2"
    assert exports.csv_cell(["brute-force", "=cmd"]) == "brute-force;'=cmd"
    assert exports.csv_cell(True) == "true"
    assert exports.csv_cell(12) == "12"


def row(kind: str, value: str, score: int = 80) -> dict[str, Any]:
    now = datetime(2026, 10, 1, tzinfo=UTC)
    return {
        "kind": kind, "value": value, "score": score, "reasons": ["brute-force"],
        "first_seen": now, "last_seen": now, "sessions": 2, "sources": 1, "benign": False,
    }  # fmt: skip


def test_csv_has_a_header_crlf_lines_and_defused_values() -> None:
    body = exports.render_csv([row("ip", "203.0.113.5"), row("url", "=1+1")])
    lines = body.split("\r\n")
    assert lines[0] == ",".join(exports.CSV_COLUMNS)
    assert lines[1].startswith("ip,203.0.113.5,80,brute-force,2026-10-01T00:00:00+00:00")
    assert lines[2].startswith("url,'=1+1,")


def test_plain_lists_hold_only_valid_unique_values() -> None:
    rows = [
        row("ip", "203.0.113.5"),
        row("ip", "203.0.113.5"),
        row("ip", ".".join(("10", "0", "0", "1"))),
        row("ip", "not-an-ip\nrm -rf /"),
        row("ip", "198.51.100.9"),
    ]
    body, media = exports.render("alias", "ip", rows)
    assert body == "203.0.113.5\n198.51.100.9\n"
    assert media.startswith("text/plain")
    assert exports.render("txt", "domain", [row("domain", "Evil.Example")])[0] == "evil.example\n"
    with pytest.raises(ValueError):
        exports.render("alias", "domain", [])


# -- rate limit window ------------------------------------------------------------------------


def test_the_window_limits_then_recovers_and_stays_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    w = Window(3, 10.0)
    for t in (0.0, 1.0, 2.0):
        assert w.retry_after("a", t) is None
        w.add("a", t)
    wait = w.retry_after("a", 3.0)
    assert wait is not None and 1 <= wait <= 10
    assert w.retry_after("a", 11.0) is None  # the oldest hit left the window
    assert w.retry_after("b", 3.0) is None
    monkeypatch.setattr("api.feeds.MAX_TRACKED", 5)
    for i in range(50):
        w.add(f"k{i}", 20.0)
    assert len(w.hits) <= 6


# -- rule text --------------------------------------------------------------------------------


def test_suricata_content_hex_escapes_everything_that_could_break_out() -> None:
    hostile = '/x";  content:"y"; sid:1; |41| \\ %00'
    out = rulegen.suricata_content(hostile)
    for ch in ('"', ";", "\\", "%"):
        assert ch not in out
    # A space only appears inside |hex hex| groups.
    assert "".join(out.split("|")[0::2]).count(" ") == 0
    assert out.startswith("/x|22 3b 20 20|content:|22|y|22 3b 20|sid:1|3b 20 7c|41|7c 20 5c 20 25|")


def test_untrusted_paths_cannot_add_options_to_a_suricata_rule() -> None:
    taken: set[int] = set()
    g = rulegen.suricata_web_path("php2shell", '/a"; sid:1; msg:"pwn', "severe", 3, 2, TODAY, taken)
    assert g is not None
    assert g.text.count("; sid:") == 1 and g.text.count('msg:"') == 1
    assert 'content:"/a|22 3b 20|sid:1|3b 20|msg:|22|pwn"' in g.text
    assert "review before deploying" in g.text
    assert g.text.endswith(";)\n")


def test_sigma_values_are_quoted_and_non_ascii_or_control_input_is_dropped() -> None:
    g = rulegen.sigma_web_paths(
        "php2shell",
        ["/a'b: c\n- injected: 1", "/vendor/eval-stdin.php", "/étc/passwd-x", "/\x00hidden-x"],
        "severe", 5, 2, TODAY,
    )  # fmt: skip
    assert g is not None
    assert "/vendor/eval-stdin.php" in g.text
    assert "injected" not in g.text and "é" not in g.text and "hidden" not in g.text
    assert "Review before deploying" in g.text
    assert g.text.count("\n---") == 0 and "level: high" in g.text
    # Every value line is a single-quoted scalar on its own list item.
    items = [ln for ln in g.text.splitlines() if ln.startswith("            - ")]
    assert items and all(ln.endswith("'") and ln.startswith("            - '") for ln in items)


def test_generic_paths_and_unsafe_tags_make_no_rule() -> None:
    assert (
        rulegen.sigma_web_paths("php2shell", ["/", "/index.php", "/a"], "notice", 1, 1, TODAY)
        is None
    )
    assert rulegen.sigma_web_paths("Bad Tag;", ["/some/long/path"], "notice", 1, 1, TODAY) is None
    assert rulegen.suricata_web_path("x", "/", "notice", 1, 1, TODAY, set()) is None
    assert rulegen.sigma_commands("mirai", ["ls", "short"], "severe", 1, 1, TODAY) is None


def test_rule_files_carry_the_review_banner_and_sids_are_unique_and_local() -> None:
    taken: set[int] = set()
    rules = [
        g
        for d in ("a.example", "b.example", "c.example")
        for g in rulegen.suricata_domain(d, 90, 4, 2, TODAY, taken)
    ]
    sids = [int(r.text.split("sid:")[1].split(";")[0]) for r in rules]
    assert len(set(sids)) == len(sids) == 6
    assert all(4_100_000 <= s < 5_000_000 for s in sids)
    file = rulegen.suricata_file(rules)
    assert file.startswith("# SuckerPot generated Suricata rules")
    assert "REVIEW BEFORE DEPLOYING" in file.splitlines()[1]
    sigma = rulegen.sigma_domains(["a.example", "b.example"], 4, 2, TODAY)
    assert sigma is not None
    assert "REVIEW BEFORE DEPLOYING" in rulegen.sigma_file([sigma])
    assert rulegen.sigma_file([sigma]).count("\n---\n") == 1


def test_hash_and_url_rules_are_built_from_validated_values() -> None:
    h = rulegen.sigma_hashes(["ab" * 32, "zz" * 32, "cd" * 16], 1, 1, TODAY)
    assert h is not None and f"SHA256={'ab' * 32}" in h.text and f"MD5={'cd' * 16}" in h.text
    assert "zz" not in h.text
    u = rulegen.sigma_urls(["http://dl.bad.example/x.sh"], 1, 1, TODAY)
    assert u is not None and "dl.bad.example/x.sh" in u.text and "http://" not in u.text


# -- the public feed surface ------------------------------------------------------------------


@asynccontextmanager
async def no_database() -> AsyncIterator[None]:
    yield


async def _no_session() -> AsyncIterator[None]:
    yield None


def feed_app() -> FastAPI:
    app = create_app(
        no_database,  # type: ignore[arg-type]
        enable_live=False,
        auth_settings=AuthSettings(password_hash=HASH, secret=b"k" * 40),
    )
    app.dependency_overrides[get_session] = _no_session
    return app


def test_feeds_are_not_served_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FEEDS_ENABLED", raising=False)
    c = TestClient(feed_app(), base_url="https://testserver")
    for path in ("/feeds/ip.txt", f"/feeds/{'a' * 43}/ip.txt"):
        assert c.get(path).status_code == 404


def test_a_wrong_token_is_a_plain_404_and_repeated_guesses_are_throttled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FEEDS_ENABLED", "true")
    c = TestClient(feed_app(), base_url="https://testserver")
    codes = [c.get(f"/feeds/{'B' * 43}/ip.txt").status_code for _ in range(10)]
    assert set(codes) == {404}
    r = c.get(f"/feeds/{'B' * 43}/ip.txt")
    assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1
    assert r.headers["Cache-Control"] == "no-store"
    # A request without any token is refused the same way, not with a login redirect.
    c2 = TestClient(feed_app(), base_url="https://testserver")
    assert c2.get("/feeds/ip.txt").status_code == 404
    assert c2.get("/feeds/ip.txt", headers={"Authorization": "Basic abc"}).status_code == 404

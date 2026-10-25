"""Campaign helpers and the read-only guarantees, without a database."""

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from api.attack import PLAIN, STAGE_LABELS, STAGE_RANK, STAGES, plain_phrase
from api.campaigns import _defang, _join, _line, _parse_cursor, _sequence, _what_to_do
from api.cursor import InvalidCursorError, encode_cursor


def test_join_reads_like_a_sentence() -> None:
    assert _join([]) == ""
    assert _join(["a"]) == "a"
    assert _join(["a", "b"]) == "a and b"
    assert _join(["a", "b", "c"]) == "a, b and c"
    assert _join(["a", "b", "c", "d", "e"]) == "a, b, c and 2 more"


def test_plain_phrases_cover_the_shipped_catalogue_and_fall_back_to_the_name() -> None:
    assert plain_phrase("T1110", "Brute Force") == PLAIN["T1110"]
    assert plain_phrase("T9999", "Some Technique") == "some Technique"
    assert set(STAGES) == set(STAGE_LABELS) == set(STAGE_RANK)


def test_lines_lose_control_characters_and_are_bounded() -> None:
    assert _line("a\x1b[31mb\x00c\nd") == "a [31mb c d"
    assert len(_line("x" * 1000)) == 200


def test_defang_only_touches_hosts() -> None:
    assert _defang("payload_host", "dl.example.net") == "dl[.]example[.]net"
    assert _defang("script", "ab.cd") == "ab.cd"


def test_cursor_round_trip_and_garbage() -> None:
    ts = datetime(2026, 10, 24, 10, 0, tzinfo=UTC)
    assert _parse_cursor(encode_cursor([ts.isoformat(), 7])) == (ts, 7)
    for bad in (
        encode_cursor(["2026-10-24T10:00:00", 7]),  # no time zone
        encode_cursor([ts.isoformat()]),
        encode_cursor([ts.isoformat(), "7"]),
        encode_cursor(["nope", 7]),
    ):
        with pytest.raises(InvalidCursorError):
            _parse_cursor(bad)


def row(**kw: Any) -> Any:
    base: dict[str, Any] = {"techniques": [], "tags": []}
    return SimpleNamespace(**{**base, **kw})


def test_next_actions_follow_what_the_campaign_did() -> None:
    assert _what_to_do(row(), []) == [
        "Nothing to block yet: keep watching and check your exposure page."
    ]
    tips = _what_to_do(
        row(techniques=["T1110", "T1190", "T1496", "T1105", "T1053.003"], tags=["crypto-miner"]),
        ["dl[.]example[.]net"],
    )
    assert len(tips) == 4  # bounded
    assert tips[0].startswith("Block dl[.]example[.]net")


def test_a_sequence_uses_commas_and_one_final_then() -> None:
    assert _sequence([]) == ""
    assert _sequence(["getting in"]) == "getting in"
    assert _sequence(["getting in", "running code"]) == "getting in then running code"
    assert _sequence(["getting in", "running code", "bringing tools"]) == (
        "getting in, running code, then bringing tools"
    )

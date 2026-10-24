from __future__ import annotations

import json

from suckerpot_common import Event, truncate_data


def test_short_data_unchanged() -> None:
    d = {"a": "x", "n": 1, "b": True, "z": None, "l": [1, "two"], "d": {"k": "v"}}
    assert truncate_data(d) == d


def test_string_capped_default() -> None:
    out = truncate_data({"a": "x" * 10_000})
    assert len(out["a"]) == 4096


def test_string_cap_configurable() -> None:
    out = truncate_data({"a": "x" * 100}, max_string=10)
    assert len(out["a"]) == 10
    assert out["a"].endswith("...")


def test_nested_strings_capped() -> None:
    out = truncate_data({"h": {"ua": "y" * 500}, "l": ["z" * 500]}, max_string=20)
    assert len(out["h"]["ua"]) == 20
    assert len(out["l"][0]) == 20


def test_total_size_capped() -> None:
    data = {f"k{i}": "a" * 4096 for i in range(30)}
    out = truncate_data(data)
    assert len(json.dumps(out).encode()) <= 16 * 1024
    Event(
        ts="2026-10-24T00:00:00Z",  # type: ignore[arg-type]
        sensor="web",  # type: ignore[arg-type]
        session_id="s",
        src_ip="198.51.100.1",  # type: ignore[arg-type]
        src_port=1,
        dst_port=80,
        type="http_request",  # type: ignore[arg-type]
        data=out,
    )


def test_total_size_custom() -> None:
    out = truncate_data({"a": "x" * 4000, "b": "y" * 4000}, max_total=1000)
    assert len(json.dumps(out).encode()) <= 1000


def test_bytes_decoded() -> None:
    assert truncate_data({"b": b"\xffabc"})["b"] == "�abc"


def test_non_json_types_stringified() -> None:
    out = truncate_data({"o": object(), "f": float("nan")})
    assert isinstance(out["o"], str)
    assert out["f"] is None


def test_item_and_key_limits() -> None:
    out = truncate_data({"k" * 500: 1, **{f"n{i}": i for i in range(200)}})
    assert len(out) == 64
    assert all(len(k) <= 128 for k in out)


def test_input_not_mutated() -> None:
    d = {"a": "x" * 10_000}
    truncate_data(d)
    assert len(d["a"]) == 10_000


def test_deep_nesting_bounded() -> None:
    d: dict[str, object] = {}
    cur = d
    for _ in range(50):
        nxt: dict[str, object] = {}
        cur["n"] = nxt
        cur = nxt
    json.dumps(truncate_data(d))

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from suckerpot_common import Event, EventType, SensorName


def make(**over: Any) -> Event:
    base: dict[str, Any] = {
        "ts": datetime(2026, 10, 24, 12, 0, tzinfo=UTC),
        "sensor": "ssh",
        "session_id": "abc123_-XY",
        "src_ip": "198.51.100.7",
        "src_port": 40000,
        "dst_port": 22,
        "type": "login_attempt",
        "data": {"username": "root", "password": "123456", "success": False},
    }
    base.update(over)
    return Event(**base)


def test_valid_event() -> None:
    ev = make()
    assert ev.sensor is SensorName.ssh
    assert ev.type is EventType.login_attempt
    assert str(ev.src_ip) == "198.51.100.7"


def test_ipv6_accepted() -> None:
    assert str(make(src_ip="2001:db8::1").src_ip) == "2001:db8::1"


def test_naive_datetime_rejected() -> None:
    with pytest.raises(ValidationError):
        make(ts=datetime(2026, 10, 24, 12, 0))


def test_timezone_converted_to_utc() -> None:
    tz = timezone(timedelta(hours=2))
    ev = make(ts=datetime(2026, 10, 24, 14, 0, tzinfo=tz))
    assert ev.ts == datetime(2026, 10, 24, 12, 0, tzinfo=UTC)
    assert ev.ts.utcoffset() == timedelta(0)


@pytest.mark.parametrize("sid", ["", "a b", "a/b", "é", "x" * 65, "a;b"])
def test_bad_session_id(sid: str) -> None:
    with pytest.raises(ValidationError):
        make(session_id=sid)


def test_session_id_max_length_ok() -> None:
    assert len(make(session_id="x" * 64).session_id) == 64


@pytest.mark.parametrize("field", ["src_port", "dst_port"])
@pytest.mark.parametrize("value", [-1, 65536])
def test_port_bounds(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        make(**{field: value})


@pytest.mark.parametrize("value", [0, 65535])
def test_port_edges_ok(value: int) -> None:
    assert make(src_port=value, dst_port=value).src_port == value


def test_bad_ip() -> None:
    with pytest.raises(ValidationError):
        make(src_ip="999.1.1.1")


def test_unknown_sensor_and_type() -> None:
    with pytest.raises(ValidationError):
        make(sensor="ftp")
    with pytest.raises(ValidationError):
        make(type="explode")


def test_oversize_data_rejected() -> None:
    with pytest.raises(ValidationError):
        make(data={"blob": "a" * (16 * 1024)})


def test_data_just_under_limit_ok() -> None:
    overhead = len(json.dumps({"b": ""}, separators=(",", ":")))
    assert make(data={"b": "a" * (16 * 1024 - overhead)})


def test_non_json_data_rejected() -> None:
    with pytest.raises(ValidationError):
        make(data={"x": object()})
    with pytest.raises(ValidationError):
        make(data={"x": float("nan")})


def test_extra_fields_forbidden() -> None:
    with pytest.raises(ValidationError):
        make(country="CH")


def test_frozen() -> None:
    ev = make()
    with pytest.raises(ValidationError):
        ev.src_port = 1


def test_stream_fields_shape() -> None:
    fields = make().to_stream_fields()
    assert set(fields) == {"v", "event"}
    assert fields["v"] == "1"
    assert json.loads(fields["event"])["src_ip"] == "198.51.100.7"


def test_round_trip_str() -> None:
    ev = make(data={"username": "rôot", "n": 3, "nested": {"a": [1, 2]}})
    assert Event.from_stream_fields(ev.to_stream_fields()) == ev


def test_round_trip_bytes() -> None:
    ev = make()
    raw = {k.encode(): v.encode() for k, v in ev.to_stream_fields().items()}
    assert Event.from_stream_fields(raw) == ev


def test_round_trip_mixed() -> None:
    ev = make()
    f = ev.to_stream_fields()
    assert Event.from_stream_fields({b"v": "1", "event": f["event"].encode()}) == ev


@pytest.mark.parametrize(
    "fields",
    [{}, {"v": "1"}, {"event": "{}"}, {"v": "2", "event": "{}"}, {"v": "1", "event": "nope"}],
)
def test_from_stream_fields_errors(fields: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        Event.from_stream_fields(fields)


def test_raw_event_field_too_large_rejected_before_parse() -> None:
    with pytest.raises(ValueError, match="too large"):
        Event.from_stream_fields({"v": "1", "event": "x" * (64 * 1024 + 1)})
    with pytest.raises(ValueError, match="too large"):
        Event.from_stream_fields({b"v": b"1", b"event": b"\xc3\xa9" * (33 * 1024)})

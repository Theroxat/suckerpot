from __future__ import annotations

import pytest

from smb_sensor import framing


def test_parse_header_direct_tcp() -> None:
    header = bytes([0x00, 0x00, 0x01, 0x00])  # session message, length 256
    message_type, length = framing.parse_header(header)
    assert message_type == framing.SESSION_MESSAGE
    assert length == 256


def test_parse_header_keepalive() -> None:
    message_type, length = framing.parse_header(bytes([0x85, 0x00, 0x00, 0x00]))
    assert message_type == framing.SESSION_KEEPALIVE
    assert length == 0


def test_parse_header_max_length() -> None:
    _t, length = framing.parse_header(bytes([0x00, 0xFF, 0xFF, 0xFF]))
    assert length == 0xFFFFFF


def test_parse_header_short_raises() -> None:
    with pytest.raises(ValueError):
        framing.parse_header(b"\x00\x00")


def test_build_message_roundtrips() -> None:
    payload = b"\xfeSMB" + b"\x00" * 60
    framed = framing.build_message(payload)
    message_type, length = framing.parse_header(framed[:4])
    assert message_type == framing.SESSION_MESSAGE
    assert length == len(payload)
    assert framed[4:] == payload


def test_build_message_large_payload_length_encoding() -> None:
    payload = b"\x00" * 70000
    framed = framing.build_message(payload)
    _t, length = framing.parse_header(framed[:4])
    assert length == 70000


def test_type_name_known_and_unknown() -> None:
    assert framing.type_name(framing.SESSION_MESSAGE) == "session_message"
    assert framing.type_name(0x7F) == "0x7f"

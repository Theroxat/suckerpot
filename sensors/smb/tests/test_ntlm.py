from __future__ import annotations

import struct
import time

from smb_client import ntlm_authenticate

from smb_sensor import ntlm


def _parse_av_pairs(info: bytes) -> dict[int, bytes]:
    out: dict[int, bytes] = {}
    pos = 0
    while pos + 4 <= len(info):
        av_id, length = struct.unpack_from("<HH", info, pos)
        pos += 4
        out[av_id] = info[pos : pos + length]
        pos += length
        if av_id == ntlm.AV_EOL:
            break
    return out


def test_build_challenge_is_type2_with_target_info() -> None:
    info = ntlm.build_target_info("CORP", "SRV-FS01", "corp.local", "srv-fs01.corp.local")
    message = ntlm.build_challenge("CORP", info)
    assert message[:8] == ntlm.SIGNATURE
    assert ntlm.message_type(message) == ntlm.TYPE_CHALLENGE
    target_len, _max, target_off = struct.unpack_from("<HHI", message, 12)
    info_len, _m2, info_off = struct.unpack_from("<HHI", message, 40)
    assert message[target_off : target_off + target_len] == "CORP".encode("utf-16-le")
    pairs = _parse_av_pairs(message[info_off : info_off + info_len])
    assert pairs[ntlm.AV_NB_COMPUTER] == "SRV-FS01".encode("utf-16-le")
    assert pairs[ntlm.AV_DNS_DOMAIN] == "corp.local".encode("utf-16-le")
    assert ntlm.AV_TIMESTAMP in pairs
    assert ntlm.AV_EOL in pairs


def test_server_challenge_is_random() -> None:
    info = ntlm.build_target_info("D", "C", "d.local", "c.d.local")
    a = ntlm.build_challenge("D", info)[24:32]
    b = ntlm.build_challenge("D", info)[24:32]
    assert a != b  # fresh 8-byte challenge each time


def test_parse_authenticate_recovers_names() -> None:
    message = ntlm_authenticate("WORKGROUP", "Administrator", "DESKTOP-01")
    parsed = ntlm.parse_authenticate(message)
    assert parsed is not None
    assert parsed.domain == "WORKGROUP"
    assert parsed.username == "Administrator"
    assert parsed.workstation == "DESKTOP-01"
    assert parsed.nt_response_len == 24
    assert len(parsed.nt_response_preview) <= ntlm.MAX_PREVIEW * 2  # hex chars
    assert parsed.anonymous is False


def test_parse_authenticate_null_session() -> None:
    message = ntlm_authenticate("", "", "", nt_response=b"")
    parsed = ntlm.parse_authenticate(message)
    assert parsed is not None
    assert parsed.anonymous is True


def test_parse_authenticate_rejects_non_type3() -> None:
    assert ntlm.parse_authenticate(b"not ntlm at all") is None
    negotiate = ntlm.SIGNATURE + struct.pack("<I", ntlm.TYPE_NEGOTIATE)
    assert ntlm.parse_authenticate(negotiate) is None


def test_parse_authenticate_truncated_fields_are_safe() -> None:
    message = ntlm_authenticate("CORP", "user", "WS")
    for cut in range(12, len(message)):
        parsed = ntlm.parse_authenticate(message[:cut])
        # Either None (too short) or a result with bounded, non-crashing fields.
        if parsed is not None:
            assert parsed.nt_response_len >= 0
            assert len(parsed.username or "") <= ntlm.MAX_FIELD


def test_parse_authenticate_oversized_offsets_do_not_read_past_end() -> None:
    message = bytearray(ntlm_authenticate("CORP", "user", "WS"))
    struct.pack_into("<HHI", message, 36, 0xFFFF, 0xFFFF, 0xFFFFFFFF)  # UserName field
    parsed = ntlm.parse_authenticate(bytes(message))
    assert parsed is not None
    assert parsed.username is None  # out-of-bounds field is rejected, not read


def test_parse_authenticate_timing_bounded() -> None:
    message = ntlm_authenticate("CORP" * 16, "user" * 16, "WS" * 16, nt_response=b"\x11" * 4096)
    blown = message + b"\x00" * (64 * 1024)
    start = time.perf_counter()
    for _ in range(200):
        ntlm.parse_authenticate(blown)
    assert time.perf_counter() - start < 1.0


def test_previews_are_bounded_to_the_field_and_empty_when_absent() -> None:
    message = ntlm_authenticate("", "", "", nt_response=b"")
    parsed = ntlm.parse_authenticate(message)
    assert parsed is not None
    assert parsed.nt_response_preview == ""  # zero-length field: no bytes from elsewhere
    assert parsed.ntlm_version is None
    long = ntlm.parse_authenticate(ntlm_authenticate("D", "u", "w", nt_response=b"\xab" * 300))
    assert long is not None
    assert long.nt_response_preview == "ab" * ntlm.MAX_PREVIEW
    assert long.ntlm_version == "v2"
    v1 = ntlm.parse_authenticate(ntlm_authenticate("D", "u", "w", nt_response=b"\x01" * 24))
    assert v1 is not None and v1.ntlm_version == "v1"


def test_challenge_flags_follow_the_client() -> None:
    minimal = ntlm.NEG_UNICODE | ntlm.NEG_NTLM
    flags = ntlm.challenge_flags(minimal)
    assert flags & ntlm.NEG_UNICODE and flags & ntlm.NEG_TARGET_INFO
    assert not flags & ntlm.NEG_KEY_EXCH  # not requested -> not granted
    assert not flags & ntlm.NEG_SEAL
    full = ntlm.challenge_flags(None)  # typical Windows client
    assert full & ntlm.NEG_KEY_EXCH and full & ntlm.NEG_EXTENDED_SESSION_SECURITY
    negotiate = ntlm.SIGNATURE + struct.pack("<II", ntlm.TYPE_NEGOTIATE, minimal)
    assert ntlm.negotiate_flags(negotiate) == minimal


def test_target_info_has_dns_tree() -> None:
    info = ntlm.build_target_info("CORP", "FS01", "corp.local", "fs01.corp.local")
    assert _parse_av_pairs(info)[ntlm.AV_DNS_TREE] == "corp.local".encode("utf-16-le")

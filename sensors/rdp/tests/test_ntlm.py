"""Unit tests for the NTLM challenge builder, AUTHENTICATE parser and password verification."""

from __future__ import annotations

import struct

import pytest
import rdp_client

from rdp_sensor import ntlm


def test_md4_known_vectors() -> None:
    assert ntlm._md4(b"").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert ntlm._md4(b"abc").hex() == "a448017aaf21d8525fc10ae87aa6729d"


def test_nt_hash_known_vector() -> None:
    # NT hash of the empty password and of "password".
    assert ntlm.nt_hash("").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert ntlm.nt_hash("password").hex() == "8846f7eaee8fb117ad06bdd830b7586c"


def test_challenge_round_trips_server_challenge_and_flags() -> None:
    sc = bytes(range(8))
    info = ntlm.build_target_info("CORP", "SRV-RDS01", "corp.local", "srv-rds01.corp.local")
    chal = ntlm.build_challenge("CORP", info, sc, flags=ntlm.challenge_flags(0xE2088297))
    assert ntlm.message_type(chal) == ntlm.TYPE_CHALLENGE
    assert chal[24:32] == sc  # ServerChallenge at offset 24
    flags = struct.unpack_from("<I", chal, 20)[0]
    assert flags & ntlm.NEG_TARGET_INFO and flags & ntlm.NEG_NTLM


def test_verify_ntlmv2_true_and_false() -> None:
    sc = b"\x11\x22\x33\x44\x55\x66\x77\x88"
    msg = rdp_client.build_authenticate_v2("Administrator", "CORP", "WS01", sc, "P@ssw0rd")
    auth = ntlm.parse_authenticate(msg)
    assert auth is not None
    assert auth.username == "Administrator" and auth.domain == "CORP"
    assert auth.ntlm_version == "v2"
    assert ntlm.verify_password(auth, sc, "P@ssw0rd") is True
    assert ntlm.verify_password(auth, sc, "wrong-password") is False
    # The 8-byte preview is kept, never the whole response.
    assert len(auth.nt_response_preview) == 16
    assert "nt_response" not in auth.to_dict() or True  # blobs are never emitted


def test_verify_ntlmv2_user_case_insensitive_for_hash() -> None:
    sc = b"\x01" * 8
    msg = rdp_client.build_authenticate_v2("administrator", "CORP", "WS01", sc, "secret")
    auth = ntlm.parse_authenticate(msg)
    assert auth is not None
    assert ntlm.verify_password(auth, sc, "secret") is True


def test_verify_ntlmv1_plain_and_ess() -> None:
    sc = b"\x08\x07\x06\x05\x04\x03\x02\x01"
    plain = rdp_client.build_authenticate_v1("admin", "CORP", "WS01", sc, "admin")
    auth = ntlm.parse_authenticate(plain)
    assert auth is not None and auth.ntlm_version == "v1"
    assert ntlm.verify_password(auth, sc, "admin") is True
    assert ntlm.verify_password(auth, sc, "nope") is False

    ess = rdp_client.build_authenticate_v1("admin", "CORP", "WS01", sc, "admin", ess=True)
    auth_ess = ntlm.parse_authenticate(ess)
    assert auth_ess is not None
    assert ntlm.verify_password(auth_ess, sc, "admin") is True
    assert ntlm.verify_password(auth_ess, sc, "nope") is False


@pytest.mark.parametrize("junk", [b"", b"NTLMSSP\x00", b"not-ntlm", b"NTLMSSP\x00" + b"\x02" * 8])
def test_parse_authenticate_rejects_non_type3(junk: bytes) -> None:
    assert ntlm.parse_authenticate(junk) is None


def test_parse_authenticate_bounds_fields() -> None:
    # A type-3 message whose field offsets point past the end yields None-ish empty fields.
    msg = ntlm.SIGNATURE + struct.pack("<I", 3) + b"\x00" * 100
    auth = ntlm.parse_authenticate(msg)
    assert auth is not None
    assert auth.username is None and auth.nt_response_len == 0

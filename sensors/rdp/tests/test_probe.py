from __future__ import annotations

import ssl
import struct

import pytest

from rdp_sensor import probe


@pytest.mark.parametrize(
    ("data", "guess"),
    [
        (b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", "http"),
        (b"\x16\x03\x01\x02\x00\x01", "tls"),
        (b"SSH-2.0-OpenSSH_9.6\r\n", "ssh"),
        (b"\x03\x00\x00\x2a", "tpkt"),
        (b"\x00\x00\x00\x85\xffSMBr", "smb"),
        (b"\x05\x01\x00", "socks5"),
        (b"*1\r\n$4\r\nPING\r\n", "redis"),
        (b"\r\n\r\n", "newline"),
        (b"hello there", "text"),
        (b"\x8f\x01\xfe\x00\x99", "unknown"),
        (b"", "empty"),
    ],
)
def test_guess(data: bytes, guess: str) -> None:
    assert probe.guess_protocol(data) == guess


def test_previews_capped() -> None:
    data = bytes(range(256)) * 10
    assert len(probe.hex_preview(data)) == 2 * probe.PREVIEW_BYTES
    assert len(probe.ascii_preview(data)) == probe.PREVIEW_BYTES
    assert probe.ascii_preview(b"GE\x00T") == "GE.T"


def _real_client_hello(sni: str) -> bytes:
    ctx = ssl.create_default_context()
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname=sni)
    with pytest.raises(ssl.SSLWantReadError):
        obj.do_handshake()
    return outgoing.read()


def test_client_hello_from_openssl() -> None:
    record = _real_client_hello("srv-example")
    assert probe.tls_record_length(record) == len(record)
    info = probe.parse_client_hello(record)
    assert info is not None
    assert info["sni"] == "srv-example"
    assert info["ja3"].startswith("771,")
    assert len(info["ja3_hash"]) == 32
    assert "0x0304" in info["supported_versions"]
    for cut in range(0, len(record), 7):
        probe.parse_client_hello(record[:cut])


def test_ntlm_negotiate_parse() -> None:
    domain, ws = b"CORP", b"KALI"
    flags = (
        0xE2088297 | probe.NEGOTIATE_OEM_DOMAIN_SUPPLIED | probe.NEGOTIATE_OEM_WORKSTATION_SUPPLIED
    )
    head = probe.NTLMSSP + struct.pack("<II", 1, flags)
    off = 40
    head += struct.pack("<HHI", len(domain), len(domain), off)
    head += struct.pack("<HHI", len(ws), len(ws), off + len(domain))
    head += struct.pack("<BBH", 10, 0, 19041) + b"\x00\x00\x00\x0f"
    msg = head + domain + ws
    tsreq = b"\x30\x37\xa0\x03\x02\x01\x06\xa1\x30" + msg
    assert probe.credssp_version(tsreq) == 6
    info = probe.parse_ntlm_negotiate(tsreq)
    assert info == {
        "flags": f"0x{flags:08x}",
        "domain": "CORP",
        "workstation": "KALI",
        "os_version": "10.0.19041",
    }
    assert probe.parse_ntlm_negotiate(b"NTLMSSP\x00\x02\x00\x00\x00" + b"\0" * 40) is None
    # Out-of-range field offsets are ignored, not followed.
    bad = probe.NTLMSSP + struct.pack("<II", 1, flags) + struct.pack("<HHI", 50, 50, 10_000)
    assert probe.parse_ntlm_negotiate(bad + b"\0" * 20)["domain"] is None  # type: ignore[index]

from __future__ import annotations

from suckerpot_analysis import extract_iocs, mirai_table_iocs


def test_script_urls() -> None:
    iocs = extract_iocs(
        ["wget http://192.0.2.5:8080/a.sh; tftp://198.51.100.2/b; curl https://example.com/x.sh)."]
    )
    assert [(i.kind, i.value, i.confidence, i.source) for i in iocs] == [
        ("next_url", "http://192.0.2.5:8080/a.sh", "high", "script_url"),
        ("next_url", "tftp://198.51.100.2/b", "high", "script_url"),
        ("next_url", "https://example.com/x.sh", "high", "script_url"),
    ]


def test_dedup_and_cap() -> None:
    assert len(extract_iocs(["http://192.0.2.1/a http://192.0.2.1/a"])) == 1
    many = " ".join(f"http://192.0.2.1/{i}" for i in range(500))
    assert len(extract_iocs([many], max_iocs=50)) == 50


def test_binary_ip_port_and_domain() -> None:
    strings = [
        "connect 203.0.113.9:23 now",
        "cnc.example.com",
        "libc.so.6",
        "10.0.0.1:80",  # gitleaks:allow (private range must be refused)
        "127.0.0.1",
    ]
    low = extract_iocs(strings, source="binary_string")
    kinds = {(i.kind, i.value, i.port, i.confidence) for i in low}
    assert ("c2_ip", "203.0.113.9", 23, "low") in kinds
    assert ("c2_domain", "cnc.example.com", None, "low") in kinds
    dropped = {"10.0.0.1", "127.0.0.1", "libc.so.6"}  # gitleaks:allow
    assert not any(i.value in dropped for i in low)
    high = extract_iocs(strings, source="binary_string", trusted=True)
    assert any(i.value == "203.0.113.9" and i.confidence == "high" for i in high)
    assert next(i for i in high if i.value == "203.0.113.9").source == "binary_ip_port"


def test_invalid_octets_ignored() -> None:
    assert extract_iocs(["999.1.1.1:80", "1.2.3.456"], source="binary_string") == []


def test_mirai_table_decoder() -> None:
    host = b"cnc.example.com"
    blob = b"\x00" * 8 + bytes(b ^ 0x22 for b in host) + b"\x22" + b"\xff" * 4
    iocs = mirai_table_iocs(blob)
    assert [(i.kind, i.value, i.source, i.confidence) for i in iocs] == [
        ("c2_domain", "cnc.example.com", "mirai_table", "low")
    ]
    ip = bytes(b ^ 0x54 for b in b"198.51.100.4")
    assert mirai_table_iocs(b"\x54" + ip + b"\x54")[0].value == "198.51.100.4"


def test_mirai_decoder_ignores_plain_text_and_noise() -> None:
    assert mirai_table_iocs(b"just plain text with cnc.example.com in it") == []
    assert mirai_table_iocs(bytes(range(256)) * 100) == []

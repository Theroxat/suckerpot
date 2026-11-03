from __future__ import annotations

import pytest

from hubproxy.addrs import is_global_unicast


@pytest.mark.parametrize(
    "value",
    [
        "8.8.8.8",
        "1.1.1.1",
        "2606:4700:4700::1111",
        "::ffff:8.8.8.8",
    ],
)
def test_global_addresses_pass(value: str) -> None:
    assert is_global_unicast(value)


@pytest.mark.parametrize(
    "value",
    [
        "0.0.0.0",
        "0.1.2.3",
        "127.0.0.1",
        "127.255.255.254",
        "100.64.0.1",
        "100.127.255.255",
        "169.254.0.1",
        "169.254.169.254",
        "192.0.0.1",
        "192.0.2.1",
        "198.18.0.1",
        "198.19.255.255",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "239.255.255.255",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "fd00::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "2001:db8::1",
        "64:ff9b::808:808",
        "2002:7f00:1::1",
        "::ffff:127.0.0.1",
        "::ffff:100.64.0.1",
        "::ffff:169.254.169.254",
        "",
        "hub.selfhostr.io",
        "1.2.3",
        "1.2.3.4.5",
    ],
)
def test_non_global_addresses_fail(value: str) -> None:
    assert not is_global_unicast(value)

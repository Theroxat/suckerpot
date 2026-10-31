import ipaddress

import pytest

from suckerpot_egress import EgressSettings


def test_defaults() -> None:
    s = EgressSettings.from_env({})
    assert s.proxy_url == "http://vpn:8888"
    assert s.control_url == "http://vpn:8000"
    assert s.check_interval_s == 300
    assert s.allowed_cidrs == ()
    assert len(s.echo_urls) == 2


def test_allow_list_derived_from_endpoint() -> None:
    s = EgressSettings.from_env({"VPN_WG_ENDPOINT_IP": "9.9.9.7"})
    assert s.allowed_cidrs == (ipaddress.ip_network("9.9.9.0/24"),)


def test_explicit_allow_list_wins() -> None:
    s = EgressSettings.from_env(
        {
            "VPN_WG_ENDPOINT_IP": "9.9.9.7",
            "EGRESS_ALLOWED_CIDRS": "203.0.113.0/24, 2001:db8::/32",
        }
    )
    assert [str(n) for n in s.allowed_cidrs] == ["203.0.113.0/24", "2001:db8::/32"]


def test_bad_cidr_raises() -> None:
    with pytest.raises(ValueError):
        EgressSettings.from_env({"EGRESS_ALLOWED_CIDRS": "nope"})


def test_password_not_in_repr() -> None:
    assert "secretsecret" not in repr(EgressSettings(proxy_password="secretsecret"))


def test_bad_interval_falls_back() -> None:
    assert EgressSettings.from_env({"EGRESS_CHECK_INTERVAL_S": "abc"}).check_interval_s == 300

from __future__ import annotations

import pytest

from hubproxy.config import ConfigError, Settings, parse_allow

GOOD_PW = "x" * 24


def test_valid_allow_lists() -> None:
    assert parse_allow("hub.selfhostr.io:443") == ("hub.selfhostr.io:443",)
    assert parse_allow("HUB.selfhostr.io, feeds.selfhostr.io:443") == (
        "hub.selfhostr.io:443",
        "feeds.selfhostr.io:443",
    )
    assert parse_allow("a.example.org,a.example.org") == ("a.example.org:443",)


@pytest.mark.parametrize(
    "value",
    [
        "",
        " , ",
        "a.example.org,b.example.org,c.example.org",
        "hub.selfhostr.io:80",
        "hub.selfhostr.io:8443",
        "203.0.113.5",
        "203.0.113.5:443",
        "[2001:db8::1]:443",
        "2001:db8::1",
        "localhost",
        "intranet",
        "printer.local",
        "svc.internal",
        "host.home.arpa",
        "-bad.example.org",
        "bad_name.example.org",
        "a..example.org",
        "example.org.",
        "1.2.3.456",
        "*.example.org",
        "a" * 64 + ".example.org",
    ],
)
def test_invalid_allow_lists_are_refused(value: str) -> None:
    with pytest.raises(ConfigError):
        parse_allow(value)


def test_settings_from_env() -> None:
    s = Settings.from_env(
        {
            "HUBPROXY_ALLOW": "hub.selfhostr.io",
            "HUBPROXY_PASSWORD": GOOD_PW,
            "HUBPROXY_MAX_CONNS": "4",
        }
    )
    assert s.allow == ("hub.selfhostr.io:443",) and s.max_conns == 4


@pytest.mark.parametrize(
    "env",
    [
        {"HUBPROXY_PASSWORD": GOOD_PW},
        {"HUBPROXY_ALLOW": "hub.selfhostr.io"},
        {"HUBPROXY_ALLOW": "hub.selfhostr.io", "HUBPROXY_PASSWORD": "short"},
        {
            "HUBPROXY_ALLOW": "hub.selfhostr.io",
            "HUBPROXY_PASSWORD": GOOD_PW,
            "HUBPROXY_MAX_CONNS": "0",
        },
        {
            "HUBPROXY_ALLOW": "hub.selfhostr.io",
            "HUBPROXY_PASSWORD": GOOD_PW,
            "HUBPROXY_MAX_CONNS": "x",
        },
        {
            "HUBPROXY_ALLOW": "hub.selfhostr.io",
            "HUBPROXY_PASSWORD": GOOD_PW,
            "HUBPROXY_MAX_CONNS": "65",
        },
    ],
)
def test_bad_settings_are_refused(env: dict[str, str]) -> None:
    with pytest.raises(ConfigError):
        Settings.from_env(env)


def test_error_messages_never_contain_the_password() -> None:
    with pytest.raises(ConfigError) as exc:
        Settings.from_env({"HUBPROXY_ALLOW": "203.0.113.5", "HUBPROXY_PASSWORD": GOOD_PW})
    assert GOOD_PW not in str(exc.value)

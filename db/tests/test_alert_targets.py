"""Webhook and e-mail validation, and the channel target encryption."""

import os

import pytest

from suckerpot_db.alert_targets import (
    TargetError,
    decrypt_target,
    encrypt_target,
    is_public_ip,
    target_hint,
    validate_email,
    validate_webhook,
)
from suckerpot_db.secretbox import SecretBox, SecretError

TOKEN = "A" * 24 + "b-_" + "c" * 20
DISCORD = f"https://discord.com/api/webhooks/123456789012345678/{TOKEN}"
TEAMS_WORKFLOW = (
    "https://prod-12.westeurope.logic.azure.com:443/workflows/"
    "0123456789abcdef0123456789abcdef/triggers/manual/paths/invoke?api-version=2016-06-01&sig=abc"
)
TEAMS_CONNECTOR = "https://example.webhook.office.com/webhookb2/0123456789abcdef-0123456789abcdef@tenant/IncomingWebhook/x/y"


def test_official_urls_are_accepted() -> None:
    assert validate_webhook("discord", DISCORD).host == "discord.com"
    assert validate_webhook("discord", DISCORD.replace("discord.com", "ptb.discord.com"))
    assert validate_webhook("teams", TEAMS_WORKFLOW).host.endswith(".logic.azure.com")
    assert validate_webhook("teams", TEAMS_CONNECTOR)


@pytest.mark.parametrize(
    "url",
    [
        DISCORD.replace("https", "http"),
        DISCORD.replace("discord.com", "discord.com.evil.example"),
        DISCORD.replace("discord.com", "evildiscord.com"),
        DISCORD.replace("https://", "https://user:pw@"),
        DISCORD.replace("https://", "https://discord.com@evil.example/#"),
        DISCORD.replace("discord.com", "discord.com:8080"),
        DISCORD + "?x=1",
        DISCORD + "#frag",
        DISCORD.replace("/api/", "/api/../"),
        DISCORD.replace("discord.com", "192.0.2.10"),
        DISCORD.replace("discord.com", "[::1]"),
        DISCORD.replace("discord.com", "localhost"),
        DISCORD.replace("/webhooks/", "/other/"),
        DISCORD.replace("webhooks", "web%68ooks"),
        DISCORD + " ",
        DISCORD.replace("discord.com", "d\u0456scord.com"),  # Cyrillic i
        "",
        "ftp://discord.com/x",
        TEAMS_WORKFLOW,  # a Teams URL is not a Discord one
    ],
)
def test_bad_discord_urls_are_refused(url: str) -> None:
    with pytest.raises(TargetError):
        validate_webhook("discord", url)


@pytest.mark.parametrize(
    "url",
    [
        TEAMS_WORKFLOW.replace("https", "http"),
        TEAMS_WORKFLOW.replace("logic.azure.com", "logic.azure.com.evil.example"),
        TEAMS_WORKFLOW.replace("prod-12.westeurope.logic.azure.com", "logic.azure.com"),
        TEAMS_WORKFLOW.replace("prod-12.westeurope.logic.azure.com", "198.51.100.7"),
        TEAMS_WORKFLOW.replace("/workflows/", "/admin/"),
        TEAMS_WORKFLOW + "#x",
        DISCORD,
        "https://evil.example/workflows/0123456789abcdef0123456789abcdef",
    ],
)
def test_bad_teams_urls_are_refused(url: str) -> None:
    with pytest.raises(TargetError):
        validate_webhook("teams", url)


def test_percent_escapes_in_a_teams_query_are_checked() -> None:
    ok = TEAMS_WORKFLOW.replace("sig=abc", "sig=a%2Bb%3D")
    assert validate_webhook("teams", ok)
    for bad in ("sig=a%2", "sig=a%zz", "sig=%"):
        with pytest.raises(TargetError):
            validate_webhook("teams", TEAMS_WORKFLOW.replace("sig=abc", bad))


def test_unknown_kind_is_refused() -> None:
    with pytest.raises(TargetError):
        validate_webhook("slack", DISCORD)


@pytest.mark.parametrize("address", ["analyst@example.org", "a.b+c@sub.example.co"])
def test_good_addresses(address: str) -> None:
    assert validate_email(address) == address


@pytest.mark.parametrize(
    "address",
    [
        "no-at-sign",
        "a@b",
        "a@example.org\nBcc: x@example.org",
        "A <a@example.org>",
        "a@example.org,b@example.org",
        "a b@example.org",
        "",
        "a@" + "x" * 300 + ".org",
    ],
)
def test_bad_addresses(address: str) -> None:
    with pytest.raises(TargetError):
        validate_email(address)


def test_hints_do_not_reveal_the_secret() -> None:
    assert target_hint("discord", DISCORD) == "discord.com"
    assert TOKEN not in target_hint("discord", DISCORD)
    assert target_hint("email", "analyst@example.org") == "a***@example.org"


@pytest.mark.parametrize(
    ("ip", "public"),
    [
        ("8.8.8.8", True),
        ("2606:4700::1111", True),
        ("10.0.0.1", False),  # gitleaks:allow (private range must be refused)
        ("192.168.1.1", False),  # gitleaks:allow (private range must be refused)
        ("172.16.5.5", False),  # gitleaks:allow (private range must be refused)
        ("127.0.0.1", False),
        ("169.254.169.254", False),
        ("100.64.0.1", False),
        ("0.0.0.0", False),
        ("::1", False),
        ("fe80::1", False),
        ("fc00::1", False),
        ("::ffff:10.0.0.1", False),  # gitleaks:allow (private range must be refused)
        ("224.0.0.1", False),
        ("not an ip", False),
    ],
)
def test_public_ip_check(ip: str, public: bool) -> None:
    assert is_public_ip(ip) is public


def test_target_encryption_is_bound_to_the_channel() -> None:
    box = SecretBox(os.urandom(32))
    blob = encrypt_target(box, 7, DISCORD)
    assert 29 <= len(blob) <= 2048
    assert DISCORD.encode() not in blob
    assert decrypt_target(box, 7, blob) == DISCORD
    with pytest.raises(SecretError):
        decrypt_target(box, 8, blob)
    with pytest.raises(SecretError):
        decrypt_target(SecretBox(os.urandom(32)), 7, blob)
    with pytest.raises(SecretError):
        decrypt_target(box, 7, b"short")

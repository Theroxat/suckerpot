"""M25 validation helpers: the SMTP host must be a public DNS name, the sender a real mailbox."""

import pytest

from api.abuse_smtp import valid_host, valid_mailbox


@pytest.mark.parametrize(
    "host", ["smtp.example.org", "mail.example.net", "smtp-2.mail.example.org", "SMTP.Example.Org"]
)
def test_public_names_are_accepted(host: str) -> None:
    assert valid_host(host)


@pytest.mark.parametrize(
    "host",
    [
        "", "mail", "localhost", "192.0.2.10", "2130706433", "0x7f.0.0.1", "1.2.3.4", "[::1]",
        "::1", "mail.local", "mail.internal", "mail.lan", "mail.localdomain", "mail.home.arpa",
        "host.corp", "-a.example.org", "a-.example.org", "a_b.example.org",
        "mail.example.org.", "a..example.org", "a" * 64 + ".example.org", ("a." * 130) + "org",
        "smtp.example.org:587", "smtp.example.org/x", "smtp@example.org",
    ],
)  # fmt: skip
def test_ip_literals_single_labels_and_internal_names_are_refused(host: str) -> None:
    assert not valid_host(host)


@pytest.mark.parametrize("value", ["ops@mail.example.org", "a.b+c@example.net"])
def test_mailboxes_accepted(value: str) -> None:
    assert valid_mailbox(value)


@pytest.mark.parametrize(
    "value",
    ["", "ops", "ops@", "@example.org", "ops@localhost", "ops@mail.internal", "ops@192.0.2.1",
     "a b@example.org", "ops@example.org\r\nBcc: x@example.org", "Name <ops@example.org>"],
)  # fmt: skip
def test_mailboxes_refused(value: str) -> None:
    assert not valid_mailbox(value)

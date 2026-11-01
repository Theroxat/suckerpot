"""Who may speak for a recipient (M26 review): exact domains, exact addresses on shared domains,
and what each kind of match is allowed to verify."""

from __future__ import annotations

from suckerpot_db.shared_mail import is_shared_domain

from ingest.replies.match import Match, Trust, from_known_recipient, is_verified, trust_of
from ingest.replies.parse import ParsedReply


def reply(address: str, auth: str = "none") -> ParsedReply:
    return ParsedReply(from_address=address, from_domain=address.rpartition("@")[2], auth=auth)


def test_trust_is_by_exact_domain() -> None:
    trust = trust_of("abuse@provider.example.net")
    assert trust.covers("noc@provider.example.net", "provider.example.net")
    assert not trust.covers("x@desk.provider.example.net", "desk.provider.example.net")
    assert not trust.covers("x@example.net", "example.net")


def test_a_listed_domain_is_exact_and_an_entry_with_an_at_is_an_address() -> None:
    trust = trust_of(
        "abuse@zendesk.example.com", extra=["acme.zendesk.example.com", "Ops@Acme.Example.Org"]
    )
    assert trust.covers("a@acme.zendesk.example.com", "acme.zendesk.example.com")
    assert trust.covers("ops@acme.example.org", "acme.example.org")
    assert not trust.covers("other@acme.example.org", "acme.example.org")


def test_a_shared_mail_domain_is_never_trusted_as_a_domain() -> None:
    trust = trust_of("abuse-desk@gmail.com", extra=["gmail.com", "outlook.com"])
    assert trust.domains == frozenset()
    assert trust.addresses == frozenset({"abuse-desk@gmail.com"})
    assert trust.covers("abuse-desk@gmail.com", "gmail.com")
    assert not trust.covers("someone@gmail.com", "gmail.com")
    assert is_shared_domain("mail.yahoo.com") and not is_shared_domain("notgmail.com")


def test_a_free_mail_recipient_makes_no_sender_known() -> None:
    from ingest.replies.match import RecentReport

    recent = [RecentReport(1, trust_of("abuse-desk@gmail.com"))]
    assert not from_known_recipient(reply("random@gmail.com"), recent)
    assert from_known_recipient(reply("abuse-desk@gmail.com"), recent)


def test_what_each_match_may_verify() -> None:
    trust = Trust(frozenset({"example.net"}))
    ours = Match(1, "message_id", True)
    assert is_verified(ours, reply("a@example.net"), trust)
    assert not is_verified(ours, reply("a@evil.example.org", "pass"), trust)  # passes, not theirs
    dsn = Match(1, "dsn", True)
    assert is_verified(dsn, reply("mailer-daemon@mx.example.org", "pass"), trust)
    assert is_verified(dsn, reply("mailer-daemon@example.net"), trust)
    assert not is_verified(dsn, reply("mailer-daemon@mx.example.org"), trust)
    token = Match(1, "token")
    assert not is_verified(token, reply("a@example.net"), trust)  # needs authentication too
    assert is_verified(token, reply("a@example.net", "pass"), trust)
    assert not is_verified(Match(None, "none"), reply("a@example.net", "pass"), trust)

"""Who may speak for a recipient (M26 review): exact domains, exact addresses on shared domains,
and what each kind of match is allowed to verify."""

from __future__ import annotations

from dataclasses import replace

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
    bounce = ParsedReply(
        from_address="mailer-daemon@mx.example.org",
        from_domain="mx.example.org",
        content_type="multipart/report",
        dsn_action="failed",
        auth="pass",
    )
    assert is_verified(ours, bounce, trust, "bounce")  # answers our Message-ID, authenticated
    assert not is_verified(ours, replace(bounce, auth="none"), trust, "bounce")
    assert is_verified(dsn, bounce, trust, "bounce")  # a bounce-shaped mail, authenticated
    assert not is_verified(dsn, replace(bounce, auth="none"), trust, "bounce")
    # A plain reply with a "dsn" match is not a bounce: authentication alone never vouches.
    assert not is_verified(dsn, reply("mailer-daemon@mx.example.org", "pass"), trust, "bounce")
    from_us = replace(bounce, from_address="mailer-daemon@example.net", from_domain="example.net")
    assert is_verified(dsn, replace(from_us, auth="none"), trust, "bounce")
    assert not is_verified(dsn, reply("mailer-daemon@mx.example.org"), trust)
    token = Match(1, "token")
    assert not is_verified(token, reply("a@example.net"), trust)  # needs authentication too
    assert is_verified(token, reply("a@example.net", "pass"), trust)
    assert not is_verified(Match(None, "none"), reply("a@example.net", "pass"), trust)


def test_a_mixed_mail_attaching_our_message_is_not_verified_by_auth_alone() -> None:
    trust = Trust(frozenset({"example.net"}))
    attached = ParsedReply(
        from_address="attacker@evil.example.org",
        from_domain="evil.example.org",
        content_type="multipart/mixed",
        auth="pass",
        dsn_message_id="<ours@example.net>",
    )
    for method in ("dsn", "message_id"):
        assert not is_verified(Match(1, method, True), attached, trust, "resolved")
        assert not is_verified(Match(1, method, True), attached, trust, "bounce")


def test_auth_alone_verifies_only_a_bounce_classification() -> None:
    trust = Trust(frozenset({"example.net"}))
    found = Match(1, "message_id", True)
    report = ParsedReply(
        from_address="mailer-daemon@mx.example.org",
        from_domain="mx.example.org",
        content_type="multipart/report",
        dsn_action="delivered",
        auth="pass",
    )
    assert is_verified(found, report, trust, "bounce")
    for outcome in ("resolved", "rejected", "acknowledged"):
        assert not is_verified(found, report, trust, outcome)
    assert not is_verified(found, report, trust)  # no classification given: not a bounce
    # A party we wrote to still speaks for any classification.
    ours = replace(report, from_address="a@example.net", from_domain="example.net", auth="none")
    assert is_verified(found, ours, trust, "resolved")

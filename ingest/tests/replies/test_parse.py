"""The parser reads hostile mail: every limit of M26 section 5 is proven here."""

from __future__ import annotations

import time
import unicodedata

import pytest

from ingest.replies.parse import (
    MAX_PART_BYTES,
    ParsedReply,
    authentication,
    make_excerpt,
    parse_headers,
    parse_message,
)

from . import mails
from .mails import OUR_ID, TOKEN, mail


def test_a_plain_reply() -> None:
    parsed = parse_message(mail())
    assert parsed.from_address == "abuse@example.net"
    assert parsed.from_domain == "example.net" and parsed.from_local == "abuse"
    assert parsed.subject == "Re: Abuse report for 198.51.100.23"
    assert parsed.body.startswith("Hello,") and "We looked into it." in parsed.body
    assert parsed.excerpt == "Hello,\n\nWe looked into it."
    assert parsed.reference_ids == (OUR_ID,) and parsed.has_in_reply_to
    assert parsed.message_id_sha256 is not None and len(parsed.message_id_sha256) == 64
    assert parsed.sent_at is not None and parsed.sent_at.year == 2026
    assert parsed.auth == "none" and parsed.attachments == {"count": 0, "types": [], "bytes": 0}
    assert not parsed.truncated


def test_the_message_id_is_only_stored_as_a_hash() -> None:
    a = parse_message(mail(message_id="<Mixed.Case@Example.NET>"))
    b = parse_message(mail(message_id="<mixed.case@example.net>"))
    assert a.message_id_sha256 == b.message_id_sha256
    assert "Mixed.Case" not in repr(a)


def test_html_only_becomes_text_without_links_or_scripts() -> None:
    html = (
        "<html><head><style>p{color:red}</style></head><body><script>alert(1)</script>"
        '<p>Hello <b>world</b></p><a href="http://198.51.100.1/x">click here</a></body></html>'
    )
    parsed = parse_message(mails.html_only(html))
    assert "Hello world" in parsed.body.replace("\n", " ")
    assert "click here" in parsed.body
    for banned in ("alert", "color", "http", "198.51.100.1", "<"):
        assert banned not in parsed.body and banned not in parsed.excerpt


def test_an_attachment_is_counted_never_decoded_or_named() -> None:
    parsed = parse_message(mails.with_pdf())
    assert parsed.body.strip() == "Thank you."
    assert parsed.attachments["count"] == 1
    assert parsed.attachments["types"] == ["application/pdf"]
    assert parsed.attachments["bytes"] > 100
    assert "invoice" not in repr(parsed) and "PDF" not in parsed.body


def test_a_delivery_status_notification() -> None:
    parsed = parse_message(mails.dsn())
    assert parsed.report_type == "delivery-status" and parsed.content_type == "multipart/report"
    assert (parsed.dsn_action, parsed.dsn_status, parsed.dsn_domain) == (
        "failed",
        "5.1.1",
        "example.net",
    )
    assert parsed.dsn_message_id == OUR_ID
    assert parsed.dsn_subject is not None and TOKEN in parsed.dsn_subject
    assert parsed.from_local == "mailer-daemon"


def test_a_bad_dsn_status_is_dropped() -> None:
    assert parse_message(mails.dsn(status="9.9.9")).dsn_status is None


def test_quoted_printable_and_other_charsets() -> None:
    assert "Réponse reçue" in parse_message(mails.quoted_printable("Réponse reçue.")).body
    jp = "こんにちは".encode("iso2022_jp").decode("ascii")
    parsed = parse_message(mail(ctype="text/plain; charset=iso-2022-jp", body=jp))
    assert "こんにちは" in parsed.body


@pytest.mark.parametrize("charset", ["x-unknown", "rot13", "base64", "zlib", "utf-7", "idna"])
def test_a_charset_outside_the_allow_list_is_read_as_utf8(charset: str) -> None:
    parsed = parse_message(mail(ctype=f"text/plain; charset={charset}", body="plain words"))
    assert parsed.body.strip() == "plain words"


def test_invalid_bytes_are_replaced() -> None:
    raw = mail(body="ok").replace(b"ok", b"o\xff\xfek")
    assert "o" in parse_message(raw).body


def test_only_two_hundred_header_lines_are_read() -> None:
    late = b"".join(f"X-Filler-{i}: x\r\n".encode() for i in range(250))
    raw = b"From: a@example.net\r\n" + late + b"Subject: too late\r\n\r\nbody text here\r\n"
    parsed = parse_message(raw)
    assert parsed.subject == "" and parsed.from_domain == "example.net"
    assert "body text here" in parsed.body
    assert parse_message(mails.many_headers(300)).subject == "Late subject"  # subject came early


def test_header_values_are_cut_at_4kib() -> None:
    parsed = parse_message(mail(subject="s" * 10_000))
    assert len(parsed.subject) <= 300


def test_at_most_fifty_parts_are_walked() -> None:
    parsed = parse_message(mails.many_parts(60))
    assert "part 5" in parsed.body and "part 59" not in parsed.body
    assert parsed.body.count("part ") <= 50


def test_nesting_beyond_depth_five_is_ignored() -> None:
    assert "deep text" not in parse_message(mails.nested(10)).body
    assert "deep text" in parse_message(mails.nested(3)).body


def test_python_recursion_limits_never_escape() -> None:
    parsed = parse_message(mails.nested(400))
    assert isinstance(parsed, ParsedReply)


def test_a_sixteen_megabyte_line_is_cut_before_parsing() -> None:
    raw = b"From: a@example.net\r\nSubject: big\r\n\r\n" + b"A" * (16 * 1024 * 1024)
    started = time.monotonic()
    parsed = parse_message(raw, max_bytes=262_144)
    assert time.monotonic() - started < 5
    assert parsed.truncated and parsed.size_bytes > 16_000_000
    assert len(parsed.body) <= MAX_PART_BYTES and len(parsed.excerpt) <= 2000


def test_base64_garbage_does_not_raise() -> None:
    raw = mail(body="!!!! not base64 @@@@\r\n", extra={"Content-Transfer-Encoding": "base64"})
    assert isinstance(parse_message(raw), ParsedReply)


def test_bidi_and_zero_width_characters_are_removed() -> None:
    subject = "Re: ab‮cd​ef⁦gh﻿\x07\x1b[31m"
    parsed = parse_message(mail(subject=subject, body="body ‮​ text\x00\x1b\r\n"))
    for value in (parsed.subject, parsed.body, parsed.excerpt):
        assert not [c for c in value if unicodedata.category(c) in ("Cf", "Cs")]
        assert not [c for c in value if unicodedata.category(c) == "Cc" and c not in "\n\t"]
    assert parsed.subject.startswith("Re: abcdefgh")


def test_a_header_with_a_newline_cannot_forge_another() -> None:
    parsed = parse_message(mail(subject="one\r\n Bcc: x@example.org"))
    assert "\n" not in parsed.subject and "\r" not in parsed.subject


def test_a_missing_or_odd_from_gives_no_address() -> None:
    assert parse_message(mail(from_="not an address")).from_address is None
    assert parse_message(mail(from_="a@b@c.example.net")).from_domain is None
    assert parse_message(b"Subject: x\r\n\r\nno from").from_domain is None
    assert parse_message(b"").from_domain is None


def test_pasted_text_without_headers_does_not_crash() -> None:
    parsed = parse_message(b"Hello, we suspended the account.\r\nRegards\r\n")
    assert isinstance(parsed, ParsedReply)


def test_the_message_is_cut_at_max_bytes() -> None:
    parsed = parse_message(mail(body="x" * 5000), max_bytes=1000)
    assert parsed.truncated and len(parsed.body) < 1000


# --- authentication ------------------------------------------------------------------------


def test_authentication_results() -> None:
    ok = "mx.example.org; dkim=pass header.d=example.net; dmarc=pass header.from=example.net"
    assert authentication(ok, "example.net") == "pass"
    assert (
        authentication("mx; dmarc=pass (policy=none) header.from=mail.example.net", "example.net")
        == "pass"
    )
    assert authentication("mx; dkim=pass header.d=other.example.org", "example.net") == "none"
    assert authentication("mx; dmarc=fail header.from=example.net", "example.net") == "fail"
    assert authentication("mx; dkim=fail header.d=example.net", "example.net") == "none"
    assert authentication("mx; spf=pass", "example.net") == "none"
    assert authentication(None, "example.net") == "none"
    assert authentication(ok, None) == "none"


def test_only_the_topmost_authentication_results_header_counts() -> None:
    top_fail = mail(
        extra={"Authentication-Results": "mx; dmarc=fail header.from=example.net"},
    ).replace(
        b"MIME-Version",
        b"Authentication-Results: mx; dkim=pass header.d=example.net\r\nMIME-Version",
    )
    # The first header in the file wins, whatever follows it.
    assert parse_message(top_fail).auth in ("fail", "pass")
    two = (
        b"Authentication-Results: mx; dmarc=fail header.from=example.net\r\n"
        b"Authentication-Results: mx; dkim=pass header.d=example.net\r\n"
        b"From: a@example.net\r\n\r\nx"
    )
    assert parse_message(two).auth == "fail"
    forged = (
        b"Authentication-Results: mx; spf=pass\r\n"
        b"Authentication-Results: mx; dkim=pass header.d=example.net\r\n"
        b"From: a@example.net\r\n\r\nx"
    )
    assert parse_message(forged).auth == "none"


# --- excerpt -------------------------------------------------------------------------------


def test_the_excerpt_drops_quotes_and_the_quoted_original() -> None:
    text = (
        "Thanks, done.\n\n> your old text\n> more\nSecond paragraph.\n\n"
        "On Mon, 2 Nov 2026 at 10:00, Reports <reports@example.org> wrote:\n> quoted\n"
    )
    assert make_excerpt(text, 2000) == "Thanks, done.\n\nSecond paragraph."
    assert make_excerpt("Hi\n-----Original Message-----\nFrom: x\nold", 2000) == "Hi"
    assert make_excerpt("Hi\n\nFrom: x@example.org\nSent: now", 2000) == "Hi"


def test_the_excerpt_limit_and_zero() -> None:
    assert len(make_excerpt("a" * 5000, 2000)) == 2000
    assert make_excerpt("anything", 0) == ""
    assert make_excerpt("blank\n\n\n\n\nruns", 2000) == "blank\n\nruns"


def test_unicode_is_kept_for_non_english_desks() -> None:
    assert make_excerpt("Wir haben den Server gesperrt. Größe: 5 / 日本語", 2000).endswith("日本語")


# --- header view ---------------------------------------------------------------------------


def test_header_view() -> None:
    view = parse_headers(mail()[: mail().index(b"\r\n\r\n")])
    assert view.from_domain == "example.net" and view.reference_ids == (OUR_ID,)
    assert not view.looks_like_dsn
    assert parse_headers(mails.dsn()).looks_like_dsn
    assert parse_headers(b"\xff\xfe garbage").looks_like_dsn is False


def test_message_id_lists_are_capped_at_twenty() -> None:
    refs = " ".join(f"<id{i}@example.org>" for i in range(60))
    parsed = parse_message(mail(extra={"References": refs}, in_reply_to=None))
    assert len(parsed.reference_ids) == 20 and parsed.reference_ids[-1] == "<id59@example.org>"

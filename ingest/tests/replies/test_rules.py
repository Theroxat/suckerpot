"""Reply classification: every default rule, precedence, ticket extraction, the loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from ingest.replies.parse import ParsedReply, parse_message
from ingest.replies.rules import (
    ReplyRules,
    TicketRule,
    find_ticket,
    load_reply_rules,
    parse_chars,
)
from ingest.tagging.engine import RuleError

from . import mails
from .mails import mail

RULES_DIR = Path(__file__).resolve().parents[2] / "rules" / "replies"


@pytest.fixture(scope="module")
def rules() -> ReplyRules:
    return load_reply_rules(RULES_DIR)


def classify(rules: ReplyRules, raw: bytes, *, matched: bool = True) -> tuple[str, str | None]:
    verdict = rules.classify(parse_message(raw), matched=matched)
    return verdict.outcome, verdict.rule_id


def test_the_shipped_rules_load(rules: ReplyRules) -> None:
    assert [r.priority for r in rules.rules] == sorted(r.priority for r in rules.rules)
    assert {r.outcome for r in rules.rules} == {
        "bounce",
        "resolved",
        "rejected",
        "ticket_opened",
        "auto_ack",
    }
    assert rules.description("auto-ack") == "An automatic acknowledgement."


def test_bounce_by_dsn_and_by_daemon(rules: ReplyRules) -> None:
    assert classify(rules, mails.dsn()) == ("bounce", "bounce-dsn")
    # A delay notice is not a bounce.
    assert classify(rules, mails.dsn(action="delayed"))[0] != "bounce"
    daemon = mail(from_="postmaster@example.net", subject="Mail delivery failed: returning message")
    assert classify(rules, daemon) == ("bounce", "bounce-daemon")


@pytest.mark.parametrize(
    "phrase",
    [
        "the address has been suspended",
        "The server HAS BEEN TERMINATED today",
        "we have taken action against the customer",
        "traffic is null-routed now",
        "the issue has been resolved",
    ],
)
def test_resolved(rules: ReplyRules, phrase: str) -> None:
    assert classify(rules, mail(body=f"Hello,\r\n\r\n{phrase}.\r\n")) == (
        "resolved",
        "resolved-action-taken",
    )


def test_resolved_by_subject(rules: ReplyRules) -> None:
    assert classify(rules, mail(subject="Case 4411 resolved"))[0] == "resolved"


@pytest.mark.parametrize(
    ("phrase", "rule"),
    [
        ("this is not our customer", "not-our-customer"),
        ("the range is not hosted by us", "not-our-customer"),
        ("we have insufficient evidence", "insufficient-evidence"),
        ("please use our web form", "form-required"),
        ("Please submit via our portal", "form-required"),
    ],
)
def test_rejected(rules: ReplyRules, phrase: str, rule: str) -> None:
    assert classify(rules, mail(body=f"{phrase}\r\n")) == ("rejected", rule)


def test_ticket_opened_by_an_automatic_message_with_an_id(rules: ReplyRules) -> None:
    raw = mail(
        subject="[#48213] We received your report",
        extra={"Auto-Submitted": "auto-replied"},
        body="Thanks. Your ticket has been created.\r\n",
    )
    parsed = parse_message(raw)
    assert rules.extract_ticket(parsed) == "48213"
    assert rules.classify(parsed, matched=True).outcome == "ticket_opened"
    assert rules.classify(parsed, matched=True).ticket_id == "48213"


def test_an_auto_acknowledgement_with_a_ticket_number_is_a_ticket(rules: ReplyRules) -> None:
    raw = mail(
        subject="Automatic reply: your report",
        extra={"Auto-Submitted": "auto-generated"},
        body="Ticket #AB-1234 was opened.\r\n",
    )
    assert classify(rules, raw)[0] == "ticket_opened"
    # Without a number the same mail is only an acknowledgement.
    plain = mail(subject="Automatic reply: your report", extra={"Auto-Submitted": "auto-replied"})
    assert classify(rules, plain) == ("auto_ack", "auto-ack")


@pytest.mark.parametrize(
    "raw",
    [
        mail(extra={"Auto-Submitted": "auto-replied"}),
        mail(extra={"X-Autoreply": "yes"}),
        mail(extra={"Precedence": "auto_reply"}),
        mail(extra={"Precedence": "bulk"}),
        mail(subject="Out of Office"),
        mail(subject="Automatische Antwort: Abuse"),
        mail(subject="Réponse automatique : abus"),
        mail(subject="Respuesta automática"),
        mail(subject="Automatisch antwoord"),
        mail(subject="Resposta automática"),
        mail(body="This is an automated message.\r\n"),
        mail(body="Please do not reply to this mailbox.\r\n"),
    ],
)
def test_auto_ack(rules: ReplyRules, raw: bytes) -> None:
    assert classify(rules, raw) == ("auto_ack", "auto-ack")


def test_a_human_answer_that_says_terminated_is_resolved(rules: ReplyRules) -> None:
    raw = mail(body="Hi, thanks for the report. The service was terminated this morning.\r\n")
    assert classify(rules, raw)[0] == "resolved"


def test_precedence_bounce_then_resolved_then_rejected_then_ticket_then_ack(
    rules: ReplyRules,
) -> None:
    both = mail(
        subject="Automatic reply",
        extra={"Auto-Submitted": "auto-replied"},
        body="The account has been suspended. This is not our customer. Ticket #7788.\r\n",
    )
    assert classify(rules, both)[0] == "resolved"
    rejected = mail(
        extra={"Auto-Submitted": "auto-replied"},
        body="Not our customer. Ticket #7788 opened. This is an automated message.\r\n",
    )
    assert classify(rules, rejected)[0] == "rejected"


def test_fallbacks(rules: ReplyRules) -> None:
    human = mail(body="Hi, could you tell me which log lines you saw? Thanks!\r\n")
    assert classify(rules, human) == ("human_reply", None)
    assert classify(rules, mail(body="ok\r\n")) == ("unknown", None)  # too short
    assert classify(rules, mail(from_="nobody", body="x" * 50)) == ("unknown", None)


def test_the_matched_field_is_available_to_rules(tmp_path: Path) -> None:
    (tmp_path / "10.yaml").write_text(
        "rules:\n  - id: r1\n    outcome: rejected\n    priority: 5\n"
        "    when: {field: matched, equals: false}\n"
    )
    rules = load_reply_rules(tmp_path)
    parsed = ParsedReply(from_domain="example.net", body="x" * 40)
    assert rules.classify(parsed, matched=False).outcome == "rejected"
    assert rules.classify(parsed, matched=True).outcome == "human_reply"


# --- ticket extraction ---------------------------------------------------------------------

GENERIC = TicketRule(
    "t", ("ticket #", "case:", "[#"), ("subject", "body"), 4, 32, parse_chars("A-Za-z0-9-_")
)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Your Ticket #48213 is open", "48213"),
        ("Case: INC-0042-X, thanks", "inc-0042-x"),
        ("[#99120] re: report", "99120"),
        ("ticket # 1234567", "1234567"),
        ("case: closed", None),  # no digit
        ("ticket #12", None),  # too short
        ("ticket #" + "9" * 80, None),  # too long
        ("nothing here", None),
    ],
)
def test_find_ticket(text: str, expected: str | None) -> None:
    assert find_ticket(text, GENERIC) == expected


def test_parse_chars() -> None:
    chars = parse_chars("A-Za-z0-9-_")
    assert {"A", "Z", "a", "0", "9", "-", "_"} <= chars and "." not in chars and " " not in chars
    with pytest.raises(RuleError):
        parse_chars("z-a")


# --- the loader refuses a bad file ---------------------------------------------------------

GOOD = "rules:\n  - id: r\n    outcome: rejected\n    priority: 5\n    when: {field: body, contains: x}\n"


def write(tmp_path: Path, content: str) -> Path:
    (tmp_path / "10-x.yaml").write_text(content)
    return tmp_path


@pytest.mark.parametrize(
    "content",
    [
        "rules: not-a-list\n",
        "unknown_key: []\n",
        GOOD.replace("outcome: rejected", "outcome: pwned"),
        GOOD.replace("priority: 5", "priority: 0"),
        GOOD.replace("priority: 5", "priority: 1000"),
        GOOD.replace("priority: 5", "priority: high"),
        GOOD.replace("body", "data.input"),  # a tagging field, not a reply field
        GOOD.replace("contains: x", "regex: x"),  # no regular expressions
        GOOD.replace("contains: x", "contains: 5"),
        GOOD.replace("    priority: 5\n", "    priority: 5\n    extra: 1\n"),
        GOOD + GOOD.split("rules:\n")[1],  # duplicate id
        "rules:\n  - outcome: rejected\n    priority: 1\n    when: {field: body, contains: x}\n",
        "tickets:\n  - id: t\n    after: []\n",
        "tickets:\n  - id: t\n    after: [x]\n    fields: [headers]\n",
        "tickets:\n  - id: t\n    after: [x]\n    min_len: 9\n    max_len: 3\n",
        "tickets:\n  - id: t\n    after: [x]\n    surprise: true\n",
        "{{{{ not yaml",
    ],
)
def test_the_loader_refuses(tmp_path: Path, content: str) -> None:
    with pytest.raises(RuleError):
        load_reply_rules(write(tmp_path, content))


def test_too_many_rules(tmp_path: Path) -> None:
    items = "".join(
        f"  - id: r{i}\n    outcome: rejected\n    priority: 5\n"
        f"    when: {{field: body, contains: x}}\n"
        for i in range(201)
    )
    with pytest.raises(RuleError):
        load_reply_rules(write(tmp_path, "rules:\n" + items))


def test_a_good_file_loads(tmp_path: Path) -> None:
    assert len(load_reply_rules(write(tmp_path, GOOD)).rules) == 1


def test_the_tagging_loader_ignores_the_replies_folder() -> None:
    from ingest.tagging.engine import load_rules

    load_rules(RULES_DIR.parent)  # rules/replies/ is a subfolder: not read as tagging rules

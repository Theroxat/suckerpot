"""Outcome derivation: precedence, verified replies only, delays from the reply times."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ingest.replies.outcome import PRECEDENCE, ReplyFact, derive, summarise

T0 = datetime(2026, 11, 1, 8, 0, tzinfo=UTC)


def fact(kind: str, hours: float = 1, *, verified: bool = True, **kw: object) -> ReplyFact:
    return ReplyFact(kind, T0 + timedelta(hours=hours), verified, **kw)  # type: ignore[arg-type]


def test_nothing_is_none() -> None:
    assert derive([]) == "none"


def test_precedence_order() -> None:
    assert PRECEDENCE == (
        "resolved",
        "rejected",
        "ticket_opened",
        "human_reply",
        "auto_ack",
        "bounce",
        "unknown",
    )
    kinds = list(PRECEDENCE)
    for i, kind in enumerate(kinds):
        assert derive(fact(k) for k in kinds[i:]) == kind
        assert derive(fact(k) for k in reversed(kinds[i:])) == kind


def test_an_unverified_reply_never_changes_the_outcome() -> None:
    assert derive([fact("resolved", verified=False)]) == "none"
    assert derive([fact("auto_ack"), fact("resolved", verified=False)]) == "auto_ack"


def test_summary_times_come_from_verified_replies() -> None:
    s = summarise(
        [
            fact("auto_ack", 1),
            fact("ticket_opened", 3, ticket_id="48213"),
            fact("human_reply", 5),
            fact("resolved", 9),
            fact("resolved", 7, verified=False),
            fact("bounce", 2),
        ]
    )
    assert s.auto_outcome == "resolved" and s.reply_count == 6
    assert s.first_reply_at == T0 + timedelta(hours=1)  # a bounce is not an answer
    assert s.ticket_at == T0 + timedelta(hours=3) and s.ticket_id == "48213"
    assert s.first_human_at == T0 + timedelta(hours=5)
    assert s.resolved_at == T0 + timedelta(hours=9)
    assert s.bounced_at == T0 + timedelta(hours=2)
    assert s.rejected_at is None


def test_the_latest_ticket_id_wins() -> None:
    s = summarise(
        [fact("ticket_opened", 1, ticket_id="old-1"), fact("auto_ack", 4, ticket_id="new-2")]
    )
    assert s.ticket_id == "new-2"


def test_unverified_replies_and_bounces_need_review_until_reviewed() -> None:
    assert summarise([fact("resolved", verified=False)]).needs_review
    assert summarise([fact("bounce")]).needs_review
    assert not summarise([fact("bounce", reviewed=True)]).needs_review
    assert not summarise([fact("resolved", verified=False, reviewed=True)]).needs_review
    assert not summarise([fact("human_reply")]).needs_review
    assert not summarise([]).needs_review


@pytest.mark.parametrize("kind", PRECEDENCE)
def test_a_single_verified_reply_is_its_own_outcome(kind: str) -> None:
    assert derive([fact(kind)]) == kind

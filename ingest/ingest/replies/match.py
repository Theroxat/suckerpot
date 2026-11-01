"""Which report does a reply belong to, and can we vouch for it (design M26, section 7).

First hit wins: our own Message-ID, the reply token, a delivery status notification that
returns one of those, a ticket id we have seen from the same sender, and last the sender's
domain (only when exactly one recent report went to that domain). The answer to "may this reply
change an outcome" is separate: ``is_verified``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .parse import BODY_FOR_RULES, ParsedReply

# A token comes right after "ref", "ref:", "ref#" or "(ref". Bounded text, no nested repeats.
TOKEN: Final = re.compile(r"(?<![a-z0-9])ref[ :#]{0,3}([0-9a-f]{12})(?![0-9a-z])")
MAX_TOKENS: Final = 5
MAX_RECENT: Final = 5000
SECOND_LEVEL: Final = frozenset({"co", "com", "org", "net", "gov", "ac", "edu", "or", "ne", "go"})
METHODS: Final = ("message_id", "token", "dsn", "ticket", "sender_domain", "manual", "none")


@dataclass(frozen=True, slots=True)
class Match:
    report_id: int | None
    method: str = "none"
    via_message_id: bool = False


@dataclass(frozen=True, slots=True)
class RecentReport:
    id: int
    domains: frozenset[str]


NO_MATCH: Final = Match(None, "none")


def registrable(domain: str) -> str:
    """The domain an organisation owns: the last two labels, three under ``co.uk``-like suffixes.
    A heuristic without a public suffix list; it only decides who may speak for a recipient."""
    labels = [x for x in domain.lower().strip(".").split(".") if x]
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def domains_of(*values: str | None, extra: Iterable[str] = ()) -> frozenset[str]:
    """Registrable domains of mailboxes (``user@domain``) or bare domains."""
    out = {registrable(v.rpartition("@")[2]) for v in values if v and v.strip()}
    out.update(registrable(d) for d in extra if d)
    out.discard("")
    return frozenset(out)


def find_tokens(*texts: str) -> list[str]:
    """Reply tokens named in the texts, in order, at most five."""
    found: list[str] = []
    for value in texts:
        for token in TOKEN.findall(value[:BODY_FOR_RULES].lower()):
            if token not in found:
                found.append(token)
    return found[:MAX_TOKENS]


async def recent_reports(session: AsyncSession, days: int) -> list[RecentReport]:
    """Reports sent in the last ``days`` days with the domains their recipient can answer from."""
    rows = (
        await session.execute(
            text(
                "SELECT r.id, rec.mailbox, rec.override_mailbox, rec.reply_domains "
                "FROM abuse_reports r JOIN abuse_recipients rec ON rec.id = r.recipient_id "
                "WHERE r.status IN ('sent', 'closed') AND NOT r.demo "
                "AND r.sent_at >= now() - make_interval(days => :d) "
                "ORDER BY r.id DESC LIMIT :n"
            ),
            {"d": days, "n": MAX_RECENT},
        )
    ).all()
    return [
        RecentReport(r.id, domains_of(r.mailbox, r.override_mailbox, extra=r.reply_domains or ()))
        for r in rows
    ]


async def report_domains(session: AsyncSession, report_id: int) -> frozenset[str]:
    row = (
        await session.execute(
            text(
                "SELECT rec.mailbox, rec.override_mailbox, rec.reply_domains "
                "FROM abuse_reports r JOIN abuse_recipients rec ON rec.id = r.recipient_id "
                "WHERE r.id = :i"
            ),
            {"i": report_id},
        )
    ).first()
    if row is None:
        return frozenset()
    return domains_of(row.mailbox, row.override_mailbox, extra=row.reply_domains or ())


async def by_message_id(session: AsyncSession, ids: tuple[str, ...]) -> int | None:
    if not ids:
        return None
    row = (
        await session.execute(
            text(
                "SELECT report_id FROM abuse_send_requests WHERE message_id = ANY(:ids) "
                "AND status = 'sent' AND report_id IS NOT NULL ORDER BY id LIMIT 1"
            ),
            {"ids": list(ids)},
        )
    ).first()
    return None if row is None else int(row.report_id)


async def by_token(session: AsyncSession, tokens: list[str]) -> tuple[int | None, bool]:
    """``(report id, a token was found at all)``. A token of a report that is not sent or
    closed (a draft, a discarded one) is not a match."""
    if not tokens:
        return None, False
    rows = (
        await session.execute(
            text("SELECT id, status FROM abuse_reports WHERE reply_token = ANY(:t)"),
            {"t": tokens},
        )
    ).all()
    for row in rows:
        if row.status in ("sent", "closed"):
            return int(row.id), True
    return None, bool(rows)


async def find_match(
    session: AsyncSession,
    reply: ParsedReply,
    *,
    ticket: str | None,
    recent: list[RecentReport],
) -> Match:
    rid = await by_message_id(session, reply.reference_ids)
    if rid is not None:
        return Match(rid, "message_id", True)
    rid, seen = await by_token(session, find_tokens(reply.subject, reply.body))
    if rid is not None:
        return Match(rid, "token")
    if seen:
        return NO_MATCH  # the token names a report that was never sent: nothing to link
    if reply.dsn_message_id:
        rid = await by_message_id(session, (reply.dsn_message_id,))
        if rid is not None:
            return Match(rid, "dsn", True)
    if reply.dsn_subject:
        rid, _ = await by_token(session, find_tokens(reply.dsn_subject))
        if rid is not None:
            return Match(rid, "dsn")
    if ticket and reply.from_domain:
        rows = (
            await session.execute(
                text(
                    "SELECT DISTINCT report_id FROM abuse_replies WHERE from_domain = :d "
                    "AND ticket_id = :t AND report_id IS NOT NULL LIMIT 2"
                ),
                {"d": reply.from_domain, "t": ticket},
            )
        ).all()
        if len(rows) == 1:
            return Match(int(rows[0].report_id), "ticket")
    if reply.from_domain:
        sender = registrable(reply.from_domain)
        hits = [r.id for r in recent if sender in r.domains]
        if len(hits) == 1:
            return Match(hits[0], "sender_domain")
    return NO_MATCH


def from_known_recipient(reply: ParsedReply, recent: list[RecentReport]) -> bool:
    if not reply.from_domain:
        return False
    sender = registrable(reply.from_domain)
    return any(sender in r.domains for r in recent)


def is_verified(found: Match, reply: ParsedReply, report_domains_: frozenset[str]) -> bool:
    """Vouched for: matched by our own Message-ID, or authenticated mail from the recipient."""
    if found.report_id is None:
        return False
    if found.method == "message_id" or (found.method == "dsn" and found.via_message_id):
        return True
    return (
        reply.auth == "pass"
        and reply.from_domain is not None
        and registrable(reply.from_domain) in report_domains_
    )

"""Which targets are reportable, and the grouped reports queued for them (section 8.5).

Reportable:
* ``ip``: severe activity (login_success, command, download, exploit) seen by at least
  ``HUB_MIN_NODES`` nodes, or an ``attempts`` bucket of 3 or more from that many nodes;
* ``url``: fetched by at least two nodes, and its value revealed;
* ``c2_ip`` and ``c2_domain``: confirmed (a domain needs its revealed value);
* ``domain``: only with a revealed value and a fetched payload from two nodes.

Scans and connects alone never are. File hashes are not mailed on their own: they travel as
evidence of the host that served them and feed the node blocklists.
"""

from __future__ import annotations

import ipaddress
import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from suckerpot_netproto import blind
from suckerpot_netproto.enums import SEVERE_ACTIVITIES

from ..config import Settings
from ..never import Never
from . import render
from .rdap import Resolver

log = logging.getLogger("hub.reports")

GROUP_DAYS = 7
CANCEL_BLOCK_DAYS = 30
FAILED_BLOCK_DAYS = 1
MIN_FETCHED_NODES = 2
REPORT_KIND = {
    "ip": "attack_source",
    "c2_ip": "c2",
    "c2_domain": "c2",
    "url": "malware_host",
    "domain": "malware_host",
}


@dataclass
class Candidate:
    target: render.ReportTarget
    host: str  # the address or name the abuse contact is looked up for
    report_kind: str


@dataclass
class QueueResult:
    candidates: int = 0
    queued: int = 0
    updated: int = 0
    skipped: dict[str, int] = field(default_factory=dict)

    def skip(self, why: str) -> None:
        self.skipped[why] = self.skipped.get(why, 0) + 1


async def reportable_ids(session: AsyncSession, s: Settings, today: date) -> set[str]:
    """Targets whose evidence passes the severity rules, among confirmed unreported ones."""
    since = today - timedelta(days=s.window_days)
    rows = await session.execute(
        text(
            """
            SELECT t.id FROM targets t
            LEFT JOIN reports r ON r.id = t.report_id
            WHERE t.state = 'confirmed' AND t.value IS NOT NULL
              AND (t.report_id IS NULL OR r.state = 'failed'
                   OR (r.state = 'cancelled' AND r.created_day < :cancel_old))
              AND (
                (t.kind IN ('c2_ip', 'c2_domain'))
                OR (t.kind = 'ip' AND (
                      (SELECT count(DISTINCT o.node_id) FROM observations o
                        WHERE o.kind = 'ip' AND o.value = t.value AND o.day >= :since
                          AND o.activity && CAST(:severe AS text[])) >= :min_nodes
                   OR (SELECT count(DISTINCT o.node_id) FROM observations o
                        WHERE o.kind = 'ip' AND o.value = t.value AND o.day >= :since
                          AND o.attempts >= 3) >= :min_nodes))
                OR (t.kind IN ('url', 'domain') AND (
                      SELECT count(DISTINCT o.node_id) FROM observations o
                       WHERE o.kind = t.kind AND o.value = coalesce(t.value_b, t.value)
                         AND o.day >= :since AND o.fetched) >= :fetched)
              )
            """
        ),
        {
            "since": since,
            "severe": sorted(SEVERE_ACTIVITIES),
            "min_nodes": s.min_nodes,
            "fetched": MIN_FETCHED_NODES,
            "cancel_old": today - timedelta(days=CANCEL_BLOCK_DAYS),
        },
    )
    return {r.id for r in rows}


async def candidates(
    session: AsyncSession, s: Settings, today: date, never: Never
) -> list[Candidate]:
    ids = await reportable_ids(session, s, today)
    if not ids:
        return []
    rows = (
        await session.execute(
            text(
                "SELECT id, kind, value, first_day, last_day, services, activity, tags, families, "
                "node_count, country_count FROM targets WHERE id = ANY(:ids)"
            ),
            {"ids": sorted(ids)},
        )
    ).all()
    out: list[Candidate] = []
    for r in rows:
        if never.matches(r.kind, r.value):
            continue
        value, port = r.value, None
        host = r.value
        if r.kind == "c2_ip":
            value, _, p = r.value.rpartition(":")
            port, host = int(p), value
        elif r.kind == "url":
            host = blind.url_host(r.value).strip("[]")
        out.append(
            Candidate(
                render.ReportTarget(
                    id=r.id,
                    kind=r.kind,
                    value=value,
                    first_day=r.first_day or today,
                    last_day=r.last_day or today,
                    services=tuple(r.services or ()),
                    activity=tuple(r.activity or ()),
                    tags=tuple(r.tags or ()),
                    families=tuple(r.families or ()),
                    node_count=r.node_count,
                    country_count=r.country_count,
                    port=port,
                ),
                host,
                REPORT_KIND[r.kind],
            )
        )
    return out


def hold_days(s: Settings) -> int:
    return math.ceil(s.report_hold_hours / 24)


def _load_template(s: Settings) -> str:
    if not s.report_template_file:
        return ""
    try:
        with open(s.report_template_file, encoding="utf-8") as fh:
            return fh.read(20000)
    except OSError:
        log.warning("report template unreadable; sending facts only")
        return ""


async def queue_reports(
    session: AsyncSession,
    s: Settings,
    today: date,
    *,
    resolver: Resolver,
    never: Never,
) -> QueueResult:
    """Group reportable targets per (recipient, kind) and queue one report each."""
    result = QueueResult()
    if s.report_mode == "off":
        return result
    found = await candidates(session, s, today, never)
    result.candidates = len(found)
    groups: dict[tuple[str, str], list[Candidate]] = defaultdict(list)
    for c in found:
        try:
            ipaddress.ip_address(c.host)
            lookup = "ip"
        except ValueError:
            lookup = "domain"
        mailbox = await resolver(lookup, c.host)
        if mailbox is None:
            result.skip("no_contact")
            continue
        groups[(mailbox, c.report_kind)].append(c)
    template = _load_template(s)
    for (recipient, report_kind), members in groups.items():
        blocking = (
            await session.execute(
                text(
                    """
                    SELECT 1 FROM reports WHERE recipient = :r AND kind = :k AND (
                      (state IN ('approved', 'sent', 'cancelled') AND created_day >= :week)
                      OR (state = 'failed' AND created_day >= :failed)) LIMIT 1
                    """
                ),
                {
                    "r": recipient,
                    "k": report_kind,
                    "week": today - timedelta(days=GROUP_DAYS),
                    "failed": today - timedelta(days=FAILED_BLOCK_DAYS),
                },
            )
        ).first()
        if blocking is not None:
            result.skip("recently_reported")
            continue
        open_report = (
            await session.execute(
                text(
                    "SELECT id, target_ids FROM reports WHERE recipient = :r AND kind = :k "
                    "AND state = 'queued' ORDER BY id DESC LIMIT 1"
                ),
                {"r": recipient, "k": report_kind},
            )
        ).first()
        ids = {m.target.id for m in members}
        if open_report is not None:
            ids |= set(open_report.target_ids)
        targets = await _load_targets(session, sorted(ids), today)
        rendered = render.render(
            report_kind,
            targets,
            template=template,
            reply_to=s.report_reply_to,
            sent_at=today,
        )
        if open_report is None:
            row = await session.execute(
                text(
                    "INSERT INTO reports (recipient, kind, target_ids, state, body_text, xarf, "
                    "created_day) VALUES (:r, :k, :ids, 'queued', :body, :xarf, :day) RETURNING id"
                ),
                {
                    "r": recipient,
                    "k": report_kind,
                    "ids": sorted(ids),
                    "body": f"Subject: {rendered.subject}\n\n{rendered.body}",
                    "xarf": rendered.xarf,
                    "day": today,
                },
            )
            report_id = row.scalar_one()
            result.queued += 1
        else:
            report_id = open_report.id
            await session.execute(
                text(
                    "UPDATE reports SET target_ids = :ids, body_text = :body, xarf = :xarf "
                    "WHERE id = :id"
                ),
                {
                    "ids": sorted(ids),
                    "body": f"Subject: {rendered.subject}\n\n{rendered.body}",
                    "xarf": rendered.xarf,
                    "id": report_id,
                },
            )
            result.updated += 1
        await session.execute(
            text("UPDATE targets SET report_id = :rid WHERE id = ANY(:ids)"),
            {"rid": report_id, "ids": sorted(ids)},
        )
    await session.commit()
    return result


async def _load_targets(
    session: AsyncSession, ids: list[str], today: date
) -> list[render.ReportTarget]:
    rows = (
        await session.execute(
            text(
                "SELECT id, kind, value, first_day, last_day, services, activity, tags, families, "
                "node_count, country_count FROM targets WHERE id = ANY(:ids)"
            ),
            {"ids": ids},
        )
    ).all()
    out = []
    for r in rows:
        value, port = r.value, None
        if r.kind == "c2_ip":
            value, _, p = r.value.rpartition(":")
            port = int(p)
        out.append(
            render.ReportTarget(
                id=r.id,
                kind=r.kind,
                value=value,
                first_day=r.first_day or today,
                last_day=r.last_day or today,
                services=tuple(r.services or ()),
                activity=tuple(r.activity or ()),
                tags=tuple(r.tags or ()),
                families=tuple(r.families or ()),
                node_count=r.node_count,
                country_count=r.country_count,
                port=port,
            )
        )
    return out


async def auto_approve(session: AsyncSession, s: Settings, today: date) -> int:
    """In ``auto`` mode, queued reports become approved after the hold. Never in ``review``."""
    if s.report_mode != "auto":
        return 0
    result = await session.execute(
        text(
            "UPDATE reports SET state = 'approved', approved_by = 'auto' "
            "WHERE state = 'queued' AND created_day <= :cutoff"
        ),
        {"cutoff": today - timedelta(days=hold_days(s))},
    )
    await session.commit()
    return int(getattr(result, "rowcount", 0) or 0)

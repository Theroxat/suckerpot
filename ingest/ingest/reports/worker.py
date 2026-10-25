"""M18 weekly report builder.

Checked every hour. The first check on Monday after 06:00 (site time zone) that finds no report
for the week just ended builds it, stores it (escaped HTML plus the summary) and queues the
``weekly_report`` alert for the channels of that rule if the rule is on. A report is built once;
a week missed because ingest was stopped is not backfilled, only the latest finished week is.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ingest.alerts import outbox
from ingest.alerts.messages import Candidate, build_message
from ingest.features import FeatureSettings, FeatureWorker
from ingest.reports.build import alert_facts, collect, due, previous_week, zone
from ingest.reports.render import render_report

log = logging.getLogger(__name__)

MAX_HTML_BYTES = 512 * 1024 - 1024


class ReportWorker(FeatureWorker):
    name = "reports"
    interval_s = 3600.0

    def __init__(
        self,
        settings: FeatureSettings,
        factory: async_sessionmaker[AsyncSession] | None = None,
    ) -> None:
        super().__init__(settings, enabled=settings.reports_enabled)
        self.factory = factory
        self.tz = zone(settings.site_timezone)
        self.last_week: str | None = None

    async def status(self) -> dict[str, Any]:
        base = (await super().status())[self.name]
        base["last_week"] = self.last_week
        return {self.name: base}

    async def run_once(self) -> None:
        await self.build_due()

    async def build_due(self, now: datetime | None = None) -> bool:
        """Build the report if it is due. Returns True when one was written."""
        if self.factory is None:
            return False
        moment = now or datetime.now(UTC)
        if not due(moment, self.tz):
            return False
        week = previous_week(moment, self.tz)
        async with self.factory() as session:
            exists = (
                await session.execute(
                    text("SELECT 1 FROM weekly_reports WHERE week_start = :w"), {"w": week}
                )
            ).first()
        if exists:
            self.last_week = week.isoformat()
            return False
        async with self.factory() as session, session.begin():
            summary = await collect(session, week, self.settings.site_timezone)
            page = render_report(summary, moment.strftime("%Y-%m-%d %H:%M UTC"))
            if len(page.encode()) > MAX_HTML_BYTES:
                log.warning("weekly report too large, not stored")
                return False
            inserted = await session.execute(
                text(
                    """
                    INSERT INTO weekly_reports (week_start, html, summary)
                    VALUES (:w, :h, CAST(:s AS jsonb)) ON CONFLICT (week_start) DO NOTHING
                    """
                ),
                {"w": week, "h": page, "s": json.dumps(summary)},
            )
            if inserted.rowcount:  # type: ignore[attr-defined]
                await self._queue_alert(session, week.isoformat(), summary)
        self.last_week = week.isoformat()
        return True

    async def _queue_alert(self, session: AsyncSession, week: str, summary: dict[str, Any]) -> None:
        rule = (
            await session.execute(
                text("SELECT channel_ids FROM alert_rules WHERE kind = 'weekly_report' AND enabled")
            )
        ).first()
        if rule is None or not rule.channel_ids:
            return
        channels = (
            await session.execute(
                text("SELECT id, mask_ips FROM alert_channels WHERE enabled AND id = ANY(:ids)"),
                {"ids": list(rule.channel_ids)},
            )
        ).all()
        cand = Candidate(
            "weekly_report",
            f"week:{week}",
            "info",
            {"week_start": week, "headline": summary["headline"], "facts": alert_facts(summary)},
        )
        for ch in channels:
            message = build_message(cand, mask_ips=ch.mask_ips)
            await outbox.enqueue(session, cand.rule, cand.key, ch.id, message)

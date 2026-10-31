"""M18 alert worker: evaluates the rules, queues alerts and delivers them.

Everything is off until the owner enables ``ALERTS_ENABLED`` and then switches individual rules
on in the dashboard (all rules are seeded disabled). One cycle:

1. answer "send a test message" requests (every 10 s, so the button feels alive);
2. once a minute, for each enabled rule: read what is new, queue one alert per channel (masked
   per the channel's choice), and move the rule's cursor, all in one transaction;
3. deliver what is pending, within the rate limits (see ``ingest.alerts.outbox``).

Channel targets are decrypted only in memory, right before a send. A failure is recorded as a
constant error code; nothing secret is logged.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from suckerpot_db.alert_targets import decrypt_target
from suckerpot_db.secretbox import SecretBox, SecretError

from ingest.alerts import outbox
from ingest.alerts.config import AlertSettings
from ingest.alerts.messages import (
    SEVERITY_RANK,
    build_digest,
    build_message,
    sample_message,
)
from ingest.alerts.outbox import Pending, Plan, Usage
from ingest.alerts.rules import COLLECTORS
from ingest.alerts.send import Sender, SendError
from ingest.features import FeatureSettings, FeatureWorker

log = logging.getLogger(__name__)

EVALUATE_EVERY_S = 60.0
TEST_BATCH = 5


@dataclass(frozen=True, slots=True)
class Channel:
    id: int
    kind: str
    enabled: bool
    ciphertext: bytes
    mask_ips: bool


def _saved_before(cursor: dict[str, Any], moment: datetime) -> bool:
    raw = cursor.get("_at")
    if not isinstance(raw, str):
        return True  # no timestamp: cannot be trusted after a re-enable
    try:
        return datetime.fromisoformat(raw) < moment
    except ValueError:
        return True


class AlertWorker(FeatureWorker):
    name = "alerts"
    interval_s = 10.0

    def __init__(
        self,
        settings: FeatureSettings,
        factory: async_sessionmaker[AsyncSession] | None = None,
        box: SecretBox | None = None,
        alert_settings: AlertSettings | None = None,
        smtp_password: str = "",
        sender: Sender | None = None,
    ) -> None:
        super().__init__(settings, enabled=settings.alerts_enabled)
        self.factory = factory
        self.box = box
        self.alert_settings = alert_settings or AlertSettings()
        self.sender = sender or Sender(self.alert_settings, smtp_password=smtp_password)
        self._last_eval = 0.0
        self.sent_cycle = 0

    @property
    def sf(self) -> async_sessionmaker[AsyncSession]:
        if self.factory is None:
            raise RuntimeError("no database")
        return self.factory

    def apply_settings(self, settings: Any, changed: set[str]) -> None:
        if "smtp" in changed:
            self.sender.smtp_password = str(getattr(settings, "smtp_password", ""))

    async def status(self) -> dict[str, Any]:
        base = (await super().status())[self.name]
        base["smtp_configured"] = self.alert_settings.smtp_configured
        base["can_decrypt"] = self.box is not None
        return {self.name: base}

    async def aclose(self) -> None:
        await self.sender.aclose()

    # ---- the cycle ----------------------------------------------------------------------------
    async def run_once(self) -> None:
        if self.factory is None:
            return
        await self._answer_tests()
        now = time.monotonic()
        if now - self._last_eval < EVALUATE_EVERY_S:
            return
        self._last_eval = now
        await self._evaluate()
        await self._deliver()

    async def _channels(self) -> dict[int, Channel]:
        async with self.sf() as session:
            rows = (
                await session.execute(
                    text(
                        "SELECT id, kind, enabled, target_ciphertext, mask_ips FROM alert_channels"
                    )
                )
            ).all()
        return {r.id: Channel(r.id, r.kind, r.enabled, bytes(r.target_ciphertext), r.mask_ips)
                for r in rows}  # fmt: skip

    def _target(self, channel: Channel) -> str:
        if self.box is None:
            raise SendError("no_encryption_key")
        try:
            return decrypt_target(self.box, channel.id, channel.ciphertext)
        except SecretError:
            raise SendError("cannot_decrypt") from None

    # ---- rules -> outbox ----------------------------------------------------------------------
    async def _evaluate(self) -> None:
        channels = await self._channels()
        async with self.sf() as session:
            rules = (
                await session.execute(
                    text(
                        "SELECT kind, channel_ids, min_severity, enabled_at FROM alert_rules "
                        "WHERE enabled AND kind <> 'weekly_report' ORDER BY kind"
                    )
                )
            ).all()
        for rule in rules:
            collector = COLLECTORS.get(rule.kind)
            if collector is None:
                continue
            targets = [
                channels[i] for i in rule.channel_ids if i in channels and channels[i].enabled
            ]
            try:
                await self._run_rule(
                    rule.kind, collector, rule.min_severity, targets, rule.enabled_at
                )
            except Exception as exc:  # one broken rule must not stop the others
                log.warning("alert rule %s failed (%s)", rule.kind, type(exc).__name__)

    async def _run_rule(
        self,
        kind: str,
        collector: Any,
        min_severity: str,
        targets: list[Channel],
        enabled_at: datetime | None = None,
    ) -> None:
        threshold = SEVERITY_RANK.get(min_severity, 2)
        async with self.sf() as session, session.begin():
            await session.execute(text("SET LOCAL statement_timeout = '30s'"))
            raw = (
                await session.execute(
                    text("SELECT cursor FROM alert_cursors WHERE rule_kind = :k FOR UPDATE"),
                    {"k": kind},
                )
            ).scalar_one_or_none()
            # A cursor saved before the rule was last switched on is stale: start again at "now"
            # instead of replaying everything that happened while the rule was off.
            if raw is not None and enabled_at is not None and _saved_before(raw, enabled_at):
                raw = None
            candidates, cursor = await collector(session, raw)
            cursor = {**cursor, "_at": datetime.now(UTC).isoformat()}
            for cand in candidates:
                if SEVERITY_RANK.get(cand.severity, 0) < threshold:
                    continue
                for channel in targets:
                    message = build_message(cand, mask_ips=channel.mask_ips)
                    await outbox.enqueue(session, kind, cand.key, channel.id, message)
            await session.execute(
                text(
                    """
                    INSERT INTO alert_cursors (rule_kind, cursor) VALUES (:k, CAST(:c AS jsonb))
                    ON CONFLICT (rule_kind) DO UPDATE SET cursor = EXCLUDED.cursor
                    """
                ),
                {"k": kind, "c": json.dumps(cursor)},
            )

    async def _send(self, channel: Channel, message: dict[str, Any]) -> None:
        """One send. Whatever goes wrong becomes a ``SendError`` with a constant code."""
        try:
            await self.sender.send(channel.kind, self._target(channel), message)
        except SendError:
            raise
        except Exception as exc:  # the text may hold a target: log the type only
            log.warning("alert send failed unexpectedly (%s)", type(exc).__name__)
            raise SendError("internal") from None

    # ---- outbox -> channels -------------------------------------------------------------------
    async def _deliver(self) -> None:
        channels = await self._channels()
        usage, _ = await outbox.read_usage(self.sf)
        total_day = sum(u.day for u in usage.values())
        left = outbox.CYCLE_LIMIT
        for channel_id in await outbox.pending_channels(self.sf):
            channel = channels.get(channel_id)
            if channel is None or not channel.enabled:
                await outbox.mark_channel_pending(
                    self.sf, channel_id, "suppressed", "channel_disabled"
                )
                continue
            use = usage.setdefault(channel_id, Usage())
            use.global_day = total_day
            if left <= 0:
                break
            items, _ = await outbox.read_pending(self.sf, channel_id)
            plan = outbox.plan_channel(len(items), use, left)
            if plan is Plan.DROP:
                await outbox.mark_channel_pending(self.sf, channel_id, "suppressed", "daily_limit")
            elif plan is Plan.EACH:
                for item in items:
                    sent = await self._send_items(channel, [item], item.payload)
                    left -= sent
                    use.minute += sent
                    use.day += sent
                    total_day += sent
            elif plan is Plan.DIGEST:
                payloads = [i.payload for i in items]
                digest = build_digest(payloads, "were waiting")
                sent = await self._send_items(
                    channel, items, digest, digest_of=len(items), final_state="suppressed"
                )
                left -= sent
                use.minute += sent
                use.day += sent
                total_day += sent
        self.sent_cycle = outbox.CYCLE_LIMIT - left

    async def _send_items(
        self,
        channel: Channel,
        items: list[Pending],
        message: dict[str, Any],
        *,
        digest_of: int = 0,
        final_state: str = "sent",
    ) -> int:
        """Send one message for ``items``. Returns 1 when it left, else 0."""
        ids = [i.id for i in items]
        try:
            await self._send(channel, message)
        except SendError as exc:
            log.info("alert delivery failed (%s)", exc.code)
            if exc.code == "egress_closed":  # not now: stays pending and costs no attempt
                await outbox.mark(self.sf, ids, "pending", error=exc.code, attempt=False)
                return 0
            await outbox.record_retry(self.sf, items, exc.code, exc.retryable)
            return 0
        if digest_of:
            key = f"digest:{int(time.time())}:{items[0].id}"
            await outbox.record_digest(self.sf, channel.id, items[0].rule_kind, key, message)
            await outbox.mark(self.sf, ids, final_state, error="digested", attempt=True)
        else:
            await outbox.mark(self.sf, ids, "sent", attempt=True)
        return 1

    # ---- "send a test message" ----------------------------------------------------------------
    async def _answer_tests(self) -> None:
        async with self.sf() as session:
            rows = (
                await session.execute(
                    text(
                        "SELECT id, channel_id FROM alert_test_requests "
                        "WHERE state = 'queued' ORDER BY id LIMIT :n"
                    ),
                    {"n": TEST_BATCH},
                )
            ).all()
        if not rows:
            return
        channels = await self._channels()
        for row in rows:
            channel = channels.get(row.channel_id)
            if channel is None:
                state, detail = "failed", "channel_missing"
            else:
                try:
                    await self._send(channel, sample_message())
                    state, detail = "done", "sent"
                except SendError as exc:
                    refused = exc.code in ("blocked_target", "private_address", "no_encryption_key",
                                           "cannot_decrypt", "smtp_not_configured")  # fmt: skip
                    state, detail = ("refused" if refused else "failed"), exc.code
            async with self.sf() as session, session.begin():
                await session.execute(
                    text("UPDATE alert_test_requests SET state = :s, detail = :d WHERE id = :i"),
                    {"s": state, "d": detail, "i": row.id},
                )

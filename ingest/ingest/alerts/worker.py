"""No-op worker for the M18 feature: alert rules, the outbox and delivery to the channels.

The real job arrives in a later phase; this stub only holds the settings and publishes a status.
"""

from __future__ import annotations

from ingest.features import FeatureSettings, FeatureWorker


class AlertWorker(FeatureWorker):
    name = "alerts"
    interval_s = 60.0

    def __init__(self, settings: FeatureSettings) -> None:
        super().__init__(settings, enabled=settings.alerts_enabled)

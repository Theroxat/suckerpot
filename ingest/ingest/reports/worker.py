"""No-op worker for the M18 feature: weekly report builder.

The real job arrives in a later phase; this stub only holds the settings and publishes a status.
"""

from __future__ import annotations

from ingest.features import FeatureSettings, FeatureWorker


class ReportWorker(FeatureWorker):
    name = "reports"
    interval_s = 3600.0

    def __init__(self, settings: FeatureSettings) -> None:
        super().__init__(settings, enabled=settings.reports_enabled)

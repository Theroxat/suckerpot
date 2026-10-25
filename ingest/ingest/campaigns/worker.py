"""No-op worker for the M15 feature: campaign clustering of finished sessions.

The real job arrives in a later phase; this stub only holds the settings and publishes a status.
"""

from __future__ import annotations

from ingest.features import FeatureSettings, FeatureWorker


class CampaignWorker(FeatureWorker):
    name = "campaigns"
    interval_s = 300.0

    def __init__(self, settings: FeatureSettings) -> None:
        super().__init__(settings, enabled=settings.campaigns_enabled)

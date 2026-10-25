"""No-op worker for the M16 feature: scoring of indicators into blocklist_entries.

The real job arrives in a later phase; this stub only holds the settings and publishes a status.
"""

from __future__ import annotations

from ingest.features import FeatureSettings, FeatureWorker


class BlocklistWorker(FeatureWorker):
    name = "blocklist"
    interval_s = 900.0

    def __init__(self, settings: FeatureSettings) -> None:
        super().__init__(settings, enabled=settings.blocklist_enabled)

"""No-op worker for the M17 feature: script library: fingerprints and built-in annotations.

The real job arrives in a later phase; this stub only holds the settings and publishes a status.
"""

from __future__ import annotations

from ingest.features import FeatureSettings, FeatureWorker


class ScriptWorker(FeatureWorker):
    name = "scripts"
    interval_s = 300.0

    def __init__(self, settings: FeatureSettings) -> None:
        super().__init__(settings, enabled=settings.scripts_enabled)

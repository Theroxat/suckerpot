"""No-op worker for the M15 feature: ATT&CK catalogue sync (techniques.yaml into attack_techniques).

The real job arrives in a later phase; this stub only holds the settings and publishes a status.
"""

from __future__ import annotations

from ingest.features import FeatureSettings, FeatureWorker


class AttackCatalogWorker(FeatureWorker):
    name = "attack"
    interval_s = 3600.0

    def __init__(self, settings: FeatureSettings) -> None:
        super().__init__(settings, enabled=settings.attack_enabled)

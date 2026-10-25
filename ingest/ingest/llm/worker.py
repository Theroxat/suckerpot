"""No-op worker for the M17 feature: optional LLM explanation of scripts (needs the anthropic key).

The real job arrives in a later phase; this stub only holds the settings and publishes a status.
"""

from __future__ import annotations

from ingest.features import FeatureSettings, FeatureWorker


class ExplainerWorker(FeatureWorker):
    name = "llm"
    interval_s = 60.0

    def __init__(self, settings: FeatureSettings) -> None:
        super().__init__(settings, enabled=settings.llm_enabled)

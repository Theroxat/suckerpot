"""M15: campaign clustering of finished sessions.

Phase 0 ships a no-op worker, disabled by default.
"""

from ingest.campaigns.worker import CampaignWorker

__all__ = ["CampaignWorker"]

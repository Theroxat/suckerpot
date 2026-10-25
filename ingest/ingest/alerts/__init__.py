"""M18: alert rules, the outbox and delivery to the channels.

Phase 0 ships a no-op worker, disabled by default.
"""

from ingest.alerts.worker import AlertWorker

__all__ = ["AlertWorker"]

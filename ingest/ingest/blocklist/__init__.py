"""M16: scoring of indicators into blocklist_entries.

Phase 0 ships a no-op worker, disabled by default.
"""

from ingest.blocklist.worker import BlocklistWorker

__all__ = ["BlocklistWorker"]

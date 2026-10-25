"""M17: script library: fingerprints and built-in annotations.

Phase 0 ships a no-op worker, disabled by default.
"""

from ingest.scripts.worker import ScriptWorker

__all__ = ["ScriptWorker"]

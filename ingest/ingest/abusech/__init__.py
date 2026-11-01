"""Optional submission of captured malware URLs to URLhaus and C2 addresses to ThreatFox (M27)."""

from ingest.abusech.worker import AbusechSubmitWorker

__all__ = ["AbusechSubmitWorker"]

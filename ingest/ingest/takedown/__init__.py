"""Takedown tracking, ingest side (design M27): targets, listing checks, states and roll-up."""

from ingest.takedown.config import TakedownSettings
from ingest.takedown.worker import TakedownWorker

__all__ = ["TakedownSettings", "TakedownWorker"]

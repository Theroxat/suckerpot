"""The synchronous, hot-path part of enrichment: local geo lookups plus tagging rules."""

from __future__ import annotations

from dataclasses import dataclass, field

from ingest.bruteforce import BruteForceTracker
from ingest.enrichment.geo import GeoResolver
from ingest.indicators import IndicatorExtractor
from ingest.tagging import RuleSet


@dataclass(slots=True)
class Enricher:
    geo: GeoResolver
    rules: RuleSet
    brute: BruteForceTracker = field(default_factory=BruteForceTracker)
    indicators: IndicatorExtractor | None = None
    link_cap: int = 500

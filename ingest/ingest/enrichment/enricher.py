"""The synchronous, hot-path part of enrichment: local geo lookups plus tagging rules."""

from __future__ import annotations

from dataclasses import dataclass

from ingest.enrichment.geo import GeoResolver
from ingest.tagging import RuleSet


@dataclass(slots=True)
class Enricher:
    geo: GeoResolver
    rules: RuleSet

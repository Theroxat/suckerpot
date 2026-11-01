"""Settings of the takedown worker (``TAKEDOWN_*``). Off until ``TAKEDOWN_ENABLED=true``."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

from ingest.features import TRUE_VALUES, _int


@dataclass(frozen=True, slots=True)
class TakedownSettings:
    track_days: int = 30
    intel_daily_quota: int = 100
    abuseipdb_daily_quota: int = 50
    quiet_days: int = 7
    include_demo: bool = False  # ABUSE_REPORTS_INCLUDE_DEMO: CI and screenshots only
    interval_s: int = 600

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> TakedownSettings:
        e = os.environ if env is None else env
        return cls(
            track_days=_int(e, "TAKEDOWN_TRACK_DAYS", 30, 7, 90),
            intel_daily_quota=_int(e, "TAKEDOWN_INTEL_DAILY_QUOTA", 100, 0, 100_000),
            abuseipdb_daily_quota=_int(e, "TAKEDOWN_ABUSEIPDB_DAILY_QUOTA", 50, 0, 100_000),
            quiet_days=_int(e, "TAKEDOWN_QUIET_DAYS", 7, 1, 90),
            include_demo=e.get("ABUSE_REPORTS_INCLUDE_DEMO", "false").strip().lower()
            in TRUE_VALUES,
            interval_s=_int(e, "TAKEDOWN_INTERVAL_S", 600, 30, 86_400),
        )

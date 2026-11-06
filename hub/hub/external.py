"""Optional external corroboration for single-signal addresses (design M29 section 8.2, rule 5).

An address seen by few nodes counts only when the hub's own AbuseIPDB or GreyNoise key says the
address is known as hostile. Results are cached for 24 hours and each source has a hard daily
quota; with no key configured the answer is always "not corroborated" (so such addresses need
twice the nodes). This is hub traffic about public attacker addresses: no node data is sent.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime

import httpx

from .config import Settings

log = logging.getLogger("hub.external")

CACHE_TTL_S = 24 * 3600
ABUSEIPDB_DAILY = 900  # under the free tier of 1,000 checks a day
GREYNOISE_DAILY = 40  # under the community tier
ABUSE_CONFIDENCE_MIN = 25
TIMEOUT = httpx.Timeout(10.0, connect=5.0)


class Corroborator:
    def __init__(
        self,
        s: Settings,
        *,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._abuseipdb = s.abuseipdb_key
        self._greynoise = s.greynoise_key
        self._clock = clock
        self._client = client or httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False)
        self._cache: dict[str, tuple[float, bool]] = {}
        self._quota: dict[str, tuple[str, int]] = {}

    @property
    def enabled(self) -> bool:
        return bool(self._abuseipdb or self._greynoise)

    async def aclose(self) -> None:
        await self._client.aclose()

    def _take(self, source: str, limit: int) -> bool:
        today = self._clock().date().isoformat()
        day, used = self._quota.get(source, (today, 0))
        if day != today:
            day, used = today, 0
        if used >= limit:
            return False
        self._quota[source] = (day, used + 1)
        return True

    async def __call__(self, ip: str) -> bool:
        if not self.enabled:
            return False
        hit = self._cache.get(ip)
        if hit is not None and time.monotonic() - hit[0] < CACHE_TTL_S:
            return hit[1]
        known = False
        if self._abuseipdb and self._take("abuseipdb", ABUSEIPDB_DAILY):
            known = await self._ask_abuseipdb(ip)
        if not known and self._greynoise and self._take("greynoise", GREYNOISE_DAILY):
            known = await self._ask_greynoise(ip)
        self._cache[ip] = (time.monotonic(), known)
        return known

    async def _ask_abuseipdb(self, ip: str) -> bool:
        try:
            resp = await self._client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": "30"},
                headers={"Key": self._abuseipdb, "Accept": "application/json"},
            )
            if resp.status_code != 200:
                return False
            data = resp.json().get("data", {})
            return int(data.get("abuseConfidenceScore", 0)) >= ABUSE_CONFIDENCE_MIN
        except httpx.HTTPError, ValueError, TypeError:
            log.warning("abuseipdb lookup failed")
            return False

    async def _ask_greynoise(self, ip: str) -> bool:
        try:
            resp = await self._client.get(
                f"https://api.greynoise.io/v3/community/{ip}",
                headers={"key": self._greynoise, "Accept": "application/json"},
            )
            if resp.status_code != 200:
                return False
            return str(resp.json().get("classification", "")).lower() == "malicious"
        except httpx.HTTPError, ValueError, TypeError:
            log.warning("greynoise lookup failed")
            return False

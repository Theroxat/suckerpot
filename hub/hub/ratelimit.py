"""In-memory rate limits.

This is the ONLY module that reads the client address of a request (``request.client`` or the
proxy header). The address is never stored or logged: it is hashed with a random key (HMAC)
that is replaced every day, and the table lives in memory only.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from collections.abc import Callable
from datetime import date, datetime

from starlette.requests import Request

MAX_ENTRIES = 200_000


def client_address(request: Request, trust_proxy: bool) -> str:
    """The peer address, or the last entry of the proxy header when a trusted proxy is in front."""
    if trust_proxy:
        header = request.headers.get("x-forwarded-for", "")
        last = header.split(",")[-1].strip()
        if last:
            return last
    client = request.client
    return client.host if client else ""


class _Window:
    __slots__ = ("count", "start")

    def __init__(self, start: int) -> None:
        self.start = start
        self.count = 0


class Counter:
    """Fixed-window counters per key, memory only, bounded."""

    def __init__(self, window_s: int, limit: int, clock: Callable[[], datetime]) -> None:
        self.window_s = window_s
        self.limit = limit
        self._clock = clock
        self._data: dict[str, _Window] = {}

    def _now(self) -> int:
        return int(self._clock().timestamp())

    def hit(self, key: str, cost: int = 1) -> int:
        """Count a hit. Returns 0 when allowed, else the seconds to wait."""
        now = self._now()
        slot = self._data.get(key)
        if slot is None or now - slot.start >= self.window_s:
            if len(self._data) >= MAX_ENTRIES:
                self._purge(now)
            slot = _Window(now)
            self._data[key] = slot
        if slot.count + cost > self.limit:
            return max(1, self.window_s - (now - slot.start))
        slot.count += cost
        return 0

    def peek(self, key: str) -> int:
        """Seconds to wait if the key is over its limit, without counting."""
        now = self._now()
        slot = self._data.get(key)
        if slot is None or now - slot.start >= self.window_s or slot.count < self.limit:
            return 0
        return max(1, self.window_s - (now - slot.start))

    def forget(self, key: str) -> None:
        self._data.pop(key, None)

    def _purge(self, now: int) -> None:
        for k in [k for k, w in self._data.items() if now - w.start >= self.window_s]:
            del self._data[k]
        if len(self._data) >= MAX_ENTRIES:  # still full: start over rather than grow
            self._data.clear()


class AddressLimiter:
    """Per-address limits on unsigned endpoints and on failed authentication."""

    def __init__(
        self,
        *,
        per_min: int,
        per_day: int,
        failures_per_min: int,
        trust_proxy: bool,
        clock: Callable[[], datetime],
    ) -> None:
        self._trust_proxy = trust_proxy
        self._clock = clock
        self._minute = Counter(60, per_min, clock)
        self._day = Counter(86400, per_day, clock)
        self._fail = Counter(60, failures_per_min, clock)
        self._key = os.urandom(32)
        self._key_day: date = clock().date()

    def _rotate(self) -> None:
        today = self._clock().date()
        if today != self._key_day:
            self._key = os.urandom(32)
            self._key_day = today
            for c in (self._minute, self._day, self._fail):
                c._data.clear()

    def _id(self, request: Request) -> str:
        self._rotate()
        addr = client_address(request, self._trust_proxy)
        return hmac.new(self._key, addr.encode(), hashlib.sha256).hexdigest()[:24]

    def check_unsigned(self, request: Request) -> int:
        who = self._id(request)
        return self._minute.hit(who) or self._day.hit(who)

    def blocked(self, request: Request) -> int:
        """Seconds to wait when this address failed authentication too often."""
        return self._fail.peek(self._id(request))

    def record_failure(self, request: Request) -> None:
        self._fail.hit(self._id(request))

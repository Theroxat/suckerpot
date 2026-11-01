"""In-memory rate limits.

This is the ONLY module that reads the client address of a request (``request.client`` or the
proxy header). The address is never stored or logged: it is hashed with a random key (HMAC)
that is replaced every day, and the table lives in memory only.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
from collections import OrderedDict
from collections.abc import Callable
from datetime import date, datetime

from starlette.requests import Request

MAX_ENTRIES = 200_000


def client_address(request: Request, trust_proxy: bool) -> str:
    """The peer address, or the last entry of the proxy header when a trusted proxy is in front.

    An IPv6 address is reduced to its /64 prefix: one subscriber owns a whole /64, so limits keyed
    by the full address would be free to dodge.
    """
    raw = ""
    if trust_proxy:
        raw = request.headers.get("x-forwarded-for", "").split(",")[-1].strip()
    if not raw:
        client = request.client
        raw = client.host if client else ""
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return raw
    if isinstance(addr, ipaddress.IPv6Address):
        return str(ipaddress.ip_network((addr, 64), strict=False).network_address) + "/64"
    return raw


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
        self._data: OrderedDict[str, _Window] = OrderedDict()

    def _now(self) -> int:
        return int(self._clock().timestamp())

    def hit(self, key: str, cost: int = 1) -> int:
        """Count a hit. Returns 0 when allowed, else the seconds to wait."""
        now = self._now()
        slot = self._data.get(key)
        if slot is None or now - slot.start >= self.window_s:
            slot = _Window(now)
            self._data[key] = slot
            self._data.move_to_end(key)
            while len(self._data) > MAX_ENTRIES:  # evict the least recently started window
                self._data.popitem(last=False)
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

    def count(self, key: str) -> int:
        """Hits counted in the key's current window."""
        slot = self._data.get(key)
        if slot is None or self._now() - slot.start >= self.window_s:
            return 0
        return slot.count

    def forget(self, key: str) -> None:
        self._data.pop(key, None)


class AddressLimiter:
    """Per-address limits on unsigned endpoints and on failed authentication."""

    def __init__(
        self,
        *,
        per_min: int,
        per_day: int,
        failures_per_min: int,
        challenges_per_prefix: int = 20,
        trust_proxy: bool,
        clock: Callable[[], datetime],
    ) -> None:
        self._trust_proxy = trust_proxy
        self._clock = clock
        self._minute = Counter(60, per_min, clock)
        self._day = Counter(86400, per_day, clock)
        self._fail = Counter(60, failures_per_min, clock)
        self._challenges = Counter(600, challenges_per_prefix, clock)
        self._key = os.urandom(32)
        self._key_day: date = clock().date()

    def _rotate(self) -> None:
        today = self._clock().date()
        if today != self._key_day:
            self._key = os.urandom(32)
            self._key_day = today
            for c in (self._minute, self._day, self._fail, self._challenges):
                c._data.clear()

    def _id(self, request: Request) -> str:
        self._rotate()
        addr = client_address(request, self._trust_proxy)
        return hmac.new(self._key, addr.encode(), hashlib.sha256).hexdigest()[:24]

    def check_unsigned(self, request: Request) -> int:
        who = self._id(request)
        return self._minute.hit(who) or self._day.hit(who)

    def check_challenge(self, request: Request) -> int:
        """At most a few pending enrolment challenges per address prefix (memory only)."""
        return self._challenges.hit(self._id(request))

    def challenge_pressure(self, request: Request) -> int:
        """Challenges this address prefix drew in the current window (memory only)."""
        return self._challenges.count(self._id(request))

    def blocked(self, request: Request) -> int:
        """Seconds to wait when this address failed authentication too often."""
        return self._fail.peek(self._id(request))

    def record_failure(self, request: Request) -> None:
        self._fail.hit(self._id(request))

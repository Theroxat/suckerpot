"""Per-source brute-force detector: login attempts per (source IP, sensor) over a sliding window.

Protocols such as MySQL, MSSQL and Redis carry one login per connection, so a session-scope
counter never reaches a useful threshold. This keeps a bounded in-memory view instead: at most
``max_keys`` keys (least recently used are evicted) and at most ``threshold`` timestamps per key.
State is lost on restart, which only delays a tag; it never blocks ingestion.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from datetime import datetime, timedelta

TAG = "credential-stuffing"


class BruteForceTracker:
    def __init__(
        self,
        threshold: int = 20,
        window: timedelta = timedelta(minutes=10),
        max_keys: int = 50_000,
    ) -> None:
        if threshold < 1 or max_keys < 1 or window <= timedelta(0):
            raise ValueError("threshold, window and max_keys must be positive")
        self.threshold = threshold
        self.window = window
        self.max_keys = max_keys
        self._seen: OrderedDict[tuple[str, str], deque[datetime]] = OrderedDict()

    def __len__(self) -> int:
        return len(self._seen)

    def record(self, ip: str, sensor: str, ts: datetime) -> bool:
        """Count one login attempt; True when the source has reached the threshold in the window."""
        key = (ip, sensor)
        times = self._seen.get(key)
        if times is None:
            times = deque(maxlen=self.threshold)
            self._seen[key] = times
            if len(self._seen) > self.max_keys:
                self._seen.popitem(last=False)
        else:
            self._seen.move_to_end(key)
        times.append(ts)
        horizon = ts - self.window
        while times and times[0] < horizon:
            times.popleft()
        return len(times) >= self.threshold

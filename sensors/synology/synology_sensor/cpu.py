"""CPU fairness: per-connection, per-IP and sensor-wide budgets charged with thread CPU time.

Work is measured with ``time.thread_time()`` deltas over *synchronous* stretches only (never
across an ``await``: other connections run there). Buckets are floored at minus their burst, so
one huge request cannot create an unbounded debt. Requests are never refused when a bucket is
empty: the connection waits (cooperatively), so a flood of expensive requests from a few IPs
slows those IPs down and cannot block the loop for the others.
"""

from __future__ import annotations

import asyncio
import time

from synology_sensor.config import Config

SLICE = 0.006  # wall-clock seconds of work before a connection yields the loop
MAX_WAIT = 2.0
_MAX_KEYS = 20_000


class CpuBudget:
    def __init__(self, cfg: Config) -> None:
        self._cfg = {
            "g": (cfg.cpu_global_rate, cfg.cpu_global_burst),
            "i": (cfg.cpu_ip_rate, cfg.cpu_ip_burst),
            "c": (cfg.cpu_conn_rate, cfg.cpu_conn_burst),
        }
        self._items: dict[str, tuple[float, float]] = {}
        self.waits = 0  # times a connection had to wait for its buckets

    def _tokens(self, kind: str, key: str, now: float) -> float:
        rate, burst = self._cfg[kind]
        tokens, last = self._items.get(kind + key, (burst, now))
        return min(burst, tokens + (now - last) * rate)

    def delay(self, ip: str, sid: str) -> float:
        """Seconds this connection must wait before doing more work.

        The sensor-wide bucket only delays IPs that are themselves heavy users (less than half
        of their own burst left), so a light client never waits for someone else's flood.
        """
        now = time.monotonic()
        ip_tokens = self._tokens("i", ip, now)
        kinds = [("i", ip_tokens), ("c", self._tokens("c", sid, now))]
        if ip_tokens < self._cfg["i"][1] / 2:
            kinds.append(("g", self._tokens("g", "", now)))
        wait = 0.0
        for kind, tokens in kinds:
            if tokens < 0:
                wait = max(wait, -tokens / self._cfg[kind][0])
        return min(wait, MAX_WAIT)

    def charge(self, ip: str, sid: str, seconds: float) -> None:
        now = time.monotonic()
        for kind, key in (("g", ""), ("i", ip), ("c", sid)):
            floor = -self._cfg[kind][1]
            self._items[kind + key] = (max(floor, self._tokens(kind, key, now) - seconds), now)
        if len(self._items) > _MAX_KEYS:
            for old in list(self._items)[: _MAX_KEYS // 4]:
                if old != "g":
                    self._items.pop(old, None)

    def drop(self, sid: str) -> None:
        self._items.pop("c" + sid, None)


class Meter:
    """Measures one connection's synchronous work and enforces the wall-clock slice."""

    def __init__(self, budget: CpuBudget, ip: str, sid: str) -> None:
        self._budget = budget
        self._ip = ip
        self._sid = sid
        self._t = time.thread_time()
        self._w = time.perf_counter()

    def mark(self) -> None:
        """Start of a synchronous stretch (call right after every ``await``)."""
        self._t = time.thread_time()
        self._w = time.perf_counter()

    def flush(self) -> None:
        """Charge the stretch so far (call right before every ``await``)."""
        spent = time.thread_time() - self._t
        if spent > 0:
            self._budget.charge(self._ip, self._sid, spent)
        self.mark()

    async def pause(self) -> None:
        """Charge, then wait as long as the buckets demand (at least one loop turn)."""
        self.flush()
        wait = self._budget.delay(self._ip, self._sid)
        if wait > 0:
            self._budget.waits += 1
        await asyncio.sleep(wait)
        self.mark()

    async def tick(self) -> None:
        """Yield when the current stretch has used up its wall-clock slice."""
        if time.perf_counter() - self._w >= SLICE:
            await self.pause()

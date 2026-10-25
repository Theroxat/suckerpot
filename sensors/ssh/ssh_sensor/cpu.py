"""Budgets shared by all sessions and fair across source IPs: shell CPU, inbound bytes.

The fake shell runs synchronously on the event loop. Each command line is capped by the
per-line time budget, but many channels running heavy lines back to back would still keep the
loop busy: one loop iteration runs every ready task, so 80 channels x 0.15 s is a 12 s stall.

``FairBudget`` is a token bucket (here: shell CPU-seconds, or inbound bytes for the socket
reader) that refills at ``share`` seconds per wall
second (at most ``burst`` ahead). The cost of a command is only known once it ran, so it is
charged afterwards and the bucket can go negative; the debt is waited out on a timer.

Fairness: while nobody waits and the bucket is not in debt, a command runs at once. Otherwise
it queues, and a dispatcher lets ONE command run at a time whenever the bucket allows,
choosing the source IP that used the least CPU recently (an exponentially decayed sum), FIFO
within an IP. One IP with many busy channels therefore cannot starve another IP, and the loop
never runs more than one queued command per refill step.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections import OrderedDict, deque
from collections.abc import Callable

_HALF_LIFE = 5.0  # seconds: how long past CPU use counts against an IP
_MAX_IPS = 10_000
_TURN_TIMEOUT = 0.5  # a released waiter that never reports its cost loses its turn


class FairBudget:
    def __init__(
        self,
        share: float,
        burst: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_ips: int = _MAX_IPS,
        name: str = "cpu",
        scale: float = 1000.0,
    ) -> None:
        self._name = name
        self._scale = scale  # stats unit: ms for CPU-seconds
        self.share = max(1e-6, share)
        self.burst = max(1e-6, burst)
        self._clock = clock
        self._max_ips = max_ips
        self._tokens = self.burst
        self._at = clock()
        # ip -> (decayed CPU seconds, when); least recently updated first
        self._usage: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._waiters: dict[str, deque[asyncio.Future[None]]] = {}
        self._dispatcher: asyncio.Task[None] | None = None
        self._turn_done = asyncio.Event()
        self.spent = 0.0
        self.refused = 0
        self.queued = 0

    # ---- accounting ----------------------------------------------------------------------
    def _refill(self) -> float:
        now = self._clock()
        self._tokens = min(self.burst, self._tokens + (now - self._at) * self.share)
        self._at = now
        return self._tokens

    def usage(self, ip: str) -> float:
        value, when = self._usage.get(ip, (0.0, 0.0))
        return value * 0.5 ** ((self._clock() - when) / _HALF_LIFE) if value else 0.0

    def spend(self, ip: str, seconds: float) -> None:
        """Charge the CPU a command used (also ends its turn if it was released by the queue)."""
        seconds = max(0.0, seconds)
        self._refill()
        self.spent += seconds
        # bounded debt: one slow line cannot block everyone for minutes
        self._tokens = max(-4 * self.burst - 1.0, self._tokens - seconds)
        self._usage[ip] = (self.usage(ip) + seconds, self._clock())
        self._usage.move_to_end(ip)
        while len(self._usage) > self._max_ips:
            self._usage.popitem(last=False)
        self._turn_done.set()

    def wait_time(self) -> float:
        """Seconds until the bucket is out of debt (0 if a command may run now)."""
        tokens = self._refill()
        return 0.0 if tokens >= 0 else -tokens / self.share

    # ---- admission -----------------------------------------------------------------------
    async def acquire(self, ip: str, max_wait: float) -> bool:
        """Wait for this IP's turn to run a command. False if it did not come within
        ``max_wait`` seconds (the caller then refuses the command)."""
        if not self._waiters and self.wait_time() == 0.0:
            return True
        fut: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._waiters.setdefault(ip, deque()).append(fut)
        self.queued += 1
        if self._dispatcher is None or self._dispatcher.done():
            self._dispatcher = asyncio.create_task(self._dispatch())
        try:
            await asyncio.wait_for(asyncio.shield(fut), max_wait)
            return True
        except TimeoutError:
            if fut.done() and not fut.cancelled():
                return True  # released at the very last moment
            fut.cancel()
            self.refused += 1
            return False
        except asyncio.CancelledError:
            if fut.done() and not fut.cancelled():
                self._turn_done.set()  # our turn came but we will not run: pass it on
            fut.cancel()
            raise
        finally:
            self._forget(ip, fut)

    def _forget(self, ip: str, fut: asyncio.Future[None]) -> None:
        queue = self._waiters.get(ip)
        if queue is None:
            return
        with contextlib.suppress(ValueError):
            queue.remove(fut)
        if not queue:
            del self._waiters[ip]

    def _next(self) -> asyncio.Future[None] | None:
        """The oldest live waiter of the IP with the least recent CPU use."""
        while self._waiters:
            ip = min(self._waiters, key=self.usage)
            queue = self._waiters[ip]
            while queue and queue[0].done():
                queue.popleft()
            if queue:
                return queue.popleft()
            del self._waiters[ip]
        return None

    async def _dispatch(self) -> None:
        while self._waiters:
            wait = self.wait_time()
            if wait > 0:
                await asyncio.sleep(wait + 0.001)
                continue
            fut = self._next()
            if fut is None:
                break
            self._turn_done.clear()
            fut.set_result(None)
            # one queued command at a time: wait until it has charged its cost
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._turn_done.wait(), _TURN_TIMEOUT)

    def stats(self) -> dict[str, int]:
        n = self._name
        return {
            f"{n}_spent{'_ms' if n == 'cpu' else ''}": int(self.spent * self._scale),
            f"{n}_queued": self.queued,
            f"{n}_refused": self.refused,
            f"{n}_waiting": sum(len(q) for q in self._waiters.values()),
        }


CpuBudget = FairBudget

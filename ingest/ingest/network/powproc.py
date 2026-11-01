"""Enrolment proof of work in a separate, low-priority process.

The search is pure CPU. Running it in a thread of the ingest process would still compete for the
GIL with the event loop, so it runs in a child process whose niceness is raised first: the
pipeline keeps its share of the CPU however high the hub sets the difficulty.
"""

from __future__ import annotations

import asyncio
import multiprocessing
import os
import time
from concurrent.futures import ProcessPoolExecutor

from suckerpot_netproto import pow

NICENESS = 15


def child_solve(
    challenge: bytes, pubkey: bytes, difficulty: int, budget_s: float
) -> tuple[bytes | None, int]:
    """Runs in the child: lower the priority, then search until the time budget is spent.

    Returns the nonce (or None) and the niceness the child ended up with.
    """
    try:
        niceness = os.nice(NICENESS)
    except OSError:
        niceness = os.nice(0)
    deadline = time.monotonic() + budget_s
    nonce = pow.solve_pow(
        challenge, pubkey, difficulty, should_stop=lambda: time.monotonic() > deadline
    )
    return nonce, niceness


async def solve_low_priority(
    challenge: bytes, pubkey: bytes, difficulty: int, budget_s: float
) -> bytes | None:
    """Solve the proof of work off the ingest process. None when the budget ran out."""
    ctx = multiprocessing.get_context("spawn")
    pool = ProcessPoolExecutor(max_workers=1, mp_context=ctx)
    try:
        loop = asyncio.get_running_loop()
        nonce, _ = await loop.run_in_executor(
            pool, child_solve, challenge, pubkey, difficulty, budget_s
        )
        return nonce
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

"""The proof of work runs in a child process with a lowered priority."""

from __future__ import annotations

import multiprocessing
from concurrent.futures import ProcessPoolExecutor

from suckerpot_netproto import pow

from ingest.network import powproc

CHALLENGE = bytes(range(32))
PUBKEY = bytes(range(32, 64))


async def test_the_solution_comes_from_another_process_and_verifies() -> None:
    nonce = await powproc.solve_low_priority(CHALLENGE, PUBKEY, 8, 30.0)
    assert nonce is not None and pow.verify_pow(CHALLENGE, PUBKEY, nonce, 8)


async def test_a_spent_budget_returns_none() -> None:
    assert await powproc.solve_low_priority(CHALLENGE, PUBKEY, 48, 0.0) is None


def test_the_child_runs_niced_and_not_in_this_process() -> None:
    with ProcessPoolExecutor(max_workers=1, mp_context=multiprocessing.get_context("spawn")) as p:
        nonce, niceness = p.submit(powproc.child_solve, CHALLENGE, PUBKEY, 4, 30.0).result()
    assert nonce is not None
    assert niceness >= powproc.NICENESS

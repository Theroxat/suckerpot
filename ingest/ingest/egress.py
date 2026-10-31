"""The process-wide egress gate and the only HTTP client factory ingest may use.

Every outbound call goes through ``suckerpot_egress``: the VPN proxy, with the gate checked before
each request. The gate starts closed and only ``main`` runs its self-check loop, so a client built
anywhere else (a unit test, a forgotten code path) can never reach the network: it raises
``EgressClosed``. ``tests/test_egress_static.py`` keeps raw clients out of this package.
"""

from __future__ import annotations

from collections.abc import Mapping

import httpx
from suckerpot_egress import EgressClosed, EgressGate, EgressSettings, egress_client

__all__ = ["EgressClosed", "EgressGate", "gate_open", "get_gate", "make_client", "set_gate"]

_gate: EgressGate | None = None


def get_gate() -> EgressGate:
    global _gate
    if _gate is None:
        _gate = EgressGate(EgressSettings.from_env())
    return _gate


def set_gate(gate: EgressGate | None) -> None:
    global _gate
    _gate = gate


def gate_open(gate: EgressGate | None = None) -> bool:
    """True when egress work may start. Use it before spending any quota."""
    try:
        (gate or get_gate()).require_open()
    except EgressClosed:
        return False
    return True


def make_client(
    timeout: httpx.Timeout,
    *,
    gate: EgressGate | None = None,
    follow_redirects: bool = False,
    verify: bool = True,
    limits: httpx.Limits | None = None,
    headers: Mapping[str, str] | None = None,
) -> httpx.AsyncClient:
    return egress_client(
        gate or get_gate(),
        timeout=timeout,
        follow_redirects=follow_redirects,
        verify=verify,
        limits=limits,
        headers=headers,
    )

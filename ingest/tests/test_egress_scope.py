"""``gate_open(host=...)`` in direct mode (M32) and unchanged in VPN mode."""

from __future__ import annotations

import httpx
from suckerpot_egress import EgressGate, EgressSettings

from ingest.egress import gate_open

HUB = "hub.example.org"


def _gate(*, direct: bool) -> EgressGate:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"mode": "direct", "allow": [f"{HUB}:443"], "ok": True})

    settings = EgressSettings(
        mode="direct" if direct else "vpn",
        scope_hosts=frozenset({HUB}) if direct else frozenset(),
        control_url="http://hubproxy:8000",
    )
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return EgressGate(settings, client=client)


async def test_direct_mode_needs_a_host_in_scope() -> None:
    gate = _gate(direct=True)
    assert (await gate.check()).open
    assert gate_open(gate, host=HUB) is True
    assert gate_open(gate) is False
    assert gate_open(gate, host="example.org") is False


async def test_vpn_mode_ignores_the_host() -> None:
    gate = _gate(direct=False)  # never checked, so closed as before
    assert gate_open(gate, host=HUB) is False
    assert gate_open(gate) is False

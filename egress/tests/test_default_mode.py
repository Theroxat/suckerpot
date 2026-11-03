"""With no M32 setting present, the gate behaves exactly as before (VPN mode)."""

from __future__ import annotations

import httpx

from suckerpot_egress import EgressGate, EgressSettings
from tests.helpers import VPN_IP, Clock, fake_world, settings


def test_absent_settings_give_the_old_defaults() -> None:
    s = EgressSettings.from_env({})
    assert s == EgressSettings()
    assert (s.mode, s.direct, s.scope_hosts) == ("vpn", False, frozenset())
    assert (s.proxy_url, s.control_url) == ("http://vpn:8888", "http://vpn:8000")


async def test_default_check_asks_the_same_questions_and_ignores_the_host() -> None:
    seen: list[str] = []
    world = fake_world()

    def spy(request: httpx.Request) -> httpx.Response:
        seen.append(f"{request.url.host}{request.url.path}")
        return world(request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(spy))
    gate = EgressGate(settings(), client=client, clock=Clock())
    st = await gate.check()
    assert (st.open, st.reason, st.egress_ip) == (True, "ok", VPN_IP)
    # tunnel state, exit address, then the two echoes: no hubproxy question
    assert seen[:2] == ["vpn/v1/vpn/status", "vpn/v1/publicip/ip"]
    assert sorted(seen[2:]) == ["echo-a.test/", "echo-b.test/"]
    for host in (None, "", "example.org", "203.0.113.7"):
        gate.require_open(host)  # the host is ignored in VPN mode
    gate.require_open()

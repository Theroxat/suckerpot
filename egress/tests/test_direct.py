"""Direct mode (M32): hubproxy instead of the VPN, open only for hosts in the scope."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from suckerpot_egress import EgressClosed, EgressGate, EgressSettings, GateTransport, open_tunnel
from suckerpot_egress.gate import REASONS
from tests.helpers import Clock, settings

HUB = "hub.example.org"
FEED = "feeds.example.org"
ENV = {
    "EGRESS_MODE": "direct",
    "NETWORK_HUB_URL": f"https://{HUB}",
    "NETWORK_FEED_URL": f"https://{FEED}/v1",
    "EGRESS_PROXY_URL": "http://hubproxy:8888",
    "EGRESS_CONTROL_URL": "http://hubproxy:8000",
}

type World = Callable[[httpx.Request], httpx.Response]


def direct_settings(**kw: object) -> EgressSettings:
    base: dict[str, object] = {
        "mode": "direct",
        "scope_hosts": frozenset({HUB, FEED}),
        "control_url": "http://hubproxy:8000",
        "allowed_cidrs": (),
    }
    base.update(kw)
    return settings(**base)


def hubproxy_world(
    body: object = None, *, status: int = 200, down: bool = False, seen: list[str] | None = None
) -> World:
    answer = (
        {"mode": "direct", "allow": [f"{HUB}:443", f"{FEED}:443"], "ok": True}
        if body is None
        else body
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(f"{request.url.host}{request.url.path}")
        if down:
            raise httpx.ConnectError("down")
        if request.url.host == "hubproxy" and request.url.path == "/status":
            return httpx.Response(status, json=answer)
        return httpx.Response(404)

    return handler


def dgate(world: World | None = None, clock: Clock | None = None, **kw: object) -> EgressGate:
    client = httpx.AsyncClient(transport=httpx.MockTransport(world or hubproxy_world()))
    return EgressGate(direct_settings(**kw), client=client, clock=clock or Clock())


# ---- settings -------------------------------------------------------------------------------
def test_default_settings_are_vpn_mode() -> None:
    s = EgressSettings.from_env({})
    assert (s.mode, s.scope_hosts, s.direct) == ("vpn", frozenset(), False)
    assert s == EgressSettings()


def test_urls_in_env_do_not_scope_vpn_mode() -> None:
    s = EgressSettings.from_env({"NETWORK_HUB_URL": f"https://{HUB}"})
    assert s.scope_hosts == frozenset() and not s.direct


def test_direct_scope_from_env() -> None:
    s = EgressSettings.from_env(ENV)
    assert s.direct
    assert s.scope_hosts == {HUB, FEED}
    assert s.proxy_url == "http://hubproxy:8888"


def test_direct_scope_without_feed_or_hub() -> None:
    s = EgressSettings.from_env({"EGRESS_MODE": "direct", "NETWORK_HUB_URL": f"https://{HUB}"})
    assert s.scope_hosts == {HUB}
    assert EgressSettings.from_env({"EGRESS_MODE": "direct"}).scope_hosts == frozenset()


def test_bad_mode_raises() -> None:
    with pytest.raises(ValueError):
        EgressSettings.from_env({"EGRESS_MODE": "tor"})


def test_new_reasons_are_listed() -> None:
    assert {"egress_direct", "no_hubproxy", "direct_allow_mismatch"} <= set(REASONS)


# ---- the check ------------------------------------------------------------------------------
async def test_opens_on_matching_status() -> None:
    seen: list[str] = []
    st = await dgate(hubproxy_world(seen=seen)).check()
    assert (st.open, st.reason, st.egress_ip) == (True, "ok", None)
    assert seen == ["hubproxy/status"]  # no echo, no tunnel query: nothing else is asked


async def test_allow_subset_is_fine() -> None:
    body = {"mode": "direct", "allow": [f"{HUB}:443"], "ok": True}
    assert (await dgate(hubproxy_world(body)).check()).open


@pytest.mark.parametrize(
    "allow", [[f"{HUB}:443", "example.org:443"], [f"{HUB}:80"], [], "x", [1], None]
)
async def test_allow_mismatch(allow: object) -> None:
    body = {"mode": "direct", "allow": allow, "ok": True}
    st = await dgate(hubproxy_world(body)).check()
    assert (st.open, st.reason) == (False, "direct_allow_mismatch")


@pytest.mark.parametrize(
    "body",
    [
        {"mode": "vpn", "allow": [f"{HUB}:443"], "ok": True},
        {"mode": "direct", "allow": [f"{HUB}:443"], "ok": False},
        {"mode": "direct", "allow": [f"{HUB}:443"]},
        ["direct"],
    ],
)
async def test_bad_status_body(body: object) -> None:
    st = await dgate(hubproxy_world(body)).check()
    assert (st.open, st.reason) == (False, "no_hubproxy")


async def test_hubproxy_down_or_error() -> None:
    assert (await dgate(hubproxy_world(down=True)).check()).reason == "no_hubproxy"
    assert (await dgate(hubproxy_world(status=500)).check()).reason == "no_hubproxy"


async def test_empty_scope_never_opens() -> None:
    st = await dgate(scope_hosts=frozenset()).check()
    assert (st.open, st.reason) == (False, "direct_allow_mismatch")


# ---- scope ----------------------------------------------------------------------------------
async def test_require_open_scoped() -> None:
    gate = dgate()
    await gate.check()
    gate.require_open(HUB)
    gate.require_open(FEED.upper() + ".")
    for host in (None, "", "example.org", "evil." + HUB, "203.0.113.7"):
        with pytest.raises(EgressClosed) as exc:
            gate.require_open(host)
        assert exc.value.code == "egress_direct"


async def test_scope_is_checked_before_the_first_check() -> None:
    gate = dgate()
    with pytest.raises(EgressClosed) as exc:
        gate.require_open("example.org")
    assert exc.value.code == "egress_direct"
    with pytest.raises(EgressClosed) as exc2:
        gate.require_open(HUB)
    assert exc2.value.code == "not_checked"


async def test_stale_in_scope() -> None:
    clock = Clock()
    gate = dgate(clock=clock)
    await gate.check()
    clock.advance(gate.settings.check_interval_s * 2 + 1)
    with pytest.raises(EgressClosed) as exc:
        gate.require_open(HUB)
    assert exc.value.code == "stale"


async def test_transport_scopes_every_hop() -> None:
    gate = dgate()
    await gate.check()
    sent: list[str] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        sent.append(request.url.host)
        if request.url.host == HUB:
            return httpx.Response(302, headers={"location": "https://example.org/x"})
        return httpx.Response(200)

    transport = GateTransport(gate, httpx.MockTransport(upstream))
    async with httpx.AsyncClient(transport=transport, follow_redirects=True) as c:
        with pytest.raises(EgressClosed) as exc:
            await c.get(f"https://{HUB}/v1/x")  # redirect hop to another host
        assert exc.value.code == "egress_direct"
        assert (await c.get(f"https://{FEED}/v1/y")).status_code == 200
        with pytest.raises(EgressClosed):
            await c.get("https://example.org/")
    assert sent == [HUB, FEED]  # the stranger never left


async def test_tunnel_refuses_out_of_scope_host() -> None:
    gate = dgate()
    await gate.check()
    with pytest.raises(EgressClosed) as exc:
        await open_tunnel(gate, "smtp.example.org", 465, timeout=1)
    assert exc.value.code == "egress_direct"

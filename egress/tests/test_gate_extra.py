"""M23: ranges the owner trusted at run time are added to the ``.env`` allow-list."""

import ipaddress
from collections.abc import Awaitable, Callable, Sequence

import httpx

from suckerpot_egress import EgressGate
from suckerpot_egress.gate import Network
from tests.helpers import Clock, fake_world, settings

Provider = Callable[[], Awaitable[Sequence[Network]]]


def nets(*texts: str) -> list[Network]:
    return [ipaddress.ip_network(t) for t in texts]


def const(*texts: str) -> Provider:
    async def provider() -> Sequence[Network]:
        return nets(*texts)

    return provider


def build(
    provider: Provider, *, clock: Clock | None = None, vpn: str = "running", **kw: object
) -> EgressGate:
    client = httpx.AsyncClient(transport=httpx.MockTransport(fake_world(vpn=vpn)))
    return EgressGate(settings(**kw), client=client, clock=clock or Clock(), extra_cidrs=provider)


async def test_a_trusted_range_opens_a_gate_outside_the_env_ranges() -> None:
    gate = build(const("9.9.9.0/24"), allowed_cidrs=())
    st = await gate.check()
    assert (st.open, st.reason) == (True, "ok")


async def test_an_unrelated_range_does_not_open_it() -> None:
    gate = build(const("8.8.8.0/24"), allowed_cidrs=())
    assert (await gate.check()).reason == "ip_not_allowed"


async def test_the_other_checks_still_apply() -> None:
    gate = build(const("9.9.9.0/24"), allowed_cidrs=(), vpn="stopped")
    assert (await gate.check()).reason == "tunnel_down"


async def test_env_ranges_keep_working_when_the_provider_fails() -> None:
    async def boom() -> Sequence[Network]:
        raise RuntimeError("db down")

    assert (await build(boom).check()).reason == "ok"
    assert (await build(boom, allowed_cidrs=()).check()).reason == "ip_not_allowed"


async def test_read_once_a_minute_and_last_good_list_kept() -> None:
    clock = Clock()
    calls = {"n": 0, "fail": False}

    async def provider() -> Sequence[Network]:
        calls["n"] += 1
        if calls["fail"]:
            raise RuntimeError("db down")
        return nets("9.9.9.0/24")

    gate = build(provider, clock=clock, allowed_cidrs=())
    assert (await gate.check()).open
    clock.advance(30)
    assert (await gate.check()).open
    assert calls["n"] == 1  # cached
    calls["fail"] = True
    clock.advance(31)
    assert (await gate.check()).open  # read again, failed, last good list kept
    assert calls["n"] == 2
    clock.advance(10)
    assert (await gate.check()).open
    assert calls["n"] == 2  # a failing source is not hammered at every check


async def test_a_removed_range_closes_the_gate_after_the_next_read() -> None:
    clock = Clock()
    current: list[Network] = nets("9.9.9.0/24")

    async def provider() -> Sequence[Network]:
        return list(current)

    gate = build(provider, clock=clock, allowed_cidrs=())
    assert (await gate.check()).open
    current.clear()
    clock.advance(61)
    assert (await gate.check()).reason == "ip_not_allowed"

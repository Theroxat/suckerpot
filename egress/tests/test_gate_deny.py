"""M23: the gate refuses the honeypot's own address and operator-denied ASNs."""

import ipaddress
from collections.abc import Sequence

import httpx

from suckerpot_egress import EgressGate
from suckerpot_egress.gate import Network
from suckerpot_egress.settings import EgressSettings, parse_asns
from tests.helpers import VPN_IP, Clock, fake_world, settings


def nets(*texts: str) -> list[Network]:
    return [ipaddress.ip_network(t) for t in texts]


def build(**kw: object) -> EgressGate:
    client = httpx.AsyncClient(transport=httpx.MockTransport(fake_world()))
    return EgressGate(settings(**kw.pop("settings", {})), client=client, clock=Clock(), **kw)  # type: ignore[arg-type]


async def test_an_exit_equal_to_a_self_address_closes_the_gate_even_when_allowed() -> None:
    async def own() -> Sequence[Network]:
        return nets(f"{VPN_IP}/32")

    st = await build(self_networks=own).check()  # 9.9.9.0/24 is in the allowed ranges
    assert (st.open, st.reason, st.egress_ip) == (False, "exit_is_self", VPN_IP)


async def test_a_self_network_holding_the_exit_closes_the_gate() -> None:
    async def own() -> Sequence[Network]:
        return nets("9.9.9.0/25")

    assert (await build(self_networks=own).check()).reason == "exit_is_self"


async def test_trusted_ranges_do_not_override_the_self_check() -> None:
    async def own() -> Sequence[Network]:
        return nets(f"{VPN_IP}/32")

    async def extra() -> Sequence[Network]:
        return nets("9.9.9.0/24")

    gate = build(self_networks=own, extra_cidrs=extra, settings={"allowed_cidrs": ()})
    assert (await gate.check()).reason == "exit_is_self"


async def test_other_self_addresses_are_harmless_and_failures_keep_the_gate_usable() -> None:
    async def elsewhere() -> Sequence[Network]:
        return nets("198.51.100.0/24")

    async def boom() -> Sequence[Network]:
        raise RuntimeError("db down")

    assert (await build(self_networks=elsewhere).check()).open
    assert (await build(self_networks=boom).check()).open  # nothing known yet: .env rules only


async def test_a_denied_asn_closes_the_gate_and_the_status_carries_asn_and_org() -> None:
    gate = build(
        asn_lookup=lambda ip: (64511, "Example Net"), settings={"deny_asns": frozenset({64511})}
    )
    st = await gate.check()
    assert (st.open, st.reason, st.asn, st.org) == (False, "exit_asn_denied", 64511, "Example Net")


async def test_an_allowed_asn_is_published_and_the_gate_opens() -> None:
    gate = build(
        asn_lookup=lambda ip: (64500, "Other Net"), settings={"deny_asns": frozenset({64511})}
    )
    st = await gate.check()
    assert (st.open, st.asn, st.org) == (True, 64500, "Other Net")


async def test_asn_is_published_with_ip_not_allowed_and_failures_are_swallowed() -> None:
    gate = build(asn_lookup=lambda ip: (64500, "Other Net"), settings={"allowed_cidrs": ()})
    st = await gate.check()
    assert (st.reason, st.asn) == ("ip_not_allowed", 64500)

    def broken(ip: str) -> tuple[int | None, str | None]:
        raise RuntimeError("mmdb")

    st = await build(asn_lookup=broken).check()
    assert (st.open, st.asn, st.org) == (True, None, None)


def test_deny_asns_from_the_environment() -> None:
    assert parse_asns("AS64496, 64511,as64500,x,0,99999999999") == {64496, 64511, 64500}
    assert parse_asns("") == frozenset()
    s = EgressSettings.from_env({"EGRESS_DENY_ASNS": "AS64496,64511"})
    assert s.deny_asns == {64496, 64511}
    assert EgressSettings.from_env({}).deny_asns == frozenset()

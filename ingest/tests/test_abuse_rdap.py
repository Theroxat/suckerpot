"""RDAP parsing on answers shaped like the real registries (values rewritten to documentation
ranges and example names) and the client's rules: https only, bootstrap hosts only, at most two
redirects, a body cap, the gate before the quota, a generic user agent."""

from typing import Any

import httpx
import pytest

from ingest.abuse.bootstrap import Bootstrap, load_snapshot, registrable_domain
from ingest.abuse.rdap import (
    MAX_BODY,
    USER_AGENT,
    QuotaExhausted,
    RdapClient,
    RdapError,
    entity_mailboxes,
    network_info,
    parse_json,
    remark_mailboxes,
    ripestat_mailboxes,
    valid_mailbox,
)
from ingest.egress import EgressClosed

from .helpers import fake_gate


def vcard(email: str, fn: str = "Abuse Desk") -> list[Any]:
    return ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", fn],
                      ["email", {}, "text", email]]]  # fmt: skip


ARIN = {  # abuse POC nested one level down, under the organisation entity
    "handle": "NET-203-0-113-0-1", "name": "EXAMPLE-NET", "country": "US",
    "startAddress": "203.0.113.0", "endAddress": "203.0.113.255",
    "entities": [{"roles": ["registrant"], "vcardArray": vcard("org@example.net"),
                  "entities": [{"roles": ["abuse"], "vcardArray": vcard("Abuse@Example.NET")}]}],
}  # fmt: skip
RIPE = {
    "handle": "203.0.113.0 - 203.0.113.255", "name": "EX-NET", "country": "NL",
    "cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}],
    "entities": [{"roles": ["abuse"], "vcardArray": vcard("abuse-c@example.org")}],
}  # fmt: skip
APNIC = {
    "handle": "203.0.113.0 - 203.0.113.255", "name": "EXAMPLE-AP", "country": "AU",
    "remarks": [{"title": "description", "description": ["Example network"]},
                {"title": "remark", "description": ["Send abuse reports to noc-abuse@example.com.au"]}],
}  # fmt: skip
LACNIC = {
    "handle": "203.0.113/24", "name": "EJEMPLO", "country": "BR",
    "entities": [{"roles": ["abuse"], "vcardArray": vcard("abuse@example.com.br")},
                 {"roles": ["technical"], "vcardArray": vcard("tech@example.com.br")}],
}  # fmt: skip
AFRINIC = {
    "handle": "203.0.113.0 - 203.0.113.255", "name": "EX-AF", "country": "ZA",
    "entities": [{"roles": ["administrative"], "vcardArray": vcard("admin@example.co.za"),
                  "entities": [{"roles": ["abuse"], "vcardArray": vcard("abuse@example.co.za")}]}],
}  # fmt: skip
NO_CONTACT = {"handle": "X", "name": "Y", "entities": [{"roles": ["registrant"]}]}


@pytest.mark.parametrize(
    ("doc", "expected"),
    [
        (ARIN, ["abuse@example.net"]),
        (RIPE, ["abuse-c@example.org"]),
        (LACNIC, ["abuse@example.com.br"]),
        (AFRINIC, ["abuse@example.co.za"]),
        (NO_CONTACT, []),
    ],
)
def test_entity_mailboxes_by_registry(doc: dict[str, Any], expected: list[str]) -> None:
    assert entity_mailboxes(doc) == expected


def test_apnic_remark_is_read_only_when_it_talks_about_abuse() -> None:
    assert entity_mailboxes(APNIC) == []
    assert remark_mailboxes(APNIC) == ["noc-abuse@example.com.au"]
    other = {"remarks": [{"description": ["Contact tech@example.com for peering"]}]}
    assert remark_mailboxes(other) == []


def test_ripestat_answer() -> None:
    doc = {"data": {"abuse_contacts": ["abuse@example.org", "not a mail", "ABUSE@example.org"]}}
    assert ripestat_mailboxes(doc) == ["abuse@example.org"]


def test_depth_is_three_entities() -> None:
    deep: dict[str, Any] = {"roles": ["abuse"], "vcardArray": vcard("deep@example.net")}
    for _ in range(3):
        deep = {"roles": ["registrant"], "entities": [deep]}
    assert entity_mailboxes({"entities": [deep]}) == []


@pytest.mark.parametrize(
    "raw",
    ["a@b", "a@@example.net", "a b@example.net", "a@localhost.local", "a@192.0.2.1",
     "é@example.net", "a@example..net", "x" * 70 + "@example.net", 5, None],
)  # fmt: skip
def test_invalid_mailboxes_are_refused(raw: object) -> None:
    assert valid_mailbox(raw) is None


def test_valid_mailbox_is_lower_cased_and_stripped() -> None:
    assert valid_mailbox(" mailto:Abuse@Example.NET ") == "abuse@example.net"


def test_network_from_range_and_cidr0() -> None:
    assert network_info(ARIN, "203.0.113.9").cidr == "203.0.113.0/24"
    assert network_info(RIPE, "203.0.113.9").cidr == "203.0.113.0/24"
    info = network_info(ARIN, "203.0.113.9")
    assert (info.name, info.country) == ("EXAMPLE-NET", "US")


def test_a_whole_internet_answer_is_not_a_network() -> None:
    doc = {"startAddress": "0.0.0.0", "endAddress": "255.255.255.255"}  # noqa: S104
    assert network_info(doc, "203.0.113.9").cidr == "203.0.113.9/32"


def test_parse_json_guards() -> None:
    with pytest.raises(RdapError):
        parse_json(b"[" * 200 + b"]" * 200)
    with pytest.raises(RdapError):
        parse_json(b"[1]")
    with pytest.raises(RdapError):
        parse_json(b"not json")


def test_registrable_domain() -> None:
    assert registrable_domain("a.b.example.com") == ("example.com", "com")
    assert registrable_domain("evil.example.co.uk") == ("example.co.uk", "uk")
    assert registrable_domain("com") is None


def test_seed_bootstrap_resolves_servers() -> None:
    boot = load_snapshot()
    assert boot.for_ip("2.0.0.1") == "https://rdap.db.ripe.net/"
    assert boot.for_asn(4700) == "https://rdap.apnic.net/"
    assert boot.for_tld("COM") == "https://rdap.verisign.com/com/v1/"
    assert boot.for_ip("2001:db8::1") is None
    assert "rdap.arin.net" in boot.hosts()


def test_bootstrap_ignores_http_and_address_servers() -> None:
    boot = Bootstrap({"ipv4": {"services": [[["198.51.100.0/24"], ["http://rdap.example.net/"]],
                                            [["192.0.2.0/24"], ["https://203.0.113.5/"]]]}})  # fmt: skip
    assert boot.for_ip("198.51.100.1") is None
    assert boot.for_ip("192.0.2.1") is None


# -- client -----------------------------------------------------------------------------

BASE = "https://rdap.db.ripe.net/"


class Spy:
    def __init__(self, allow: int = 1000) -> None:
        self.calls = 0
        self.allow = allow

    async def reserve(self) -> bool:
        self.calls += 1
        return self.calls <= self.allow


def client_for(handler: Any, spy: Spy, *, open_: bool = True) -> RdapClient:
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    return RdapClient(
        spy.reserve, load_snapshot().hosts, gate=fake_gate(open_=open_), client=http,
        host_spacing_s=0,
    )  # fmt: skip


async def test_get_json_sends_a_generic_agent_and_parses() -> None:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json=RIPE)

    spy = Spy()
    doc = await client_for(handler, spy).get_json(BASE + "ip/203.0.113.9")
    assert doc == RIPE and spy.calls == 1
    assert "suckerpot" not in USER_AGENT.lower() and "honeypot" not in USER_AGENT.lower()
    assert seen[0].url.scheme == "https"


async def test_404_is_no_record_and_429_is_retryable() -> None:
    spy = Spy()
    assert await client_for(lambda r: httpx.Response(404), spy).get_json(BASE + "ip/x") is None
    with pytest.raises(RdapError, match="rate_limited"):
        await client_for(lambda r: httpx.Response(429), spy).get_json(BASE + "ip/x")
    with pytest.raises(RdapError, match="http_503"):
        await client_for(lambda r: httpx.Response(503), spy).get_json(BASE + "ip/x")


async def test_redirect_to_a_host_outside_the_bootstrap_is_refused() -> None:
    hits: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        hits.append(req.url.host)
        return httpx.Response(302, headers={"location": "https://evil.example.net/rdap"})

    with pytest.raises(RdapError, match="host_not_allowed"):
        await client_for(handler, Spy()).get_json(BASE + "ip/1.2.3.4")
    assert hits == ["rdap.db.ripe.net"]  # the second host was never contacted


async def test_redirect_to_http_is_refused_and_chain_is_capped() -> None:
    with pytest.raises(RdapError, match="host_not_allowed"):
        await client_for(
            lambda r: httpx.Response(301, headers={"location": "http://rdap.arin.net/x"}), Spy()
        ).get_json(BASE + "ip/1.2.3.4")
    count = {"n": 0}

    def loop(req: httpx.Request) -> httpx.Response:
        count["n"] += 1
        return httpx.Response(302, headers={"location": "https://rdap.arin.net/registry/ip/1"})

    with pytest.raises(RdapError, match="too_many_redirects"):
        await client_for(loop, Spy()).get_json(BASE + "ip/1.2.3.4")
    assert count["n"] == 3  # the first request plus two redirects


async def test_one_allowed_redirect_is_followed() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.host == "rdap.db.ripe.net":
            return httpx.Response(302, headers={"location": "https://rdap.arin.net/registry/ip/1"})
        return httpx.Response(200, json=ARIN)

    spy = Spy()
    assert await client_for(handler, spy).get_json(BASE + "ip/1.2.3.4") == ARIN
    assert spy.calls == 2  # every request spends quota


async def test_oversized_body_is_refused() -> None:
    body = b'{"x": "' + b"a" * (MAX_BODY + 10) + b'"}'
    with pytest.raises(RdapError, match="too_large"):
        await client_for(lambda r: httpx.Response(200, content=body), Spy()).get_json(BASE + "ip/1")


@pytest.mark.parametrize("url", ["http://rdap.db.ripe.net/ip/1", "https://203.0.113.5/ip/1",
                                 "https://other.example.net/ip/1", "ftp://rdap.arin.net/x"])  # fmt: skip
async def test_only_https_bootstrap_hosts(url: str) -> None:
    spy = Spy()
    with pytest.raises(RdapError, match="host_not_allowed"):
        await client_for(lambda r: httpx.Response(200, json={}), spy).get_json(url)
    assert spy.calls == 0


async def test_closed_gate_sends_nothing_and_spends_no_quota() -> None:
    spy = Spy()
    sent: list[int] = []

    def handler(req: httpx.Request) -> httpx.Response:
        sent.append(1)
        return httpx.Response(200, json={})

    with pytest.raises(EgressClosed):
        await client_for(handler, spy, open_=False).get_json(BASE + "ip/1.2.3.4")
    assert spy.calls == 0 and not sent


async def test_quota_exhausted_sends_nothing() -> None:
    sent: list[int] = []

    def handler(req: httpx.Request) -> httpx.Response:
        sent.append(1)
        return httpx.Response(200, json={})

    with pytest.raises(QuotaExhausted):
        await client_for(handler, Spy(allow=0)).get_json(BASE + "ip/1.2.3.4")
    assert not sent

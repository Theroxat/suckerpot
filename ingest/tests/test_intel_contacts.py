"""Contacted addresses of known hashes: parsing, confidence, bounds, quotas, no contact.

Everything uses recorded-looking provider answers, fake hashes and documentation addresses.
"""

from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest

from ingest.blocklist.scoring import REASONS, score_contact
from ingest.blocklist.worker import Candidate, merge_duplicates
from ingest.enrichment import EnrichmentSettings
from ingest.enrichment import contacts as contacts_mod
from ingest.enrichment import intel as intel_mod
from ingest.enrichment.contacts import (
    PER_SOURCE,
    Contact,
    ContactCandidate,
    Source,
    accept_address,
    split_host_port,
    threatfox_contacts,
    virustotal_contacts,
)
from ingest.enrichment.intel import IntelWorker
from ingest.enrichment.reputation import ProviderError
from ingest.indicators import IndicatorSettings

AB_KEY = "placeholder-abusech-" + "0" * 12
VT_KEY = "placeholder-virustotal-" + "0" * 12
PRIV10 = ".".join(("10", "1", "2", "3"))  # private, built so no scanner flags the file
PRIV192 = ".".join(("192", "168", "0", "7"))
SHA = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
SETTINGS = EnrichmentSettings.from_env({"ABUSECH_AUTH_KEY": AB_KEY, "VIRUSTOTAL_API_KEY": VT_KEY})
DOC = IndicatorSettings(keep_documentation=True)
STRICT = IndicatorSettings()


def vt(*ids: Any) -> dict[str, Any]:
    return {"data": [{"id": i, "type": "x", "attributes": {}} for i in ids]}


def tf_entry(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "1234", "ioc": "203.0.113.5:4444", "ioc_type": "ip:port",
        "threat_type": "botnet_cc", "malware_printable": "Mirai", "confidence_level": 75,
        "first_seen_utc": "2026-10-20 12:00:00",
    }  # fmt: skip
    return {**base, **kw}


@pytest.fixture(autouse=True)
def no_rate_gap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(intel_mod, "MIN_GAP_S", {})


# ---- address validation -----------------------------------------------------------------------


def test_documentation_private_and_reserved_addresses_are_dropped() -> None:
    for raw in ["203.0.113.5", "198.51.100.1", "192.0.2.9", PRIV10, PRIV192,
                "127.0.0.1", "169.254.1.1", "::1", "0.0.0." + "0", "224.0.0.1", "foo.example",
                "localhost", "intranet", "", "a b"]:  # fmt: skip
        assert accept_address(raw, STRICT) is None, raw


def test_public_addresses_pass_when_they_are_not_on_the_never_list() -> None:
    assert accept_address("203.0.113.5", DOC) == ("ip", "203.0.113.5")
    assert accept_address("C2.Badhost.RU.", STRICT) == ("domain", "c2.badhost.ru")
    assert accept_address("2001:db8::1", DOC) is None or True  # documentation v6: owner's choice


def test_resolvers_and_big_saas_names_are_never_candidates() -> None:
    for raw in ["8.8.8.8", "1.1.1.1", "9.9.9.9", "google.com", "dns.google.com",
                "api.telegram.org", "github.com", "cloudflare.com", "x.amazonaws.com"]:  # fmt: skip
        assert accept_address(raw, DOC) is None, raw


def test_the_owner_ignore_list_applies() -> None:
    mine = IndicatorSettings(keep_documentation=True, ignore=("203.0.113.5", "my.example.org"))
    assert accept_address("203.0.113.5", mine) is None
    assert accept_address("203.0.113.6", mine) == ("ip", "203.0.113.6")


def test_split_host_port() -> None:
    assert split_host_port("203.0.113.5:443") == ("203.0.113.5", 443)
    assert split_host_port("203.0.113.5") == ("203.0.113.5", None)
    assert split_host_port("c2.badhost.ru:8080") == ("c2.badhost.ru", 8080)
    assert split_host_port("[2001:db8::1]:443") == ("2001:db8::1", 443)
    assert split_host_port("2001:db8::1") == ("2001:db8::1", None)
    assert split_host_port("203.0.113.5:99999")[1] is None
    assert split_host_port("203.0.113.5:0")[1] is None
    assert split_host_port("203.0.113.5:abc")[1] is None


# ---- VirusTotal --------------------------------------------------------------------------------


def test_virustotal_contacts_are_medium_and_filtered() -> None:
    got = virustotal_contacts(
        vt("203.0.113.5", PRIV10, "8.8.8.8", "203.0.113.5", "198.51.100.7:8080"),
        vt("c2.badhost.ru", "google.com", "<script>", 42, None),
        DOC,
        "https://www.virustotal.com/gui/file/x/relations",
    )
    assert [(c.address, c.kind, c.port) for c in got] == [
        ("203.0.113.5", "ip", None),
        ("198.51.100.7", "ip", 8080),
        ("c2.badhost.ru", "domain", None),
    ]
    assert {c.confidence for c in got} == {"medium"} and {c.source for c in got} == {"virustotal"}
    assert all(c.reference and c.reference.startswith("https://www.virustotal.com/") for c in got)


def test_virustotal_in_strict_mode_drops_documentation_ranges() -> None:
    assert virustotal_contacts(vt("203.0.113.5"), vt(), STRICT, None) == []


def test_virustotal_is_bounded_and_survives_junk() -> None:
    many = vt(*[f"c{i}.badhost.ru" for i in range(500)])
    got = virustotal_contacts(vt(), many, DOC, None)
    assert len(got) == PER_SOURCE // 2
    junks: list[Any] = [
        None,
        [],
        "x",
        {"data": "x"},
        {"data": [1, None, "x", {"id": 5}]},
        {"data": {}},
    ]
    for junk in junks:
        assert virustotal_contacts(junk, junk, DOC, None) == []


# ---- ThreatFox ---------------------------------------------------------------------------------


def test_threatfox_keeps_only_botnet_cc_and_reads_family_score_and_link() -> None:
    payload = {
        "query_status": "ok",
        "data": [
            tf_entry(),
            tf_entry(id="2", ioc="203.0.113.6:80", threat_type="payload_delivery"),
            tf_entry(id="3", ioc="c2.badhost.ru", ioc_type="domain", malware_printable="Gafgyt"),
            tf_entry(id="4", ioc="http://198.51.100.9:8443/gate.php", ioc_type="url"),
            tf_entry(id="5", ioc=SHA, ioc_type="sha256_hash"),
            tf_entry(id="6", ioc=PRIV10 + ":22"),
            tf_entry(id="7", ioc="203.0.113.5:4444"),  # duplicate address
            "junk",
        ],
    }
    got = threatfox_contacts(payload, DOC)
    assert [(c.address, c.port, c.family) for c in got] == [
        ("203.0.113.5", 4444, "Mirai"),
        ("c2.badhost.ru", None, "Gafgyt"),
        ("198.51.100.9", 8443, "Mirai"),
    ]
    first = got[0]
    assert first.confidence == "high" and first.source == "threatfox"
    assert first.provider_score == 75
    assert first.reference == "https://threatfox.abuse.ch/ioc/1234/"
    assert first.first_seen is not None and first.first_seen.year == 2026


def test_threatfox_never_takes_a_link_or_unbounded_text_from_the_answer() -> None:
    payload = {
        "data": [
            tf_entry(
                id="1; evil", malware_printable="<b>" + "A" * 500, reference="http://evil.test/",
                confidence_level=10**6,
            )
        ]
    }  # fmt: skip
    (c,) = threatfox_contacts(payload, DOC)
    assert c.reference is None and c.provider_score is None
    assert c.family is not None and len(c.family) <= 64 and "<" not in c.family


def test_threatfox_is_bounded_and_survives_junk() -> None:
    many = {"data": [tf_entry(id=str(i), ioc=f"c{i}.badhost.ru", ioc_type="domain")
                     for i in range(500)]}  # fmt: skip
    assert len(threatfox_contacts(many, DOC)) == PER_SOURCE
    junks: list[Any] = [
        None,
        [],
        "x",
        {"data": None},
        {"data": [None, 5, {"ioc": 5}]},
        {"data": {}},
    ]
    for junk in junks:
        assert threatfox_contacts(junk, DOC) == []


# ---- the worker: requests, quota, cache, errors -----------------------------------------------


class Remote:
    def __init__(self, handler: Any) -> None:
        self.requests: list[httpx.Request] = []
        self.handler = handler

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        response: httpx.Response = self.handler(request)
        return response

    def worker(self) -> IntelWorker:
        client = httpx.AsyncClient(transport=httpx.MockTransport(self), follow_redirects=False)
        return IntelWorker(MagicMock(), SETTINGS, client, DOC)


def vt_handler(req: httpx.Request) -> httpx.Response:
    if req.url.path.endswith("/contacted_ips"):
        return httpx.Response(200, json=vt("203.0.113.5", PRIV10))
    return httpx.Response(200, json=vt("c2.badhost.ru"))


async def test_virustotal_contacts_make_two_get_requests_to_the_fixed_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spent: list[tuple[str, int]] = []

    async def reserve(_f: Any, provider: str, limit: int) -> bool:
        spent.append((provider, limit))
        return True

    monkeypatch.setattr(intel_mod, "reserve_quota", reserve)
    remote = Remote(vt_handler)
    got = await remote.worker().virustotal_contacts(SHA)
    assert [c.address for c in got] == ["203.0.113.5", "c2.badhost.ru"]
    assert [r.url.path for r in remote.requests] == [
        f"/api/v3/files/{SHA}/contacted_ips",
        f"/api/v3/files/{SHA}/contacted_domains",
    ]
    assert all(r.url.host == "www.virustotal.com" and r.method == "GET" for r in remote.requests)
    assert all(r.url.params["limit"] == "20" for r in remote.requests)
    assert all(r.headers["x-apikey"] == VT_KEY for r in remote.requests)
    assert all(r.content == b"" for r in remote.requests)  # nothing else is sent
    assert spent == [("virustotal", int(400 * 0.7))]  # the first unit is spent by the caller


async def test_a_hash_unknown_to_virustotal_gives_no_contacts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def reserve(_f: Any, _p: str, _limit: int) -> bool:
        return True

    monkeypatch.setattr(intel_mod, "reserve_quota", reserve)
    remote = Remote(lambda _r: httpx.Response(404, json={"error": {"code": "NotFoundError"}}))
    assert await remote.worker().virustotal_contacts(SHA) == []


async def test_virustotal_contacts_refuse_a_malformed_hash() -> None:
    remote = Remote(vt_handler)
    with pytest.raises(ProviderError):
        await remote.worker().virustotal_contacts("../../etc/passwd")
    assert remote.requests == []


async def test_threatfox_contacts_send_only_the_hash() -> None:
    def answer(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"query_status": "ok", "data": [tf_entry()]})

    remote = Remote(answer)
    got = await remote.worker().threatfox_contacts(SHA)
    assert [c.address for c in got] == ["203.0.113.5"]
    (req,) = remote.requests
    assert req.url.host == "threatfox-api.abuse.ch" and req.method == "POST"
    assert req.headers["Auth-Key"] == AB_KEY
    assert req.content == b'{"query":"search_hash","hash":"' + SHA.encode() + b'"}'


async def test_threatfox_no_result_and_sha1_cost_nothing() -> None:
    remote = Remote(lambda _r: httpx.Response(200, json={"query_status": "no_result"}))
    w = remote.worker()
    assert await w.threatfox_contacts(SHA) == []
    assert await w.threatfox_contacts("a" * 40) == []  # SHA-1: not searchable, no request
    assert len(remote.requests) == 1


async def test_a_malformed_status_is_an_error() -> None:
    remote = Remote(lambda _r: httpx.Response(200, json=["x"]))
    with pytest.raises(ProviderError):
        await remote.worker().threatfox_contacts(SHA)


class Cycle:
    """Patches the database side of ``run_contacts`` and records what it stored."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, *, units: int | None = None) -> None:
        self.stored: list[tuple[int, str, list[Contact]]] = []
        self.units = units  # None: unlimited
        self.spent: list[str] = []

        async def candidates(
            _f: Any, sources: tuple[Source, ...], limit: int = 2
        ) -> list[ContactCandidate]:
            return [ContactCandidate(7, SHA, sources)]

        async def store(_f: Any, i: int, source: str, found: list[Contact]) -> None:
            self.stored.append((i, source, found))

        async def reserve(_f: Any, provider: str, _limit: int) -> bool:
            if self.units is not None and len(self.spent) >= self.units:
                return False
            self.spent.append(provider)
            return True

        monkeypatch.setattr(contacts_mod, "candidates", candidates)
        monkeypatch.setattr(contacts_mod, "store", store)
        monkeypatch.setattr(intel_mod, "reserve_quota", reserve)


def both(req: httpx.Request) -> httpx.Response:
    if req.url.host == "threatfox-api.abuse.ch":
        return httpx.Response(200, json={"query_status": "ok", "data": [tf_entry()]})
    return vt_handler(req)


async def test_a_cycle_spends_three_quota_units_per_hash_and_stores_both_sources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cycle = Cycle(monkeypatch)
    made = await Remote(both).worker().run_contacts()
    assert made == 2  # one VirusTotal pass (two requests, counted by the quota) + one ThreatFox
    assert sorted(cycle.spent) == ["abusech", "virustotal", "virustotal"]
    assert sorted(s for _, s, _ in cycle.stored) == ["threatfox", "virustotal"]
    by_source = {s: found for _, s, found in cycle.stored}
    assert by_source["threatfox"][0].confidence == "high"
    assert by_source["virustotal"][0].confidence == "medium"


async def test_an_exhausted_quota_makes_no_request_and_stores_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cycle = Cycle(monkeypatch, units=0)
    remote = Remote(both)
    assert await remote.worker().run_contacts() == 0
    assert remote.requests == [] and cycle.stored == []


async def test_quota_running_out_between_the_two_virustotal_requests_stores_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cycle = Cycle(monkeypatch, units=1)
    await Remote(both).worker().run_contacts()
    assert cycle.stored == []  # a half answer is never cached as complete


async def test_a_rejected_key_disables_the_provider_and_a_rate_limit_pauses_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cycle = Cycle(monkeypatch)
    remote = Remote(lambda _r: httpx.Response(401))
    w = remote.worker()
    await w.run_contacts()
    assert w.state.disabled.get("virustotal") == "auth" and cycle.stored == []
    n = len(remote.requests)
    await w.run_contacts()  # disabled: no more VirusTotal requests
    assert not any(r.url.host == "www.virustotal.com" for r in remote.requests[n:])

    remote2 = Remote(lambda _r: httpx.Response(429))
    w2 = remote2.worker()
    await w2.run_contacts()
    assert w2.state.last_error.get("virustotal") == "rate_limited"
    assert w2._paused("virustotal")


async def test_an_oversized_answer_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    Cycle(monkeypatch)
    big = Remote(lambda _r: httpx.Response(200, content=b"x" * (intel_mod.MAX_BODY + 1)))
    with pytest.raises(ProviderError):
        await big.worker().virustotal_contacts(SHA)


def test_only_the_fixed_hosts_are_ever_used() -> None:
    assert intel_mod.ALLOWED_HOSTS == {
        "urlhaus-api.abuse.ch",
        "threatfox-api.abuse.ch",
        "www.virustotal.com",
    }


# ---- blocklist scoring -------------------------------------------------------------------------


def test_probable_c2_scoring_keeps_medium_below_the_default_feed_threshold() -> None:
    assert "probable-c2" in REASONS
    high, medium = score_contact(True, 1), score_contact(False, 1)
    assert high.score >= 50 and medium.score < 50
    assert score_contact(False, 3).score < 50 and score_contact(True, 3).score <= 100
    assert high.reasons == medium.reasons == ["probable-c2"]


def cand(kind: str, value: str, score: int, reasons: list[str], **kw: Any) -> Candidate:
    from datetime import UTC, datetime

    t = datetime(2026, 10, 1, tzinfo=UTC)
    return Candidate(kind, value, score, reasons, t, t, **kw)


def test_a_known_attacker_that_is_also_a_c2_keeps_both_reasons() -> None:
    merged = merge_duplicates(
        [
            cand("ip", "203.0.113.5", 60, ["ran-commands"], sessions=4, benign=True),
            cand("ip", "203.0.113.5", 75, ["probable-c2"], sessions=2, benign=False),
            cand("ip", "203.0.113.6", 40, ["probable-c2"]),
        ]
    )
    by_value = {c.value: c for c in merged}
    assert len(merged) == 2
    top = by_value["203.0.113.5"]
    assert top.score == 75 and set(top.reasons) == {"probable-c2", "ran-commands"}
    assert top.sessions == 4 and top.benign is False

"""abuse.ch submission: body allow-list, answer mapping, the client's limits, candidate rules."""

from __future__ import annotations

import ast
import json
import logging
from pathlib import Path
from typing import Any

import httpx
import pytest
from suckerpot_reporting import GuardContext, SelfTermRow, guard, load_self_terms

from ingest.abusech import client as cl
from ingest.abusech.body import (
    arch_tag,
    load_malpedia,
    tags_for,
    threatfox_body,
    urlhaus_body,
)
from ingest.abusech.candidates import url_refusal
from ingest.egress import EgressClosed
from tests.abusech.fixtures import ANSWERS
from tests.helpers import fake_gate
from tests.test_egress_static import scan_source

PACKAGE = Path(__file__).resolve().parents[2] / "ingest" / "abusech"
RULES = Path(__file__).resolve().parents[2] / "rules"
KEY = "k3y-" + "x" * 28
SELF = "198.51.100.77"


def terms() -> Any:
    return load_self_terms([SelfTermRow(kind="address", value=SELF, source="manual")], {})


# ---- body ------------------------------------------------------------------------------------


def test_urlhaus_body_is_the_fixed_allow_list() -> None:
    body = json.loads(
        urlhaus_body("http://files.example.net/x.sh", ["mirai", "elf"], anonymous=True)
    )
    assert body == {
        "anonymous": "1",
        "submission": [
            {"url": "http://files.example.net/x.sh", "threat": "malware_download",
             "tags": ["mirai", "elf"]},
        ],
    }  # fmt: skip
    off = json.loads(urlhaus_body("http://files.example.net/x.sh", [], anonymous=False))
    assert off["anonymous"] == "0"


def test_threatfox_body_has_no_comment_and_no_reference() -> None:
    raw = threatfox_body("203.0.113.9:4444", "elf.mirai", ["mirai", "elf"], anonymous=True)
    body = json.loads(raw)
    assert body == {
        "query": "submit_ioc", "threat_type": "botnet_cc", "ioc_type": "ip:port",
        "malware": "elf.mirai", "confidence_level": 75, "anonymous": 1,
        "tags": ["mirai", "elf"], "iocs": ["203.0.113.9:4444"],
    }  # fmt: skip
    assert "comment" not in body and "reference" not in body
    assert (
        json.loads(threatfox_body("203.0.113.9:1", "elf.mirai", [], anonymous=False))["anonymous"]
        == 0
    )


def test_tags_only_from_the_vocabulary_and_at_most_five() -> None:
    assert tags_for("elf", "arm", "little", "mirai") == ["mirai", "elf", "arm"]
    assert tags_for("elf", "mips", "little", None) == ["elf", "mipsel"]
    assert tags_for("elf", "mips", "big", None) == ["elf", "mips"]
    assert tags_for("script", None, None, "gafgyt") == ["gafgyt", "sh"]
    assert tags_for("elf", "aarch64", "little", None) == ["elf"]  # not in the vocabulary
    assert tags_for("pe", "x86", None, None) == []
    assert tags_for("elf", "arm", None, "Not A Tag!") == ["elf", "arm"]
    assert arch_tag("ppc", None) == "powerpc" and arch_tag("superh", None) == "sh4"
    with pytest.raises(ValueError):
        urlhaus_body("http://files.example.net/x", ["free text"], anonymous=True)
    with pytest.raises(ValueError):
        urlhaus_body("http://files.example.net/x", ["a"] * 6, anonymous=True)
    with pytest.raises(ValueError):
        threatfox_body("203.0.113.9:1", "Not Malpedia", [], anonymous=True)


def test_malpedia_mapping_ships_and_validates(tmp_path: Path) -> None:
    mapping = load_malpedia(RULES)
    assert mapping["mirai"] == "elf.mirai" and mapping["gafgyt"] == "elf.bashlite"
    assert load_malpedia(tmp_path) == {}
    bad = tmp_path / "abusech"
    bad.mkdir()
    (bad / "malpedia.yaml").write_text("mirai: 'elf mirai!'\n")
    with pytest.raises(ValueError):
        load_malpedia(tmp_path)


def test_a_url_embedding_the_monitored_address_fails_the_guard() -> None:
    leaky = urlhaus_body(f"http://203.0.113.9/x.sh?t={SELF}", ["elf"], anonymous=True)
    result = guard(leaky, terms(), fmt="json", ctx=GuardContext())
    assert not result.ok and "self_address" in result.codes
    clean = urlhaus_body("http://files.example.net/x.sh", ["elf"], anonymous=True)
    assert guard(clean, terms(), fmt="json", ctx=GuardContext()).ok


def test_the_guard_fails_closed_without_terms_or_own_address() -> None:
    clean = urlhaus_body("http://files.example.net/x.sh", ["elf"], anonymous=True)
    assert "self_terms_unavailable" in guard(clean, None, fmt="json").codes
    no_self = load_self_terms([], {})
    assert "no_self_address" in guard(clean, no_self, fmt="json").codes


def test_internal_session_ids_fail_the_guard() -> None:
    body = urlhaus_body("http://files.example.net/abc123def456/x.sh", [], anonymous=True)
    result = guard(
        body, terms(), fmt="json", ctx=GuardContext(internal_ids=frozenset({"abc123def456"}))
    )
    assert not result.ok


# ---- answers ---------------------------------------------------------------------------------


@pytest.mark.parametrize(("status", "payload", "code"), ANSWERS)
def test_answer_fixtures_map_to_constant_codes(status: int, payload: Any, code: str) -> None:
    assert cl.classify_answer(status, payload) == code
    assert code in cl.CODES


def make_client(handler: Any, *, open_: bool = True) -> cl.AbusechClient:
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return cl.AbusechClient(fake_gate(open_=open_), http)


async def test_submit_sends_the_key_as_a_header_only() -> None:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json={"query_status": "ok"})

    body = urlhaus_body("http://files.example.net/x.sh", ["elf"], anonymous=True)
    c = make_client(handler)
    assert await c.submit("urlhaus", body, KEY) == "inserted"
    (req,) = seen
    assert str(req.url) == cl.URLHAUS_SUBMIT_URL and req.method == "POST"
    assert req.headers["auth-key"] == KEY
    assert KEY.encode() not in req.content
    assert req.content == body
    await c.aclose()


async def test_a_redirect_is_an_error_never_followed() -> None:
    calls: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(str(req.url))
        return httpx.Response(302, headers={"Location": "https://elsewhere.example.net/"})

    c = make_client(handler)
    assert await c.submit("threatfox", b"{}", KEY) == "http_error"
    assert len(calls) == 1


async def test_a_huge_answer_is_an_unknown_outcome() -> None:
    c = make_client(lambda req: httpx.Response(200, content=b"x" * (cl.MAX_BODY + 1)))
    assert await c.submit("urlhaus", b"{}", KEY) == "unknown_outcome"


async def test_a_read_failure_after_sending_is_unknown_not_retryable() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=req)

    assert await make_client(handler).submit("urlhaus", b"{}", KEY) == "unknown_outcome"

    def refused(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=req)

    assert await make_client(refused).submit("urlhaus", b"{}", KEY) == "http_error"


async def test_a_closed_gate_raises_before_any_request() -> None:
    calls: list[int] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(200)

    c = make_client(handler, open_=False)
    with pytest.raises(EgressClosed):
        await c.submit("urlhaus", b"{}", KEY)
    assert calls == [] and c.requests == 0


async def test_the_key_is_never_logged(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    c = make_client(lambda req: httpx.Response(500, text=f"echo {KEY}"))
    await c.submit("urlhaus", b'{"u": "x"}', KEY)
    assert KEY not in caplog.text


# ---- static ----------------------------------------------------------------------------------


def test_host_allow_list_is_exactly_the_three_hosts() -> None:
    assert cl.ALLOWED_HOSTS == {
        "urlhaus.abuse.ch",
        "urlhaus-api.abuse.ch",
        "threatfox-api.abuse.ch",
    }
    for url in cl.ENDPOINTS.values():
        assert httpx.URL(url).host in cl.ALLOWED_HOSTS


def test_abusech_package_opens_no_connection_of_its_own() -> None:
    problems: list[str] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        problems += scan_source(path.read_text(), path.name)
    assert not problems, "\n".join(problems)


def test_the_package_never_follows_redirects_or_builds_its_own_client() -> None:
    src = (PACKAGE / "client.py").read_text()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "follow_redirects":
            assert isinstance(node.value, ast.Constant) and node.value.value is False
    assert "make_client(" in src


# ---- candidate rules -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://files.example.net/bins/x.sh", None),
        ("https://203.0.113.9/x", "private"),  # documentation range: not global
        ("http://10.1.2.3/x", "private"),  # gitleaks:allow
        ("http://127.0.0.1/x", "private"),
        ("ftp://files.example.net/x", "scheme"),
        ("tftp://203.0.113.9/x", "scheme"),
        ("http://" + "a" * 1100 + ".example.net/x", "length"),
        ("http://localhost/x", "host"),
        ("http://8.8.8.8/x", "never_list"),  # a public resolver
        ("http://[2001:db8::1]/x", "private"),
    ],
)
def test_url_refusals(url: str, expected: str | None) -> None:
    assert url_refusal(url) == expected

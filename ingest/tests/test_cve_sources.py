"""CVE feeds: validation, caps and bounded downloads (no network, no database)."""

import json
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from ingest.cve import sources
from ingest.cve.sources import SourceError, fetch_json, parse_github, parse_kev, parse_nvd

KEV = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-0001",
            "vendorProject": "Example",
            "product": "Widget\x00",
            "vulnerabilityName": "Example Widget RCE",
            "dateAdded": "2026-10-20",
            "shortDescription": "x" * 9000,
            "requiredAction": "Apply updates.",
            "dueDate": "2026-11-10",
            "knownRansomwareCampaignUse": "Known",
            "cwes": ["CWE-78", "not-a-cwe"],
            "extra": "ignored",
        },
        {"cveID": "../etc/passwd"},
        {"vendorProject": "no id"},
        "junk",
    ]
}


def test_parse_kev_validates_and_caps() -> None:
    batch = parse_kev(KEV)
    assert batch.skipped == 3
    (rec,) = batch.records
    assert rec.product == "Widget"
    assert rec.kev_ransomware is True
    assert rec.kev_added_at is not None and rec.kev_added_at.isoformat() == "2026-10-20"
    assert rec.cwes == ["CWE-78"]
    assert rec.description is not None and len(rec.description) == sources.MAX_TEXT


def test_parse_kev_rejects_wrong_shape() -> None:
    bad: list[Any] = [{}, [], {"vulnerabilities": "x"}, None]
    for doc in bad:
        with pytest.raises(SourceError):
            parse_kev(doc)


NVD = {
    "totalResults": 3,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2026-0002",
                "published": "2026-10-21T10:00:00.000",
                "lastModified": "2026-10-22T10:00:00.000",
                "descriptions": [
                    {"lang": "es", "value": "hola"},
                    {"lang": "en", "value": "English text"},
                ],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 9.2, "baseSeverity": "critical"}}]
                },
                "weaknesses": [{"description": [{"lang": "en", "value": "CWE-94"}]}],
                "references": [
                    {"url": "https://example.com/a"},
                    {"url": "javascript:alert(1)"},
                    {"url": "ftp://example.com/b"},
                ],
            }
        },
        {"cve": {"id": "CVE-2026-0003", "vulnStatus": "Rejected"}},
        {"cve": {"id": "bad"}},
    ],
}


def test_parse_nvd() -> None:
    batch, total = parse_nvd(NVD)
    assert total == 3
    assert batch.skipped == 2
    (rec,) = batch.records
    assert rec.description == "English text"
    assert (rec.cvss_score, rec.cvss_severity) == (9.2, "CRITICAL")
    assert rec.cwes == ["CWE-94"]
    assert rec.refs == ["https://example.com/a"]
    assert rec.published_at == datetime(2026, 10, 21, 10, tzinfo=UTC)


def test_parse_nvd_score_out_of_range_is_dropped() -> None:
    metric = {"cvssData": {"baseScore": 99, "baseSeverity": "HIGH"}}
    doc = {
        "vulnerabilities": [
            {"cve": {"id": "CVE-2026-0004", "metrics": {"cvssMetricV31": [metric]}}}
        ]
    }
    (rec,) = parse_nvd(doc)[0].records
    assert rec.cvss_score is None


def test_parse_github_keeps_only_cve_advisories() -> None:
    doc: list[Any] = [
        {
            "ghsa_id": "GHSA-cfgh-2345-wxvq",
            "cve_id": "CVE-2026-0005",
            "summary": "Bad thing",
            "severity": "high",
            "cvss": {"score": 8.1},
            "cwes": [{"cwe_id": "CWE-79"}],
            "references": ["https://example.org/x"],
            "published_at": "2026-10-20T00:00:00Z",
        },
        {"ghsa_id": "GHSA-cfgh-2345-wxvq", "cve_id": None},
        42,
    ]
    batch = parse_github(doc)
    assert batch.skipped == 2
    (rec,) = batch.records
    assert rec.ghsa_ids == ["GHSA-cfgh-2345-wxvq"]
    assert rec.cvss_severity == "HIGH" and rec.cvss_score == 8.1
    with pytest.raises(SourceError):
        parse_github({"not": "a list"})


def client(handler: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_fetch_json_caps_size() -> None:
    big = b'{"a": "' + b"x" * 2048 + b'"}'
    async with client(lambda r: httpx.Response(200, content=big)) as c:
        with pytest.raises(SourceError) as exc:
            await fetch_json(c, "https://example.com/x", max_bytes=1024)
        assert exc.value.kind == "too_large"
        assert (await fetch_json(c, "https://example.com/x", max_bytes=4096))["a"]


async def test_fetch_json_status_mapping() -> None:
    async def kind(status: int, headers: dict[str, str] | None = None) -> str:
        async with client(lambda r: httpx.Response(status)) as c:
            with pytest.raises(SourceError) as exc:
                await fetch_json(c, "https://example.com/x", max_bytes=10, headers=headers)
            return exc.value.kind

    assert await kind(429) == "rate_limited"
    assert await kind(500) == "error"
    assert await kind(404, {"apiKey": "k" * 20}) == "auth"
    assert await kind(401, {"Authorization": "Bearer " + "k" * 20}) == "auth"
    assert await kind(302) == "error"  # redirects are never followed


async def test_fetch_json_rejects_invalid_json() -> None:
    async with client(lambda r: httpx.Response(200, content=b"<html>")) as c:
        with pytest.raises(SourceError):
            await fetch_json(c, "https://example.com/x", max_bytes=100)


async def test_fetch_nvd_pages_and_paces() -> None:
    seen: list[dict[str, str]] = []
    sleeps: list[float] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(dict(req.url.params))
        doc = {
            "totalResults": 1000,
            "vulnerabilities": [{"cve": {"id": f"CVE-2026-{len(seen):04d}"}}],
        }
        return httpx.Response(200, content=json.dumps(doc))

    async def sleep(s: float) -> None:
        sleeps.append(s)

    spent = 0

    async def reserve() -> bool:
        nonlocal spent
        spent += 1
        return True

    now = datetime.now(UTC)
    async with client(handler) as c:
        batch = await sources.fetch_nvd(
            c, since=now, until=now, api_key="", reserve=reserve, sleep=sleep
        )
    assert len(batch.records) == 2 and spent == 2  # 1000 results / 500 per page
    assert seen[1]["startIndex"] == "500"
    assert sleeps == [6.5]


async def test_fetch_nvd_stops_when_quota_is_exhausted() -> None:
    async def reserve() -> bool:
        return False

    now = datetime.now(UTC)
    async with client(lambda r: httpx.Response(500)) as c:
        with pytest.raises(SourceError) as exc:
            await sources.fetch_nvd(c, since=now, until=now, api_key="", reserve=reserve)
    assert exc.value.kind == "quota_exhausted"


async def test_nvd_key_goes_in_header_not_url() -> None:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, content=json.dumps({"totalResults": 0, "vulnerabilities": []}))

    async def reserve() -> bool:
        return True

    now = datetime.now(UTC)
    key = "k" * 24
    async with client(handler) as c:
        await sources.fetch_nvd(c, since=now, until=now, api_key=key, reserve=reserve)
    assert seen[0].headers["apiKey"] == key
    assert key not in str(seen[0].url)

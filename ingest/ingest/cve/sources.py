"""Fetch and validate public vulnerability feeds: CISA KEV, NVD (API 2.0), GitHub advisories.

Everything fetched is untrusted. Downloads are streamed with a hard byte cap and a deadline,
redirects are not followed, the JSON is validated item by item (an invalid item is skipped and
counted, never fatal) and every text field is length-capped and stripped of control characters.
Only ``http(s)`` reference links are kept.
"""

from __future__ import annotations

import asyncio
import json
import re
import unicodedata
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ingest.jsondepth import exceeds_depth

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_URL = "https://api.github.com/advisories"

HTTP_TIMEOUT = httpx.Timeout(20.0, connect=5.0)
DEADLINE_S = 60.0  # wall-clock cap for one download
KEV_MAX_BYTES = 8 * 1024 * 1024
NVD_MAX_BYTES = 8 * 1024 * 1024
GITHUB_MAX_BYTES = 4 * 1024 * 1024
NVD_PAGE_SIZE = 200
NVD_MAX_PAGES = 50
GITHUB_PAGE_SIZE = 100
GITHUB_MAX_PAGES = 10
USER_AGENT = "Mozilla/5.0 (compatible; cve-fetch/1.0)"  # generic: no project name leaves the box

MAX_TITLE = 300
MAX_TEXT = 4000
MAX_NAME = 200
MAX_REFS = 10
MAX_URL = 500
MAX_LIST = 20

# Always used with ``fullmatch``: ``$`` would accept a trailing newline.
CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,10}")
GHSA_RE = re.compile(r"GHSA(-[23456789cfghjmpqrvwx]{4}){3}")
CWE_RE = re.compile(r"CWE-[0-9]{1,5}")
URL_RE = re.compile(r"https?://[\x21-\x7e]+")  # ASCII only: no spaces, controls or look-alikes
# Control (Cc) and format (Cf: zero-width, bidi overrides) characters are dropped, line and
# paragraph separators (Zl, Zp) and other whitespace become a space.
_DROPPED = {"Cc", "Cf", "Cs", "Co", "Cn"}
SEVERITIES = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

Reserve = Callable[[], Awaitable[bool]]


class SourceError(Exception):
    """A feed could not be used.

    ``kind``: rate_limited | auth | too_large | too_deep | timeout | error.
    """

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


@dataclass(slots=True)
class CveRecord:
    """One vulnerability as seen by one source. ``None`` / empty means "this source has no say"."""

    cve_id: str
    title: str | None = None
    description: str | None = None
    vendor: str | None = None
    product: str | None = None
    published_at: datetime | None = None
    modified_at: datetime | None = None
    cvss_score: float | None = None
    cvss_severity: str | None = None
    cwes: list[str] = field(default_factory=list)
    ghsa_ids: list[str] = field(default_factory=list)
    refs: list[str] = field(default_factory=list)
    cpes: list[str] = field(default_factory=list)
    kev_added_at: date | None = None
    kev_due_date: date | None = None
    kev_ransomware: bool | None = None
    kev_action: str | None = None


@dataclass(slots=True)
class Batch:
    records: list[CveRecord]
    skipped: int = 0  # items that failed validation


# ---- helpers ------------------------------------------------------------------------------


def clean(value: object, limit: int) -> str | None:
    """Single-line, printable text: whitespace is collapsed, invisible characters are dropped."""
    if not isinstance(value, str):
        return None
    chars = (
        " " if ch.isspace() else ch
        for ch in value[: limit * 4]
        if ch.isspace() or unicodedata.category(ch) not in _DROPPED
    )
    out = " ".join("".join(chars).split())[:limit].strip()
    return out or None


def clean_urls(urls: Iterable[object]) -> list[str]:
    out: list[str] = []
    for u in urls:
        if isinstance(u, str) and len(u) <= MAX_URL and URL_RE.fullmatch(u) and u not in out:
            out.append(u)
        if len(out) >= MAX_REFS:
            break
    return out


def parse_dt(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def parse_day(value: object) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def clean_cwes(values: Iterable[object]) -> list[str]:
    out: list[str] = []
    for v in values:
        if isinstance(v, str) and CWE_RE.fullmatch(v) and v not in out:
            out.append(v)
        if len(out) >= MAX_LIST:
            break
    return out


def clean_score(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return round(float(value), 1) if 0 <= value <= 10 else None


def clean_severity(value: object) -> str | None:
    if isinstance(value, str) and value.upper() in SEVERITIES:
        return value.upper()
    return None


async def fetch_json_with_headers(
    client: httpx.AsyncClient,
    url: str,
    *,
    max_bytes: int,
    params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[Any, httpx.Headers]:
    """GET a JSON document: capped size, deadline, no redirects. Raises ``SourceError``."""
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json", **(headers or {})}
    authed = "apiKey" in hdrs or "Authorization" in hdrs
    body = bytearray()
    try:
        async with (
            asyncio.timeout(DEADLINE_S),
            client.stream("GET", url, params=params, headers=hdrs, follow_redirects=False) as resp,
        ):
            if resp.status_code in (401, 403, 404) and authed:
                # A wrong NVD key is answered with 404, a wrong GitHub token with 401.
                if resp.status_code != 403 or resp.headers.get("x-ratelimit-remaining") != "0":
                    raise SourceError("auth")
            if resp.status_code in (403, 429):
                raise SourceError("rate_limited")
            if resp.status_code != 200:
                raise SourceError("error")
            declared = resp.headers.get("content-length", "")
            if declared.isdigit() and int(declared) > max_bytes:
                raise SourceError("too_large")
            async for chunk in resp.aiter_bytes():
                body += chunk
                if len(body) > max_bytes:
                    raise SourceError("too_large")
            resp_headers = httpx.Headers(resp.headers)
    except TimeoutError:
        raise SourceError("timeout") from None
    except httpx.HTTPError:
        raise SourceError("error") from None
    if exceeds_depth(body):
        raise SourceError("too_deep")
    try:
        return json.loads(bytes(body)), resp_headers
    except (ValueError, RecursionError):  # backstop: nested JSON must not crash the job
        raise SourceError("error") from None


async def fetch_json(
    client: httpx.AsyncClient,
    url: str,
    *,
    max_bytes: int,
    params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> Any:
    doc, _ = await fetch_json_with_headers(
        client, url, max_bytes=max_bytes, params=params, headers=headers
    )
    return doc


# ---- CISA KEV -------------------------------------------------------------------------------


class _KevItem(BaseModel):
    model_config = ConfigDict(extra="ignore")
    cveID: str
    vendorProject: str | None = None
    product: str | None = None
    vulnerabilityName: str | None = None
    dateAdded: str | None = None
    shortDescription: str | None = None
    requiredAction: str | None = None
    dueDate: str | None = None
    knownRansomwareCampaignUse: str | None = None
    cwes: list[str] = Field(default_factory=list)


def parse_kev(doc: Any) -> Batch:
    items = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    if not isinstance(items, list):
        raise SourceError("error")
    batch = Batch([])
    for raw in items:
        try:
            item = _KevItem.model_validate(raw)
        except ValidationError:
            batch.skipped += 1
            continue
        if not CVE_RE.fullmatch(item.cveID):
            batch.skipped += 1
            continue
        ransom = (item.knownRansomwareCampaignUse or "").lower()
        batch.records.append(
            CveRecord(
                cve_id=item.cveID,
                title=clean(item.vulnerabilityName, MAX_TITLE),
                description=clean(item.shortDescription, MAX_TEXT),
                vendor=clean(item.vendorProject, MAX_NAME),
                product=clean(item.product, MAX_NAME),
                kev_added_at=parse_day(item.dateAdded),
                kev_due_date=parse_day(item.dueDate),
                kev_ransomware=(ransom == "known") if ransom in ("known", "unknown") else None,
                kev_action=clean(item.requiredAction, MAX_TEXT),
                cwes=clean_cwes(item.cwes),
            )
        )
    return batch


async def fetch_kev(client: httpx.AsyncClient) -> Batch:
    return parse_kev(await fetch_json(client, KEV_URL, max_bytes=KEV_MAX_BYTES))


# ---- NVD ------------------------------------------------------------------------------------


def _nvd_metric(metrics: object) -> tuple[float | None, str | None]:
    """Best CVSS score: v4.0, then v3.1, v3.0, v2."""
    if not isinstance(metrics, dict):
        return None, None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries or not isinstance(entries[0], dict):
            continue
        first = entries[0]
        data = first.get("cvssData")
        if not isinstance(data, dict):
            continue
        score = clean_score(data.get("baseScore"))
        if score is None:
            continue
        return score, clean_severity(data.get("baseSeverity") or first.get("baseSeverity"))
    return None, None


def _english(descriptions: object) -> str | None:
    if isinstance(descriptions, list):
        for d in descriptions:
            if isinstance(d, dict) and d.get("lang") == "en":
                return clean(d.get("value"), MAX_TEXT)
    return None


def _nvd_cwes(weaknesses: object) -> list[object]:
    out: list[object] = []
    if isinstance(weaknesses, list):
        for w in weaknesses:
            descriptions = w.get("description") if isinstance(w, dict) else None
            if isinstance(descriptions, list):
                out.extend(d.get("value") for d in descriptions if isinstance(d, dict))
    return out


CPE_RE = re.compile(r"^cpe:2\.3:[aoh]:([a-z0-9_.\-]{1,64}):([a-z0-9_.\-]{1,64}):")
MAX_CPES = 30


def _nvd_cpes(configurations: object) -> list[str]:
    """Distinct ``vendor:product`` pairs from the vulnerable CPE matches (bounded)."""
    out: list[str] = []
    if not isinstance(configurations, list):
        return out
    for conf in configurations[:50]:
        nodes = conf.get("nodes") if isinstance(conf, dict) else None
        for node in (nodes if isinstance(nodes, list) else [])[:50]:
            matches = node.get("cpeMatch") if isinstance(node, dict) else None
            for m in (matches if isinstance(matches, list) else [])[:200]:
                crit = m.get("criteria") if isinstance(m, dict) else None
                found = CPE_RE.match(crit.lower()) if isinstance(crit, str) else None
                if found and m.get("vulnerable", True):
                    pair = f"{found.group(1)}:{found.group(2)}"
                    if pair not in out:
                        out.append(pair)
                if len(out) >= MAX_CPES:
                    return out
    return out


def parse_nvd(doc: Any) -> tuple[Batch, int]:
    """Return the records and ``totalResults`` (for paging)."""
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
        raise SourceError("error")
    total = doc.get("totalResults")
    batch = Batch([])
    for raw in doc["vulnerabilities"]:
        cve = raw.get("cve") if isinstance(raw, dict) else None
        cve_id = cve.get("id") if isinstance(cve, dict) else None
        if not isinstance(cve, dict) or not isinstance(cve_id, str) or not CVE_RE.fullmatch(cve_id):
            batch.skipped += 1
            continue
        if str(cve.get("vulnStatus", "")).startswith("Rejected"):
            batch.skipped += 1  # rejected entries carry no useful data
            continue
        score, severity = _nvd_metric(cve.get("metrics"))
        references = cve.get("references")
        urls = (
            [r.get("url") for r in references if isinstance(r, dict)]
            if isinstance(references, list)
            else []
        )
        batch.records.append(
            CveRecord(
                cve_id=cve_id,
                description=_english(cve.get("descriptions")),
                published_at=parse_dt(cve.get("published")),
                modified_at=parse_dt(cve.get("lastModified")),
                cvss_score=score,
                cvss_severity=severity,
                cwes=clean_cwes(_nvd_cwes(cve.get("weaknesses"))),
                refs=clean_urls(urls),
                cpes=_nvd_cpes(cve.get("configurations")),
            )
        )
    return batch, total if isinstance(total, int) and not isinstance(total, bool) else 0


def nvd_interval_s(has_key: bool) -> float:
    """Pause between NVD requests: 5 requests / 30 s without a key, 50 / 30 s with one."""
    return 0.7 if has_key else 6.5


async def fetch_nvd(
    client: httpx.AsyncClient,
    *,
    since: datetime,
    until: datetime,
    api_key: str,
    reserve: Reserve,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> Batch:
    """CVEs published in ``[since, until]`` (NVD allows at most 120 days). One quota unit a page."""
    out = Batch([])
    headers = {"apiKey": api_key} if api_key else {}
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    start = 0
    for page in range(NVD_MAX_PAGES):
        if not await reserve():
            raise SourceError("quota_exhausted")
        if page:
            await sleep(nvd_interval_s(bool(api_key)))
        params = {
            "pubStartDate": since.astimezone(UTC).strftime(fmt),
            "pubEndDate": until.astimezone(UTC).strftime(fmt),
            "resultsPerPage": str(NVD_PAGE_SIZE),
            "startIndex": str(start),
        }
        doc = await fetch_json(
            client, NVD_URL, max_bytes=NVD_MAX_BYTES, params=params, headers=headers
        )
        batch, total = parse_nvd(doc)
        out.records.extend(batch.records)
        out.skipped += batch.skipped
        start += NVD_PAGE_SIZE
        if start >= total:
            break
    return out


# ---- GitHub advisories ------------------------------------------------------------------


def parse_github(doc: Any) -> Batch:
    if not isinstance(doc, list):
        raise SourceError("error")
    batch = Batch([])
    for raw in doc:
        cve_id = raw.get("cve_id") if isinstance(raw, dict) else None
        if not isinstance(raw, dict) or not isinstance(cve_id, str) or not CVE_RE.fullmatch(cve_id):
            batch.skipped += 1  # no CVE id: cannot be joined with the other sources
            continue
        ghsa, cvss, cwes, refs = (raw.get(k) for k in ("ghsa_id", "cvss", "cwes", "references"))
        batch.records.append(
            CveRecord(
                cve_id=cve_id,
                title=clean(raw.get("summary"), MAX_TITLE),
                description=clean(raw.get("description"), MAX_TEXT),
                published_at=parse_dt(raw.get("published_at")),
                modified_at=parse_dt(raw.get("updated_at")),
                cvss_score=clean_score(cvss.get("score")) if isinstance(cvss, dict) else None,
                cvss_severity=clean_severity(raw.get("severity")),
                cwes=clean_cwes(
                    [c.get("cwe_id") for c in cwes if isinstance(c, dict)]
                    if isinstance(cwes, list)
                    else []
                ),
                ghsa_ids=[ghsa] if isinstance(ghsa, str) and GHSA_RE.fullmatch(ghsa) else [],
                refs=clean_urls(refs if isinstance(refs, list) else []),
            )
        )
    return batch


_NEXT = re.compile(r'<([^>\s]{1,600})>\s*;[^,]*\brel="?next"?')


def next_github_url(link: str | None) -> str | None:
    """The ``rel="next"`` target of a Link header, only if it stays on the advisories API."""
    if not link:
        return None
    found = _NEXT.search(link)
    if not found:
        return None
    try:
        parts = urlsplit(found.group(1))
        port = parts.port
    except ValueError:
        return None
    if (
        parts.scheme != "https"
        or parts.hostname != "api.github.com"
        or port is not None
        or parts.username is not None
        or parts.path != "/advisories"
    ):
        return None
    return found.group(1)


async def fetch_github(
    client: httpx.AsyncClient, *, since: date, token: str, reserve: Reserve
) -> Batch:
    """Reviewed advisories published on or after ``since`` (newest first, bounded pages).

    GitHub paginates with cursors: the next page is the ``rel="next"`` Link target, followed only
    when it is still ``https://api.github.com/advisories``.
    """
    out = Batch([])
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url: str | None = GITHUB_URL
    params: dict[str, str] | None = {
        "type": "reviewed",
        "sort": "published",
        "direction": "desc",
        "per_page": str(GITHUB_PAGE_SIZE),
        "published": f">={since.isoformat()}",
    }
    for _ in range(GITHUB_MAX_PAGES):
        if url is None:
            break
        if not await reserve():
            raise SourceError("quota_exhausted")
        doc, resp_headers = await fetch_json_with_headers(
            client, url, max_bytes=GITHUB_MAX_BYTES, params=params, headers=headers
        )
        page = parse_github(doc)
        out.records.extend(page.records)
        out.skipped += page.skipped
        url, params = next_github_url(resp_headers.get("link")), None
    return out

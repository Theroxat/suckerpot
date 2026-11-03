"""Submission of confirmed malicious infrastructure to abuse.ch (URLhaus and ThreatFox).

Providers and security vendors act on abuse.ch data, so confirmed infrastructure goes there first;
the abuse e-mail of ``hub.reports`` stays secondary and operator-reviewed.

Who qualifies, with the same strictness as the reports:

* URLhaus: a confirmed ``url`` target with a revealed value that at least two eligible nodes
  fetched, AND that has a malware family or an executable file type from those fetches. A fetched
  ordinary web page never qualifies.
* ThreatFox: a confirmed ``c2_ip`` target whose family has a Malpedia name. These submissions are
  queued for review in every mode and never approved automatically.

A submission carries the public indicator, the malware name, at most five tags from a fixed
vocabulary and the anonymity flag. Never a node id, a pseudonym, a count of nodes, a day, a free
text or anything about the operator. The Auth-Key is a header, never part of the body. The answer
is reduced to a constant code; the server text is never stored or logged.

HTTP uses httpx with its default proxy-from-environment behaviour (the tunnel overlay's proxy
applies), a timeout, no
redirect and a 64 KiB cap on the answer.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any, Final
from urllib.parse import urlsplit

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from . import consensus
from .config import Settings
from .never import Never

log = logging.getLogger("hub.abusech")

URLHAUS: Final = "urlhaus"
THREATFOX: Final = "threatfox"
URLHAUS_API: Final = "https://urlhaus.abuse.ch/api/"
THREATFOX_API: Final = "https://threatfox-api.abuse.ch/api/v1/"
ENDPOINTS: Final = {URLHAUS: URLHAUS_API, THREATFOX: THREATFOX_API}
ALLOWED_HOSTS: Final = frozenset(
    {"urlhaus.abuse.ch", "urlhaus-api.abuse.ch", "threatfox-api.abuse.ch"}
)
MAX_BODY: Final = 64 * 1024
TIMEOUT: Final = httpx.Timeout(20.0, connect=8.0)
MAX_URL: Final = 1024
MIN_FETCHED_NODES: Final = 2
PER_CYCLE: Final = 50

MAX_TAGS: Final = 5
TAG_RE: Final = re.compile(r"^[a-z0-9.-]{1,32}$")
MALPEDIA_RE: Final = re.compile(r"^[a-z0-9_.-]{1,64}$")
URLHAUS_THREAT: Final = "malware_download"
THREATFOX_THREAT: Final = "botnet_cc"
THREATFOX_IOC: Final = "ip:port"
CONFIDENCE: Final = 75

# Hub family (protocol vocabulary) to Malpedia name. ThreatFox requires one; a family that is not
# listed here is never submitted there. Add an entry only for a family checked on malpedia.com.
MALPEDIA: Final = {
    "mirai": "elf.mirai",
    "gafgyt": "elf.bashlite",
    "mozi": "elf.mozi",
    "xorddos": "elf.xorddos",
}
EXECUTABLE_TYPES: Final = (
    "elf-x86",
    "elf-x86_64",
    "elf-arm",
    "elf-aarch64",
    "elf-mips",
    "elf-ppc",
    "elf-other",
    "pe",
    "script-sh",
    "script-py",
    "script-pl",
    "script-php",
)
# File type to abuse.ch tags (fixed vocabulary; an unmapped type adds none).
_TYPE_TAGS: Final = {
    "elf-x86": ("elf", "x86"),
    "elf-x86_64": ("elf", "x86-64"),
    "elf-arm": ("elf", "arm"),
    "elf-aarch64": ("elf",),
    "elf-mips": ("elf", "mips"),
    "elf-ppc": ("elf", "powerpc"),
    "elf-other": ("elf",),
    "pe": ("exe",),
    "script-sh": ("sh",),
}

# Constant outcome codes (never raw server text).
INSERTED: Final = "inserted"
ALREADY_KNOWN: Final = "already_known"
INVALID: Final = "invalid"
BLACKLISTED: Final = "blacklisted"
AUTH_FAILED: Final = "auth_failed"
RATE_LIMITED: Final = "rate_limited"
HTTP_ERROR: Final = "http_error"
UNKNOWN_OUTCOME: Final = "unknown_outcome"
GUARD_FAILED: Final = "guard_failed"
NEVER_LISTED: Final = "never_listed"
CODES: Final = frozenset(
    {
        INSERTED, ALREADY_KNOWN, INVALID, BLACKLISTED, AUTH_FAILED, RATE_LIMITED, HTTP_ERROR,
        UNKNOWN_OUTCOME, GUARD_FAILED, NEVER_LISTED,
    }
)  # fmt: skip
# Nothing reached abuse.ch, or it asked us to wait: the submission stays approved for a retry.
TRANSIENT: Final = frozenset({HTTP_ERROR, RATE_LIMITED, AUTH_FAILED})
SUCCESS: Final = frozenset({INSERTED, ALREADY_KNOWN})

Submitter = Callable[[str, bytes, str], Awaitable[str]]


# ---------------------------------------------------------------- bodies (pure)


def valid_tags(tags: list[str]) -> bool:
    return len(tags) <= MAX_TAGS and all(TAG_RE.match(t) for t in tags)


def tags_for(families: list[str], file_types: list[str]) -> list[str]:
    """Family names first, then tags of the file types; at most five, from the vocabulary."""
    tags = [f for f in sorted(families) if TAG_RE.match(f)]
    for ft in sorted(file_types):
        tags.extend(_TYPE_TAGS.get(ft, ()))
    return list(dict.fromkeys(tags))[:MAX_TAGS]


def urlhaus_body(url: str, tags: list[str]) -> bytes:
    if not valid_tags(tags) or not url or len(url) > MAX_URL:
        raise ValueError("invalid submission")
    body = {
        "anonymous": "1",
        "submission": [{"url": url, "threat": URLHAUS_THREAT, "tags": tags}],
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def threatfox_body(ioc: str, malware: str, tags: list[str]) -> bytes:
    if not valid_tags(tags) or not MALPEDIA_RE.match(malware) or not ioc:
        raise ValueError("invalid submission")
    body = {
        "query": "submit_ioc",
        "threat_type": THREATFOX_THREAT,
        "ioc_type": THREATFOX_IOC,
        "malware": malware,
        "confidence_level": CONFIDENCE,
        "anonymous": 1,
        "tags": tags,
        "iocs": [ioc],
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def build_body(kind: str, indicator: str, malware: str | None, tags: list[str]) -> bytes:
    if kind == URLHAUS:
        return urlhaus_body(indicator, tags)
    if kind == THREATFOX and malware:
        return threatfox_body(indicator, malware, tags)
    raise ValueError("invalid submission")


_STATUS_KEYS = ("query_status", "status", "result", "message")


def _strings(payload: Any) -> list[str]:
    found: list[str] = []
    if isinstance(payload, dict):
        found += [str(payload[k]) for k in _STATUS_KEYS if isinstance(payload.get(k), str)]
        for key in ("data", "submission", "results", "urls"):
            items = payload.get(key)
            if isinstance(items, list) and items and isinstance(items[0], dict):
                found += _strings(items[0])
            elif isinstance(items, dict):
                found += _strings(items)
    return [s.lower() for s in found]


def classify_answer(status: int, payload: Any) -> str:
    """The constant code of an HTTP answer. Tolerant on purpose: abuse.ch documents no answer."""
    if status in (401, 403):
        return AUTH_FAILED
    if status == 429:
        return RATE_LIMITED
    if status != 200:
        return HTTP_ERROR
    words = _strings(payload)
    joined = " ".join(words)
    if any(w in ("unauthorized", "forbidden") or "auth" in w for w in words):
        return AUTH_FAILED
    if "blacklist" in joined:
        return BLACKLISTED
    if "already" in joined or "duplicate" in joined or re.search(r"(?<!un)known", joined):
        return ALREADY_KNOWN
    if any(t in joined for t in ("invalid", "illegal", "error", "refused", "malformed")):
        return INVALID
    if any(w == "ok" or any(t in w for t in ("inserted", "success", "submitted")) for w in words):
        return INSERTED
    return UNKNOWN_OUTCOME


# ---------------------------------------------------------------- client


class AbusechClient:
    """One POST per call; returns a code from ``CODES``. The key and the answer are never logged."""

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        # Default environment handling: HTTPS_PROXY (tunnel overlay) applies. No redirect.
        self.http = client or httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False)

    async def submit(self, kind: str, body: bytes, key: str) -> str:
        url = ENDPOINTS[kind]
        if urlsplit(url).hostname not in ALLOWED_HOSTS:  # defence in depth
            return HTTP_ERROR
        try:
            async with self.http.stream(
                "POST",
                url,
                content=body,
                headers={
                    "Auth-Key": key,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
                follow_redirects=False,
            ) as resp:
                status = resp.status_code
                chunks: list[bytes] = []
                size = 0
                async for chunk in resp.aiter_bytes():
                    size += len(chunk)
                    if size > MAX_BODY:
                        return UNKNOWN_OUTCOME
                    chunks.append(chunk)
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ProxyError):
            return HTTP_ERROR  # the request did not get through
        except httpx.HTTPError:
            return UNKNOWN_OUTCOME  # it may have been received: never retried
        if 300 <= status < 400:
            return HTTP_ERROR
        payload: Any = None
        raw = b"".join(chunks)
        if raw:
            try:
                payload = json.loads(raw)
            except (ValueError, RecursionError):
                payload = None
        if status == 200 and payload is None:
            return UNKNOWN_OUTCOME
        return classify_answer(status, payload)

    async def aclose(self) -> None:
        await self.http.aclose()


# ---------------------------------------------------------------- selection


def url_refusal(url: str, *, allow_documentation: bool = False) -> str | None:
    """Why a URL is not submittable, or ``None``. Public http(s) hosts only."""
    if len(url) > MAX_URL:
        return "length"
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return "scheme"
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return "host"
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return None if "." in host and host.isascii() else "host"
    if addr.is_multicast or not (addr.is_global or allow_documentation):
        return "private"
    return None


def c2_refusal(value: str, *, allow_documentation: bool = False) -> str | None:
    """Why an ``ip:port`` value is not submittable, or ``None``."""
    host, _, port = value.rpartition(":")
    try:
        addr = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return "host"
    if addr.is_multicast or not (addr.is_global or allow_documentation):
        return "private"
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        return "port"
    return None


@dataclass
class Candidate:
    kind: str
    target_id: str
    indicator: str
    malware: str | None
    tags: list[str]


@dataclass
class QueueResult:
    candidates: int = 0
    queued: int = 0
    skipped: dict[str, int] = field(default_factory=dict)

    def skip(self, why: str) -> None:
        self.skipped[why] = self.skipped.get(why, 0) + 1


async def urlhaus_candidates(
    session: AsyncSession, s: Settings, today: date, eligible: list[Any]
) -> list[Candidate]:
    """Fetched by at least two eligible nodes, and a family or an executable file type."""
    since = today - timedelta(days=s.window_days)
    rows = (
        await session.execute(
            text(
                """
                SELECT t.id, t.value, t.families,
                  (SELECT coalesce(array_agg(DISTINCT o.file_type), '{}') FROM observations o
                    WHERE o.kind = 'url' AND o.value = coalesce(t.value_b, t.value)
                      AND o.day >= :since AND o.fetched AND o.node_id = ANY(:eligible)
                      AND o.file_type = ANY(:exe)) AS exe_types
                FROM targets t
                WHERE t.kind = 'url' AND t.state IN ('confirmed', 'reported')
                  AND t.value IS NOT NULL
                  AND (SELECT count(DISTINCT o.node_id) FROM observations o
                        WHERE o.kind = 'url' AND o.value = coalesce(t.value_b, t.value)
                          AND o.day >= :since AND o.fetched
                          AND o.node_id = ANY(:eligible)) >= :fetched
                  AND NOT EXISTS (SELECT 1 FROM abusech_submissions a
                                  WHERE a.kind = 'urlhaus' AND a.indicator = t.value)
                ORDER BY t.id LIMIT :n
                """
            ),
            {
                "since": since,
                "eligible": eligible,
                "exe": list(EXECUTABLE_TYPES),
                "fetched": MIN_FETCHED_NODES,
                "n": PER_CYCLE,
            },
        )
    ).all()
    out: list[Candidate] = []
    for r in rows:
        families = [f for f in (r.families or []) if f != "generic"]
        exe_types = list(r.exe_types or [])
        if not families and not exe_types:
            continue  # a fetched ordinary page: never submitted
        out.append(Candidate(URLHAUS, r.id, r.value, None, tags_for(families, exe_types)))
    return out


async def threatfox_candidates(session: AsyncSession) -> list[Candidate]:
    rows = (
        await session.execute(
            text(
                "SELECT t.id, t.value, t.families FROM targets t "
                "WHERE t.kind = 'c2_ip' AND t.state IN ('confirmed', 'reported') "
                "AND t.value IS NOT NULL "
                "AND NOT EXISTS (SELECT 1 FROM abusech_submissions a "
                "WHERE a.kind = 'threatfox' AND a.indicator = t.value) "
                "ORDER BY t.id LIMIT :n"
            ),
            {"n": PER_CYCLE},
        )
    ).all()
    out: list[Candidate] = []
    for r in rows:
        known = [f for f in sorted(r.families or []) if f in MALPEDIA]
        if not known:
            continue  # ThreatFox requires a Malpedia family
        out.append(Candidate(THREATFOX, r.id, r.value, MALPEDIA[known[0]], tags_for(known, [])))
    return out


def _never_kind(kind: str) -> str:
    return "url" if kind == URLHAUS else "c2_ip"


async def queue_submissions(
    session: AsyncSession, s: Settings, today: date, *, never: Never
) -> QueueResult:
    """Queue what qualifies. Every submission is queued; only URLhaus ones can be auto-approved."""
    result = QueueResult()
    if not s.abusech_active:
        return result
    eligible = list(await consensus.eligible_nodes(session, s, today))
    found = await urlhaus_candidates(session, s, today, eligible)
    found += await threatfox_candidates(session)
    result.candidates = len(found)
    for c in found:
        if never.matches(_never_kind(c.kind), c.indicator):
            result.skip("never_list")
            continue
        refusal = (
            url_refusal(c.indicator, allow_documentation=s.allow_documentation)
            if c.kind == URLHAUS
            else c2_refusal(c.indicator, allow_documentation=s.allow_documentation)
        )
        if refusal is not None:
            result.skip("not_public")
            continue
        try:
            build_body(c.kind, c.indicator, c.malware, c.tags)
        except ValueError:
            result.skip("invalid")
            continue
        inserted = await session.execute(
            text(
                "INSERT INTO abusech_submissions (kind, target_id, indicator, malware, tags, "
                "state, created_day) VALUES (:k, :t, :i, :m, :tags, 'queued', :d) "
                "ON CONFLICT (kind, indicator) DO NOTHING"
            ),
            {
                "k": c.kind,
                "t": c.target_id,
                "i": c.indicator,
                "m": c.malware,
                "tags": c.tags,
                "d": today,
            },
        )
        result.queued += int(getattr(inserted, "rowcount", 0) or 0)
    await session.commit()
    return result


async def auto_approve(session: AsyncSession, s: Settings, today: date) -> int:
    """In ``auto`` mode, queued URLhaus submissions become approved after the report hold, once the
    network has ``HUB_AUTO_MIN_COHORTS`` independent cohorts. ThreatFox ones never are."""
    if s.abusech_mode != "auto" or not s.abusech_active:
        return 0
    eligible = await consensus.eligible_nodes(session, s, today)
    if len({n.cohort for n in eligible.values()}) < s.auto_min_cohorts:
        return 0
    result = await session.execute(
        text(
            "UPDATE abusech_submissions SET state = 'approved', approved_by = 'auto' "
            "WHERE state = 'queued' AND kind = 'urlhaus' AND created_day <= :cutoff"
        ),
        {"cutoff": today - timedelta(days=math.ceil(s.report_hold_hours / 24))},
    )
    await session.commit()
    return int(getattr(result, "rowcount", 0) or 0)


# ---------------------------------------------------------------- sending


@dataclass
class SendResult:
    sent: int = 0
    failed: int = 0
    rejected: int = 0
    deferred: dict[str, int] = field(default_factory=dict)


async def send_due(
    session: AsyncSession,
    s: Settings,
    now: datetime,
    submit: Submitter,
    *,
    never: Never,
) -> SendResult:
    """Send approved submissions, oldest first, up to the daily cap."""
    result = SendResult()
    if not s.abusech_active:
        return result
    midnight = datetime.combine(now.date(), datetime.min.time(), tzinfo=now.tzinfo)
    sent_today = (
        await session.execute(
            text(
                "SELECT count(*) FROM abusech_submissions "
                "WHERE state = 'sent' AND sent_at >= :start AND sent_at < :end"
            ),
            {"start": midnight, "end": midnight + timedelta(days=1)},
        )
    ).scalar_one()
    rows = (
        await session.execute(
            text(
                "SELECT id, kind, indicator, malware, tags, approved_by FROM abusech_submissions "
                "WHERE state = 'approved' ORDER BY id LIMIT :n"
            ),
            {"n": PER_CYCLE},
        )
    ).all()
    for i, r in enumerate(rows):
        if sent_today >= s.abusech_daily_cap:
            result.deferred["daily_cap"] = result.deferred.get("daily_cap", 0) + 1
            continue
        code = await _one(r, s, submit, never)
        if code in TRANSIENT:
            await session.execute(
                text("UPDATE abusech_submissions SET result_code = :c WHERE id = :id"),
                {"c": code, "id": r.id},
            )
            await session.commit()
            result.deferred[code] = len(rows) - i
            break  # the service is down, throttling or refusing the key: next cycle
        state = "sent" if code in SUCCESS else "rejected" if code == NEVER_LISTED else "failed"
        await session.execute(
            text(
                "UPDATE abusech_submissions SET state = :st, result_code = :c, sent_at = :now "
                "WHERE id = :id"
            ),
            {"st": state, "c": code, "now": now, "id": r.id},
        )
        await session.commit()
        if state == "sent":
            sent_today += 1
            result.sent += 1
        elif state == "rejected":
            result.rejected += 1
        else:
            result.failed += 1
            log.warning("abuse.ch submission failed: %s", code)
    return result


async def _one(r: Any, s: Settings, submit: Submitter, never: Never) -> str:
    # A command-and-control submission needs a person, whatever the mode.
    if r.kind == THREATFOX and r.approved_by in (None, "auto"):
        return GUARD_FAILED
    if never.matches(_never_kind(r.kind), r.indicator):
        return NEVER_LISTED
    try:
        body = build_body(r.kind, r.indicator, r.malware, list(r.tags or []))
    except ValueError:
        return GUARD_FAILED
    return await submit(r.kind, body, s.abusech_auth_key)

"""The abuse.ch submission client (design M27 section 7.5).

Built from the published API documentation of URLhaus (``POST https://urlhaus.abuse.ch/api/``,
JSON body with ``anonymous`` and ``submission``) and ThreatFox (``POST
https://threatfox-api.abuse.ch/api/v1/`` with ``query: submit_ioc``), the Auth-Key in the
``Auth-Key`` header. Neither page documents the answer of a submission, so the mapping from an
answer to a constant code is deliberately tolerant (see ``classify_answer``) and covered by
fixtures in the tests; verify it against a real answer before relying on a particular code.

Every request goes through the egress client (VPN gate). The client allows three hosts, never
follows a redirect, reads at most 64 KiB and parses JSON with the depth guard. It returns a
constant code and never an answer text; the key and the body are never logged.
"""

from __future__ import annotations

import json
import re
from typing import Any, Final
from urllib.parse import urlsplit

import httpx

from ingest.egress import EgressClosed, EgressGate, get_gate, make_client
from ingest.jsondepth import exceeds_depth

URLHAUS_SUBMIT_URL: Final = "https://urlhaus.abuse.ch/api/"
THREATFOX_API: Final = "https://threatfox-api.abuse.ch/api/v1/"
ALLOWED_HOSTS: Final = frozenset(
    {"urlhaus.abuse.ch", "urlhaus-api.abuse.ch", "threatfox-api.abuse.ch"}
)
ENDPOINTS: Final = {"urlhaus": URLHAUS_SUBMIT_URL, "threatfox": THREATFOX_API}
MAX_BODY: Final = 64 * 1024
TIMEOUT: Final = httpx.Timeout(20.0, connect=8.0)

# Constant outcome codes.
INSERTED: Final = "inserted"
ALREADY_KNOWN: Final = "already_known"
INVALID: Final = "invalid"
BLACKLISTED: Final = "blacklisted"
AUTH_FAILED: Final = "auth_failed"
RATE_LIMITED: Final = "rate_limited"
HTTP_ERROR: Final = "http_error"
UNKNOWN_OUTCOME: Final = "unknown_outcome"
EGRESS_CLOSED: Final = "egress_closed"
GUARD_FAILED: Final = "guard_failed"
CODES: Final = frozenset(
    {
        INSERTED, ALREADY_KNOWN, INVALID, BLACKLISTED, AUTH_FAILED, RATE_LIMITED, HTTP_ERROR,
        UNKNOWN_OUTCOME, EGRESS_CLOSED, GUARD_FAILED,
    }
)  # fmt: skip

_STATUS_KEYS = ("query_status", "status", "result", "message")


def _strings(payload: Any) -> list[str]:
    """Status-like strings of an answer: the top level and the first item of a result list."""
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
    """The constant code of an HTTP answer. Pure."""
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


class AbusechClient:
    def __init__(
        self, gate: EgressGate | None = None, client: httpx.AsyncClient | None = None
    ) -> None:
        self._gate = gate or get_gate()
        self.client = client or make_client(TIMEOUT, gate=self._gate)
        self.requests = 0  # for tests: how many requests were really attempted

    async def submit(self, platform: str, body: bytes, key: str) -> str:
        """One POST. Returns a code from ``CODES``; raises ``EgressClosed`` only when nothing was
        sent. After the request left, every failure is a code (an unknown outcome is never
        retried by the caller)."""
        url = ENDPOINTS[platform]
        if urlsplit(url).hostname not in ALLOWED_HOSTS:  # defence in depth
            return HTTP_ERROR
        self._gate.require_open()  # EgressClosed before any socket exists
        self.requests += 1
        try:
            async with self.client.stream(
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
        except EgressClosed:
            raise
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ProxyError):
            return HTTP_ERROR  # the request did not get through
        except httpx.HTTPError:
            return UNKNOWN_OUTCOME  # it may have been received
        if 300 <= status < 400:
            return HTTP_ERROR
        payload: Any = None
        raw = b"".join(chunks)
        if raw and not exceeds_depth(raw):
            try:
                payload = json.loads(raw)
            except (ValueError, RecursionError):
                payload = None
        if status == 200 and payload is None:
            return UNKNOWN_OUTCOME
        return classify_answer(status, payload)

    async def aclose(self) -> None:
        await self.client.aclose()

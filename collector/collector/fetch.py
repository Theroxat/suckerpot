"""One download: through the egress client only, redirects followed by hand, every hop validated.

The caller passes in the client (built by ``suckerpot_egress.egress_client``, which checks the gate
before every request). ``EgressClosed`` is never caught here: nothing was sent, so the caller
treats it as "not now". Bodies are counted on the raw bytes as they stream (``aiter_raw``: httpx
never decompresses), so a lying ``Content-Length`` or a gzip bomb cannot grow the file.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

import httpx

from collector.config import CollectorSettings
from collector.identity import user_agent_for
from collector.store import Quarantine, StoredFile, TooLarge
from collector.validate import UrlRefused, normalize_url, resolve_redirect

type Done = Callable[..., FetchResult]

REDIRECT_CODES: Final = frozenset({301, 302, 303, 307, 308})

# Constant outcome codes stored in fetch_attempts.outcome.
OK: Final = "ok"
EMPTY: Final = "empty"
HTTP_4XX: Final = "http_4xx"
HTTP_5XX: Final = "http_5xx"
TIMEOUT: Final = "timeout"
NETWORK: Final = "network"
TOO_LARGE: Final = "too_large"
QUARANTINE_FULL: Final = "quarantine_full"
REFUSED: Final = "refused"
REDIRECT_LIMIT: Final = "redirect_limit"
BAD_REDIRECT: Final = "bad_redirect"
RETRYABLE: Final = frozenset({TIMEOUT, NETWORK, HTTP_5XX})


@dataclass(frozen=True)
class FetchResult:
    outcome: str
    detail: str | None = None  # a constant code (UrlRefused.code), never a server answer
    http_status: int | None = None
    redirects: int = 0
    stored: StoredFile | None = None
    bytes: int | None = None
    duration_ms: int = 0


class Fetcher:
    def __init__(
        self, client: httpx.AsyncClient, store: Quarantine, settings: CollectorSettings
    ) -> None:
        self._client = client
        self._store = store
        self._s = settings

    async def fetch(self, url: str, *, budget: int) -> FetchResult:
        """Download ``url``. ``budget`` is the room left in quarantine, in bytes."""
        started = time.monotonic()
        limit = min(self._s.max_bytes, budget)
        redirects = 0
        status: int | None = None

        def done(
            outcome: str, detail: str | None = None, *, stored: StoredFile | None = None
        ) -> FetchResult:
            ms = int((time.monotonic() - started) * 1000)
            size = stored.size if stored else None
            return FetchResult(outcome, detail, status, redirects, stored, size, ms)

        if limit <= 0:
            return done(QUARANTINE_FULL)
        try:
            async with asyncio.timeout(self._s.timeout_s):
                current = normalize_url(
                    url, deny_nets=self._s.deny_nets, deny_hosts=self._s.deny_hosts
                )
                while True:
                    headers = {
                        "User-Agent": user_agent_for(current.url),
                        "Accept": "*/*",
                        "Accept-Encoding": "identity",
                    }
                    async with self._client.stream("GET", current.url, headers=headers) as resp:
                        status = resp.status_code
                        if status in REDIRECT_CODES:
                            location = resp.headers.get("location")
                            if not location:
                                return done(BAD_REDIRECT)
                            if redirects >= self._s.max_redirects:
                                return done(REDIRECT_LIMIT)
                            redirects += 1
                            current = resolve_redirect(
                                current.url,
                                location,
                                deny_nets=self._s.deny_nets,
                                deny_hosts=self._s.deny_hosts,
                            )
                            continue
                        if 400 <= status < 500:
                            return done(HTTP_4XX)
                        if not 200 <= status < 300:
                            return done(HTTP_5XX)
                        return await self._body(resp, limit, budget, done)
        except UrlRefused as exc:
            return done(REFUSED, exc.code)
        except (TimeoutError, httpx.TimeoutException):
            return done(TIMEOUT)
        except httpx.HTTPError:
            return done(NETWORK)

    async def _body(
        self,
        resp: httpx.Response,
        limit: int,
        budget: int,
        finish: Done,
    ) -> FetchResult:
        full_outcome = QUARANTINE_FULL if budget < self._s.max_bytes else TOO_LARGE
        declared = resp.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > limit:
            return finish(full_outcome)
        with self._store.open_temp(limit) as temp:
            try:
                async for chunk in resp.aiter_raw():
                    temp.write(chunk)
            except TooLarge:
                return finish(full_outcome)
            if temp.size == 0:
                return finish(EMPTY)
            stored = await asyncio.to_thread(self._store.commit, temp)
        return finish(OK, stored=stored)

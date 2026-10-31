"""The egress gate: a periodic self-check that opens or closes every outbound client.

Check order and reason codes follow docs/design/m21.md section 3.4. A reason is always a constant
code, never a server answer.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx

from suckerpot_egress.settings import EgressSettings

log = logging.getLogger(__name__)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

ECHO_TIMEOUT_S = 10.0
CONTROL_TIMEOUT_S = 5.0
ECHO_MAX_BYTES = 64
PROXY_ERRORS_BEFORE_RECHECK = 3
STALE_FACTOR = 2  # a verdict older than this many intervals no longer counts as open

REASONS = (
    "ok",
    "not_checked",
    "stale",
    "no_vpn",
    "tunnel_down",
    "no_public_ip",
    "echo_failed",
    "echo_disagree",
    "ip_mismatch",
    "ip_not_global",
    "ip_not_allowed",
    "check_error",
)


class EgressClosed(Exception):
    """The gate is closed. Retry later; nothing was sent, so no quota may be spent."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class GateStatus:
    open: bool
    reason: str
    egress_ip: str | None
    checked_at: datetime


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _parse_ip(text: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(text.strip())
    except ValueError:
        return None


class EgressGate:
    def __init__(
        self,
        settings: EgressSettings,
        *,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self.settings = settings
        self._clock = clock
        self._injected = client
        self._control: httpx.AsyncClient | None = client
        self._proxied: httpx.AsyncClient | None = client
        self._status = GateStatus(False, "not_checked", None, datetime.fromtimestamp(0, UTC))
        self._proxy_errors = 0
        self._wake = asyncio.Event()

    # ---- state --------------------------------------------------------------------------------
    @property
    def status(self) -> GateStatus:
        return self._status

    def require_open(self) -> None:
        st = self._status
        if not st.open:
            raise EgressClosed(st.reason)
        age = (self._clock() - st.checked_at).total_seconds()
        if age > self.settings.check_interval_s * STALE_FACTOR:
            raise EgressClosed("stale")

    def note_proxy_ok(self) -> None:
        self._proxy_errors = 0

    def note_proxy_error(self) -> None:
        """Three proxy errors in a row ask for a re-check right away."""
        self._proxy_errors += 1
        if self._proxy_errors >= PROXY_ERRORS_BEFORE_RECHECK:
            self._proxy_errors = 0
            self._wake.set()

    def _set(self, ok: bool, reason: str, ip: str | None) -> GateStatus:
        previous = self._status
        self._status = GateStatus(ok, reason, ip, self._clock())
        if (previous.open, previous.reason) != (ok, reason):
            log.info("egress gate %s (%s)", "open" if ok else "closed", reason)
        return self._status

    # ---- clients ------------------------------------------------------------------------------
    def _clients(self) -> tuple[httpx.AsyncClient, httpx.AsyncClient]:
        if self._control is None or self._proxied is None:
            s = self.settings
            # The control server is on an internal network: never through the proxy.
            self._control = httpx.AsyncClient(
                timeout=CONTROL_TIMEOUT_S, trust_env=False, follow_redirects=False
            )
            self._proxied = httpx.AsyncClient(
                timeout=ECHO_TIMEOUT_S,
                trust_env=False,
                follow_redirects=False,
                proxy=httpx.Proxy(s.proxy_url, auth=(s.proxy_user, s.proxy_password)),
            )
        return self._control, self._proxied

    async def aclose(self) -> None:
        if self._injected is not None:
            return
        for c in {id(c): c for c in (self._control, self._proxied) if c is not None}.values():
            await c.aclose()
        self._control = self._proxied = None

    # ---- the check ----------------------------------------------------------------------------
    async def check(self) -> GateStatus:
        try:
            return await self._check()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("egress self-check crashed (%s)", type(exc).__name__)
            return self._set(False, "check_error", None)

    async def _check(self) -> GateStatus:
        control, _ = self._clients()
        base = self.settings.control_url
        # 1. tunnel state
        try:
            resp = await control.get(f"{base}/v1/vpn/status")
        except httpx.HTTPError:
            return self._set(False, "no_vpn", None)
        if resp.status_code != 200 or _json_field(resp, "status") != "running":
            return self._set(False, "tunnel_down", None)
        # 2. gluetun's own view of its exit address
        try:
            resp = await control.get(f"{base}/v1/publicip/ip")
        except httpx.HTTPError:
            return self._set(False, "no_public_ip", None)
        reported = (
            _parse_ip(_json_field(resp, "public_ip") or "") if resp.status_code == 200 else None
        )
        if reported is None:
            return self._set(False, "no_public_ip", None)
        # 3. what the outside world sees through the proxy
        answers = await asyncio.gather(*(self._echo(u) for u in self.settings.echo_urls))
        good = [a for a in answers if a is not None]
        if len(good) < 2:
            return self._set(False, "echo_failed", None)
        seen = good[0]
        if any(a != seen for a in good[1:]):
            return self._set(False, "echo_disagree", None)
        shown = str(seen)
        # 4. same address as gluetun reports
        if seen != reported:
            return self._set(False, "ip_mismatch", shown)
        # 5. a public address
        if not seen.is_global:
            return self._set(False, "ip_not_global", shown)
        # 6. inside the VPN's expected range
        if not any(seen in net for net in self.settings.allowed_cidrs):
            return self._set(False, "ip_not_allowed", shown)
        return self._set(True, "ok", shown)

    async def _echo(self, url: str) -> IPAddress | None:
        _, proxied = self._clients()
        try:
            async with proxied.stream("GET", url, timeout=ECHO_TIMEOUT_S) as resp:
                if resp.status_code != 200:
                    return None
                body = b""
                async for chunk in resp.aiter_bytes():
                    body += chunk
                    if len(body) > ECHO_MAX_BYTES:
                        return None
        except httpx.HTTPError:
            return None
        return _parse_ip(body.decode("ascii", "ignore"))

    async def run(self, on_status: Callable[[GateStatus], Awaitable[None]] | None = None) -> None:
        """Check at start, then every interval, or sooner after repeated proxy errors.

        ``on_status`` is awaited after every check (to publish it); its errors are logged only.
        """
        while True:
            status = await self.check()
            if on_status is not None:
                try:
                    await on_status(status)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    log.warning("could not publish the egress status (%s)", type(exc).__name__)
            self._wake.clear()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), self.settings.check_interval_s)


def _json_field(resp: httpx.Response, key: str) -> str | None:
    try:
        body = resp.json()
    except ValueError:
        return None
    value = body.get(key) if isinstance(body, dict) else None
    return value if isinstance(value, str) else None

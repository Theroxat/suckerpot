"""The only way to build an outbound HTTP client: always through the proxy, gate checked."""

from __future__ import annotations

from collections.abc import Mapping

import httpx

from suckerpot_egress.gate import EgressGate

_PROXY_ERRORS = (httpx.ProxyError, httpx.ConnectError, httpx.ConnectTimeout)


def _inner_transport(
    gate: EgressGate, *, verify: bool, limits: httpx.Limits | None
) -> httpx.AsyncBaseTransport:
    s = gate.settings
    return httpx.AsyncHTTPTransport(
        verify=verify,
        trust_env=False,
        limits=limits or httpx.Limits(),
        proxy=httpx.Proxy(s.proxy_url, auth=(s.proxy_user, s.proxy_password)),
    )


class GateTransport(httpx.AsyncBaseTransport):
    """Checks the gate before every request, redirect hops included."""

    def __init__(self, gate: EgressGate, inner: httpx.AsyncBaseTransport) -> None:
        self._gate = gate
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self._gate.require_open()  # raises EgressClosed: nothing is sent
        try:
            response = await self._inner.handle_async_request(request)
        except _PROXY_ERRORS:
            self._gate.note_proxy_error()
            raise
        self._gate.note_proxy_ok()
        return response

    async def aclose(self) -> None:
        await self._inner.aclose()


def egress_client(
    gate: EgressGate,
    *,
    timeout: httpx.Timeout,
    follow_redirects: bool = False,
    verify: bool = True,
    limits: httpx.Limits | None = None,
    headers: Mapping[str, str] | None = None,
) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=GateTransport(gate, _inner_transport(gate, verify=verify, limits=limits)),
        timeout=timeout,
        follow_redirects=follow_redirects,
        trust_env=False,
        headers=headers,
    )

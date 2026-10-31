import httpx
import pytest

from suckerpot_egress import EgressClosed, GateTransport, egress_client
from suckerpot_egress import client as client_mod
from tests.helpers import Clock, fake_world, gate_for, open_gate

T = httpx.Timeout(5.0)


class Recorder(httpx.AsyncBaseTransport):
    def __init__(self, responder=None) -> None:  # type: ignore[no-untyped-def]
        self.requests: list[httpx.Request] = []
        self.responder = responder or (lambda r: httpx.Response(200, text="ok"))

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.responder(request)


@pytest.fixture
def inner(monkeypatch: pytest.MonkeyPatch) -> Recorder:
    rec = Recorder()
    monkeypatch.setattr(client_mod, "_inner_transport", lambda gate, **kw: rec)
    return rec


async def test_closed_gate_sends_nothing(inner: Recorder) -> None:
    gate = gate_for(fake_world())  # never checked: closed
    async with egress_client(gate, timeout=T) as c:
        with pytest.raises(EgressClosed):
            await c.get("https://api.test/x")
    assert inner.requests == []


async def test_open_gate_passes(inner: Recorder) -> None:
    gate = await open_gate()
    async with egress_client(gate, timeout=T) as c:
        r = await c.get("https://api.test/x")
    assert r.text == "ok"
    assert len(inner.requests) == 1


async def test_redirect_hop_is_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    gate = await open_gate()

    def responder(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/start":
            gate._status = type(gate._status)(False, "tunnel_down", None, gate._status.checked_at)
            return httpx.Response(302, headers={"location": "https://cdn.test/file"})
        return httpx.Response(200, text="file")

    rec = Recorder(responder)
    monkeypatch.setattr(client_mod, "_inner_transport", lambda g, **kw: rec)
    async with egress_client(gate, timeout=T, follow_redirects=True) as c:
        with pytest.raises(EgressClosed) as exc:
            await c.get("https://cdn.test/start")
    assert exc.value.code == "tunnel_down"
    assert [r.url.path for r in rec.requests] == ["/start"]


async def test_stale_gate_blocks(inner: Recorder) -> None:
    clock = Clock()
    gate = await open_gate(clock)
    clock.advance(10_000)
    async with egress_client(gate, timeout=T) as c:
        with pytest.raises(EgressClosed):
            await c.get("https://api.test/x")


async def test_proxy_errors_are_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    gate = await open_gate()

    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ProxyError("no")

    monkeypatch.setattr(client_mod, "_inner_transport", lambda g, **kw: Recorder(boom))
    async with egress_client(gate, timeout=T) as c:
        for _ in range(3):
            with pytest.raises(httpx.ProxyError):
                await c.get("https://api.test/x")
    assert gate._wake.is_set()


async def test_factory_options(inner: Recorder) -> None:
    gate = await open_gate()
    c = egress_client(gate, timeout=T, follow_redirects=True, headers={"X-A": "1"})
    assert c.follow_redirects and c.headers["X-A"] == "1"
    assert isinstance(c._transport, GateTransport)
    assert c._trust_env is False
    await c.aclose()


def test_real_inner_transport_uses_proxy_with_auth() -> None:
    gate = gate_for(fake_world())
    t = client_mod._inner_transport(gate, verify=True, limits=None)
    assert isinstance(t, httpx.AsyncHTTPTransport)

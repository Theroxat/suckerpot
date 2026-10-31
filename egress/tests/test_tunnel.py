import base64

import pytest

from suckerpot_egress import EgressClosed, TunnelError, TunnelSMTP, TunnelSMTP_SSL, open_tunnel
from suckerpot_egress import smtp as smtp_mod
from tests.helpers import FakeProxy, FakeSmtp, fake_world, gate_for, open_gate


@pytest.fixture
def proxy():  # type: ignore[no-untyped-def]
    p = FakeProxy()
    yield p
    p.close()


def url(p: FakeProxy) -> str:
    return f"http://127.0.0.1:{p.port}"


async def test_connect_sends_auth_and_target(proxy: FakeProxy) -> None:
    gate = await open_gate(proxy_url=url(proxy), proxy_password="p" * 24)
    proxy.upstream = ("127.0.0.1", 9)  # unused: answer 200 then upstream refuses
    proxy.answer = 403
    with pytest.raises(TunnelError) as exc:
        await open_tunnel(gate, "mail.example.test", 587, timeout=3)
    assert exc.value.code == "refused"
    head = proxy.requests[0]
    assert head.startswith("CONNECT mail.example.test:587 HTTP/1.1")
    token = base64.b64encode(("egress:" + "p" * 24).encode()).decode()
    assert f"Proxy-Authorization: Basic {token}" in head


async def test_closed_gate_never_connects(proxy: FakeProxy) -> None:
    gate = gate_for(fake_world(), proxy_url=url(proxy))
    with pytest.raises(EgressClosed):
        await open_tunnel(gate, "mail.example.test", 587, timeout=3)
    assert proxy.requests == []


@pytest.mark.parametrize(
    ("host", "port", "code"),
    [
        ("10.0.0.5", 25, "blocked_host"),  # gitleaks:allow (private range must be refused)
        ("127.0.0.1", 25, "blocked_host"),
        ("192.0.2.10", 25, "blocked_host"),
        ("::1", 25, "blocked_host"),
        ("evil.test\r\nX: y", 25, "bad_host"),
        ("a b", 25, "bad_host"),
        ("mail.test", 0, "bad_port"),
        ("mail.test", 70000, "bad_port"),
    ],
)
async def test_bad_targets_rejected(proxy: FakeProxy, host: str, port: int, code: str) -> None:
    gate = await open_gate(proxy_url=url(proxy))
    with pytest.raises(TunnelError) as exc:
        await open_tunnel(gate, host, port, timeout=3)
    assert exc.value.code == code
    assert proxy.requests == []


async def test_public_literal_is_allowed(proxy: FakeProxy) -> None:
    gate = await open_gate(proxy_url=url(proxy))
    proxy.answer = 502
    with pytest.raises(TunnelError):
        await open_tunnel(gate, "8.8.8.8", 25, timeout=3)
    assert proxy.requests[0].startswith("CONNECT 8.8.8.8:25")


async def test_unreachable_proxy_counts_errors() -> None:
    gate = await open_gate(proxy_url="http://127.0.0.1:1")
    for _ in range(3):
        with pytest.raises(TunnelError) as exc:
            await open_tunnel(gate, "mail.test", 25, timeout=1)
        assert exc.value.code == "proxy_unreachable"
    assert gate._wake.is_set()


async def test_smtp_over_tunnel() -> None:
    server = FakeSmtp()
    proxy = FakeProxy(upstream=("127.0.0.1", server.port))
    try:
        gate = await open_gate(proxy_url=url(proxy))

        def talk() -> tuple[int, bytes]:
            with TunnelSMTP(gate, "smtp.test", 25, timeout=5, local_hostname="localhost") as s:
                s.ehlo()
                return s.noop()

        import asyncio

        code, _ = await asyncio.to_thread(talk)
    finally:
        proxy.close()
        server.close()
    assert code == 250
    assert proxy.requests[0].startswith("CONNECT smtp.test:25 ")
    assert "ehlo localhost" in [x.lower() for x in server.lines]


async def test_smtp_ssl_wraps_with_the_real_host_name() -> None:
    seen: dict[str, object] = {}

    class Ctx:
        def wrap_socket(self, sock, server_hostname):  # type: ignore[no-untyped-def]
            seen["host"] = server_hostname
            raise OSError("stop here")

    server = FakeSmtp()
    proxy = FakeProxy(upstream=("127.0.0.1", server.port))
    try:
        gate = await open_gate(proxy_url=url(proxy))
        import asyncio

        def talk() -> None:
            TunnelSMTP_SSL(gate, "smtp.test", 465, timeout=5, context=Ctx())

        with pytest.raises(OSError, match="stop here"):
            await asyncio.to_thread(talk)
    finally:
        proxy.close()
        server.close()
    assert seen["host"] == "smtp.test"
    assert smtp_mod.TunnelSMTP_SSL is TunnelSMTP_SSL

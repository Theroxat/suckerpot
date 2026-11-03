"""SMTP through the egress proxy (tunnel mode): CONNECT with Basic auth, never a direct socket."""

from __future__ import annotations

import base64
import socket
import threading
from collections.abc import Callable, Iterator
from datetime import UTC, datetime

import pytest

from hub.config import Settings
from hub.reports import send, tunnel

PW = "proxy-p@ss/w0rd"
PROXY_PASSWORD_ENCODED = "proxy-p%40ss%2Fw0rd"


class FakeProxy:
    """A one-shot TCP server: records the request head, answers with ``reply``, then closes."""

    def __init__(self, reply: bytes) -> None:
        self.reply = reply
        self.heads: list[bytes] = []
        self._srv = socket.socket()
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(5)
        self.port: int = self._srv.getsockname()[1]
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def _run(self) -> None:
        while True:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            with conn:
                head = b""
                while not head.endswith(b"\r\n\r\n"):
                    chunk = conn.recv(1)
                    if not chunk:
                        break
                    head += chunk
                self.heads.append(head)
                conn.sendall(self.reply)

    def url(self) -> str:
        return f"http://relay:{PROXY_PASSWORD_ENCODED}@127.0.0.1:{self.port}"

    def close(self) -> None:
        self._srv.close()


@pytest.fixture
def proxy_factory() -> Iterator[Callable[[bytes], FakeProxy]]:
    made: list[FakeProxy] = []

    def make(reply: bytes) -> FakeProxy:
        p = FakeProxy(reply)
        made.append(p)
        return p

    yield make
    for p in made:
        p.close()


@pytest.fixture(autouse=True)
def _clean_proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for v in tunnel.PROXY_VARS:
        monkeypatch.delenv(v, raising=False)
        monkeypatch.delenv(v.lower(), raising=False)


def settings(port: int = 587) -> Settings:
    return Settings(
        smtp_host="smtp.example.org",
        smtp_port=port,
        smtp_user="mailer",
        smtp_password="smtp-secret",
        smtp_from="r@example.org",
    )


def mailer(s: Settings) -> send.Mailer:
    return send.smtp_mailer(s, lambda: datetime(2026, 11, 1, tzinfo=UTC))


def test_proxy_url_from_env_reads_every_variable_in_both_cases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tunnel.proxy_url_from_env() is None
    for name in ("HTTPS_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, "http://p:1")
        assert tunnel.proxy_url_from_env() == "http://p:1"
        monkeypatch.delenv(name)


async def test_connect_line_and_decoded_basic_auth_are_sent(
    monkeypatch: pytest.MonkeyPatch,
    proxy_factory: Callable[[bytes], FakeProxy],
    caplog: pytest.LogCaptureFixture,
) -> None:
    proxy = proxy_factory(b"HTTP/1.1 200 Connection established\r\n\r\n")
    monkeypatch.setenv("HTTPS_PROXY", proxy.url())
    with caplog.at_level("DEBUG"), pytest.raises(send.SendDeferred) as err:
        await mailer(settings())("abuse@example.net", "s", "b", None)
    # The proxy accepted and then dropped the link before any mail: outage, not a verdict.
    assert err.value.args == ("smtp_link_down",)
    head = proxy.heads[0].decode()
    assert head.startswith("CONNECT smtp.example.org:587 HTTP/1.1\r\n")
    assert "Host: smtp.example.org:587\r\n" in head
    token = base64.b64encode(f"relay:{PW}".encode()).decode()
    assert f"Proxy-Authorization: Basic {token}\r\n" in head
    for secret in (PW, PROXY_PASSWORD_ENCODED, "smtp-secret", token):
        assert secret not in caplog.text and secret not in repr(err.value)


async def test_proxy_refusal_is_deferred_with_a_constant_code(
    monkeypatch: pytest.MonkeyPatch, proxy_factory: Callable[[bytes], FakeProxy]
) -> None:
    proxy = proxy_factory(b"HTTP/1.1 407 Proxy Authentication Required\r\nX-Detail: leak\r\n\r\n")
    monkeypatch.setenv("http_proxy", proxy.url())
    with pytest.raises(send.SendDeferred) as err:
        await mailer(settings())("abuse@example.net", "s", "b", None)
    assert err.value.args == ("proxy_refused",)


async def test_proxy_outage_is_deferred_and_never_goes_direct(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    dead_port = probe.getsockname()[1]
    probe.close()  # nothing listens here now
    monkeypatch.setenv("ALL_PROXY", f"http://relay:{PROXY_PASSWORD_ENCODED}@127.0.0.1:{dead_port}")
    dialled: list[object] = []
    real = socket.create_connection

    def spy(address: tuple[str, int], *a: object, **k: object) -> socket.socket:
        dialled.append(address)
        return real(address, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(socket, "create_connection", spy)
    with caplog.at_level("DEBUG"), pytest.raises(send.SendDeferred) as err:
        await mailer(settings())("abuse@example.net", "s", "b", None)
    assert err.value.args == ("proxy_unreachable",)
    assert dialled == [("127.0.0.1", dead_port)]  # the SMTP host was never dialled
    assert PW not in caplog.text and PROXY_PASSWORD_ENCODED not in caplog.text


async def test_implicit_tls_port_also_uses_the_tunnel(
    monkeypatch: pytest.MonkeyPatch, proxy_factory: Callable[[bytes], FakeProxy]
) -> None:
    proxy = proxy_factory(b"HTTP/1.1 200 OK\r\n\r\n")
    monkeypatch.setenv("HTTPS_PROXY", proxy.url())
    # The "server" closes without a TLS handshake: an outage before any mail, so deferred or a
    # TLS error, but never a direct connection.
    with pytest.raises(send.SendError):
        await mailer(settings(465))("abuse@example.net", "s", "b", None)
    assert proxy.heads[0].startswith(b"CONNECT smtp.example.org:465 HTTP/1.1\r\n")


async def test_no_proxy_variable_keeps_the_direct_path(
    monkeypatch: pytest.MonkeyPatch, proxy_factory: Callable[[bytes], FakeProxy]
) -> None:
    called: list[str] = []
    monkeypatch.setattr(send, "_deliver_direct", lambda s, m: called.append("direct"))
    monkeypatch.setattr(send, "_deliver_proxied", lambda s, m, p: called.append("proxied"))
    await mailer(settings())("abuse@example.net", "s", "b", None)
    assert called == ["direct"]


@pytest.mark.parametrize("proxy", ["socks5://p:1", "http://p", "not a url", "http://[::1"])
def test_bad_proxy_urls_are_refused(proxy: str) -> None:
    with pytest.raises(tunnel.TunnelError) as err:
        tunnel.connect_via_proxy(proxy, "smtp.example.org", 587, timeout=1)
    assert err.value.code == "bad_proxy"


@pytest.mark.parametrize("host", ["100.64.0.1", "127.0.0.1", "169.254.0.1", "[::1]", "a b"])
def test_private_literal_and_bad_hosts_are_refused_before_dialling(host: str) -> None:
    with pytest.raises(tunnel.TunnelError):
        tunnel.connect_via_proxy("http://127.0.0.1:9", host, 587, timeout=1)


async def test_unconfigured_smtp_is_still_a_plain_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://p:1")
    with pytest.raises(send.SendError) as err:
        await mailer(Settings())("abuse@example.net", "s", "b", None)
    assert not isinstance(err.value, send.SendDeferred)

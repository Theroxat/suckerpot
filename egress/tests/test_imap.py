import asyncio
import imaplib
import ssl
from datetime import UTC, datetime

import pytest

from suckerpot_egress import EgressClosed, TunnelIMAP4, TunnelIMAP4_SSL
from suckerpot_egress import imap as imap_mod
from suckerpot_egress.imap import format_since, internaldate_to_utc
from tests.helpers import FakeImap, FakeProxy, fake_world, gate_for, open_gate


def url(p: FakeProxy) -> str:
    return f"http://127.0.0.1:{p.port}"


async def test_imap_over_tunnel() -> None:
    server = FakeImap()
    proxy = FakeProxy(upstream=("127.0.0.1", server.port))
    try:
        gate = await open_gate(proxy_url=url(proxy))

        def talk() -> tuple[str, list[bytes | None]]:
            client = TunnelIMAP4(gate, "imap.example.org", 143, timeout=5)
            try:
                typ, data = client.capability()
                return typ, list(data)
            finally:
                client.logout()

        typ, data = await asyncio.to_thread(talk)
    finally:
        proxy.close()
        server.close()
    assert typ == "OK"
    assert data == [b"IMAP4rev1 MOVE"]
    assert proxy.requests[0].startswith("CONNECT imap.example.org:143 ")


async def test_a_closed_gate_never_opens_a_socket() -> None:
    server = FakeImap()
    proxy = FakeProxy(upstream=("127.0.0.1", server.port))
    try:
        gate = gate_for(fake_world(), proxy_url=url(proxy))  # never checked: closed

        def plain() -> None:
            TunnelIMAP4(gate, "imap.example.org", 143, timeout=5)

        def tls() -> None:
            TunnelIMAP4_SSL(
                gate, "imap.example.org", 993, ssl_context=ssl.create_default_context(), timeout=5
            )

        with pytest.raises(EgressClosed):
            await asyncio.to_thread(plain)
        with pytest.raises(EgressClosed):
            await asyncio.to_thread(tls)
    finally:
        proxy.close()
        server.close()
    assert proxy.requests == []
    assert server.lines == []


async def test_implicit_tls_wraps_with_the_real_host_name() -> None:
    seen: dict[str, object] = {}

    class Ctx(ssl.SSLContext):
        def wrap_socket(self, sock, *args, **kwargs):  # type: ignore[no-untyped-def]
            seen["host"] = kwargs.get("server_hostname")
            raise OSError("stop here")

    server = FakeImap()
    proxy = FakeProxy(upstream=("127.0.0.1", server.port))
    try:
        gate = await open_gate(proxy_url=url(proxy))

        def talk() -> None:
            TunnelIMAP4_SSL(
                gate, "imap.example.org", 993, ssl_context=Ctx(ssl.PROTOCOL_TLS_CLIENT), timeout=5
            )

        with pytest.raises(OSError, match="stop here"):
            await asyncio.to_thread(talk)
    finally:
        proxy.close()
        server.close()
    assert seen["host"] == "imap.example.org"
    assert proxy.requests[0].startswith("CONNECT imap.example.org:993 ")


async def test_the_certificate_is_verified() -> None:
    """A server that does not speak TLS (or has no valid certificate) never gets a session."""
    server = FakeImap()
    proxy = FakeProxy(upstream=("127.0.0.1", server.port))
    try:
        gate = await open_gate(proxy_url=url(proxy))
        context = ssl.create_default_context()
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname

        def talk() -> None:
            TunnelIMAP4_SSL(gate, "imap.example.org", 993, ssl_context=context, timeout=3)

        with pytest.raises(OSError):
            await asyncio.to_thread(talk)
    finally:
        proxy.close()
        server.close()
    assert server.lines == []


async def test_a_long_line_from_the_server_is_refused() -> None:
    assert getattr(imaplib, "_MAXLINE") == imap_mod.MAX_LINE == 65_536  # noqa: B009
    server = FakeImap(long_line=imap_mod.MAX_LINE + 100)
    proxy = FakeProxy(upstream=("127.0.0.1", server.port))
    try:
        gate = await open_gate(proxy_url=url(proxy))

        def talk() -> None:
            TunnelIMAP4(gate, "imap.example.org", 143, timeout=5).noop()

        with pytest.raises(imaplib.IMAP4.error):
            await asyncio.to_thread(talk)
    finally:
        proxy.close()
        server.close()


def test_internaldate_is_converted_to_utc() -> None:
    raw = b'12 (UID 7 INTERNALDATE " 5-Mar-2026 10:30:00 +0200" RFC822.SIZE 99)'
    assert internaldate_to_utc(raw) == datetime(2026, 3, 5, 8, 30, tzinfo=UTC)
    assert internaldate_to_utc(b'1 (INTERNALDATE "31-Dec-2025 23:00:00 -0100")') == datetime(
        2026, 1, 1, 0, 0, tzinfo=UTC
    )
    assert internaldate_to_utc(b"garbage") is None
    assert internaldate_to_utc(b'1 (INTERNALDATE "31-Zzz-2025 23:00:00 -0100")') is None
    assert internaldate_to_utc(b'1 (INTERNALDATE "31-Feb-2025 23:00:00 -0100")') is None


def test_since_uses_english_month_names() -> None:
    assert format_since(datetime(2026, 11, 1, tzinfo=UTC)) == "01-Nov-2026"

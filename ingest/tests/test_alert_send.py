"""Webhook and e-mail delivery through the egress proxy: no redirects, TLS-only mail (mocked)."""

import smtplib
import ssl
from typing import Any, ClassVar

import httpx
import pytest
from suckerpot_egress import EgressGate

from ingest.alerts.config import AlertSettings
from ingest.alerts.messages import sample_message
from ingest.alerts.send import Sender, SendError

from .helpers import fake_gate

TOKEN = "T" * 30
DISCORD = f"https://discord.com/api/webhooks/123456789012345678/{TOKEN}"


def sender(
    handler: Any, settings: AlertSettings | None = None, gate: EgressGate | None = None
) -> tuple[Sender, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        response: httpx.Response = handler(request)
        return response

    client = httpx.AsyncClient(transport=httpx.MockTransport(wrapped), follow_redirects=False)
    return Sender(settings or AlertSettings(), client=client, gate=gate or fake_gate()), seen


async def test_discord_post_goes_to_the_host_name() -> None:
    s, seen = sender(lambda _r: httpx.Response(204))
    await s.send("discord", DISCORD, sample_message())
    (req,) = seen
    assert req.url.host == "discord.com" and req.url.path.endswith(TOKEN)
    assert b'"parse":[]' in req.content.replace(b" ", b"")


async def test_closed_gate_sends_nothing_and_is_retryable() -> None:
    gate = fake_gate(open_=False, reason="tunnel_down")
    s = Sender(AlertSettings(), gate=gate)  # the real, gate-checked client
    with pytest.raises(SendError) as err:
        await s.send("discord", DISCORD, sample_message())
    assert err.value.code == "egress_closed" and err.value.retryable


async def test_closed_gate_blocks_mail_before_the_thread(smtp: "type[FakeSMTP]") -> None:
    s, _ = sender(
        lambda _r: httpx.Response(204),
        settings=MAIL,
        gate=fake_gate(open_=False, reason="no_vpn"),
    )
    with pytest.raises(SendError) as err:
        await s.send("email", "analyst@example.org", sample_message())
    assert err.value.code == "egress_closed" and err.value.retryable
    assert smtp.instances == []


async def test_unofficial_host_is_refused_before_any_request() -> None:
    s, seen = sender(lambda _r: httpx.Response(204))
    with pytest.raises(SendError) as err:
        await s.send("discord", DISCORD.replace("discord.com", "evil.example"), sample_message())
    assert err.value.code == "blocked_target" and seen == []


async def test_redirects_are_not_followed() -> None:
    s, seen = sender(lambda _r: httpx.Response(302, headers={"Location": "https://evil.example/"}))
    with pytest.raises(SendError) as err:
        await s.send("discord", DISCORD, sample_message())
    assert err.value.code == "redirect" and not err.value.retryable
    assert len(seen) == 1


@pytest.mark.parametrize(
    ("status", "code", "retry"),
    [(429, "http_429", True), (503, "http_5xx", True), (404, "http_404", False)],
)
async def test_status_mapping(status: int, code: str, retry: bool) -> None:
    s, _ = sender(lambda _r: httpx.Response(status))
    with pytest.raises(SendError) as err:
        await s.send("discord", DISCORD, sample_message())
    assert (err.value.code, err.value.retryable) == (code, retry)


async def test_errors_never_carry_the_token() -> None:
    def boom(_r: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout(f"timed out for {DISCORD}")

    s, _ = sender(boom)
    with pytest.raises(SendError) as err:
        await s.send("discord", DISCORD, sample_message())
    assert err.value.code == "timeout" and err.value.retryable
    assert TOKEN not in str(err.value) and TOKEN not in repr(err.value)


async def test_teams_card_is_sent() -> None:
    url = (
        "https://prod-1.westeurope.logic.azure.com/workflows/"
        "0123456789abcdef0123456789abcdef/triggers/manual/paths/invoke?sig=abc"
    )
    s, seen = sender(lambda _r: httpx.Response(202))
    await s.send("teams", url, sample_message())
    assert seen[0].url.params["sig"] == "abc"
    assert b"AdaptiveCard" in seen[0].content


# ---- e-mail -----------------------------------------------------------------------------------


class FakeSMTP:
    instances: ClassVar[list["FakeSMTP"]] = []
    fail: ClassVar[Exception | None] = None
    starttls_fails: ClassVar[bool] = False

    def __init__(self, gate: Any, host: str, port: int, **kw: Any) -> None:
        self.gate, self.host, self.port, self.kw = gate, host, port, kw
        self.calls: list[str] = []
        self.sent: tuple[Any, list[str]] | None = None
        FakeSMTP.instances.append(self)

    def __enter__(self) -> "FakeSMTP":
        return self

    def __exit__(self, *_a: object) -> None:
        return None

    def ehlo(self) -> None:
        self.calls.append("ehlo")

    def starttls(self, context: ssl.SSLContext) -> None:
        if FakeSMTP.starttls_fails:
            raise smtplib.SMTPNotSupportedError("no starttls")
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
        self.calls.append("starttls")

    def login(self, user: str, password: str) -> None:
        self.calls.append(f"login:{user}")
        if FakeSMTP.fail:
            raise FakeSMTP.fail

    def send_message(self, mail: Any, to_addrs: list[str]) -> None:
        self.calls.append("send")
        self.sent = (mail, to_addrs)


@pytest.fixture
def smtp(monkeypatch: pytest.MonkeyPatch) -> type[FakeSMTP]:
    FakeSMTP.instances = []
    FakeSMTP.fail = None
    FakeSMTP.starttls_fails = False
    import ingest.alerts.send as send_mod

    monkeypatch.setattr(send_mod, "TunnelSMTP", FakeSMTP)
    monkeypatch.setattr(send_mod, "TunnelSMTP_SSL", FakeSMTP)
    return FakeSMTP


MAIL = AlertSettings.from_env(
    {"SMTP_HOST": "smtp.example.org", "SMTP_FROM": "alerts@example.org", "SMTP_USER": "u"}
)


async def test_email_uses_starttls_with_verification(smtp: type[FakeSMTP]) -> None:
    s, _ = sender(lambda _r: httpx.Response(204), settings=MAIL)
    await s.send("email", "analyst@example.org", sample_message())
    (conn,) = smtp.instances
    assert conn.calls == ["ehlo", "starttls", "ehlo", "login:u", "send"]
    assert conn.sent is not None
    mail, to = conn.sent
    assert to == ["analyst@example.org"] and mail["From"] == "alerts@example.org"
    assert mail.get_body(("plain",)) is not None and mail.get_body(("html",)) is not None


async def test_email_refuses_a_server_without_tls(smtp: type[FakeSMTP]) -> None:
    smtp.starttls_fails = True
    s, _ = sender(lambda _r: httpx.Response(204), settings=MAIL)
    with pytest.raises(SendError) as err:
        await s.send("email", "analyst@example.org", sample_message())
    assert err.value.code == "tls"
    assert all("send" not in c.calls for c in smtp.instances)


async def test_email_auth_failure_is_not_retried_and_has_no_secret(smtp: type[FakeSMTP]) -> None:
    smtp.fail = smtplib.SMTPAuthenticationError(535, b"bad password hunter2")
    s, _ = sender(lambda _r: httpx.Response(204), settings=MAIL)
    s.smtp_password = "hunter2"
    with pytest.raises(SendError) as err:
        await s.send("email", "analyst@example.org", sample_message())
    assert err.value.code == "smtp_auth" and not err.value.retryable
    assert "hunter2" not in str(err.value)


async def test_email_needs_configuration_and_a_clean_address(smtp: type[FakeSMTP]) -> None:
    s, _ = sender(lambda _r: httpx.Response(204))
    with pytest.raises(SendError) as err:
        await s.send("email", "analyst@example.org", sample_message())
    assert err.value.code == "smtp_not_configured"
    s2, _ = sender(lambda _r: httpx.Response(204), settings=MAIL)
    with pytest.raises(SendError) as err2:
        await s2.send("email", "a@example.org\nBcc: b@example.org", sample_message())
    assert err2.value.code == "blocked_target"
    assert smtp.instances == []


async def test_an_unexpected_exception_becomes_a_constant_internal_error() -> None:
    def broken(_r: httpx.Request) -> httpx.Response:
        raise ValueError(f"boom {DISCORD}")

    s, _ = sender(broken)
    with pytest.raises(SendError) as err:
        await s.send("discord", DISCORD, sample_message())
    assert err.value.code == "internal" and TOKEN not in str(err.value)
    assert err.value.__cause__ is None and err.value.__suppress_context__


async def test_the_whole_smtp_exchange_has_a_deadline(
    smtp: type[FakeSMTP], monkeypatch: pytest.MonkeyPatch
) -> None:
    import time

    import ingest.alerts.send as send_mod

    monkeypatch.setattr(send_mod, "SMTP_DEADLINE_S", 0.05)
    s, _ = sender(lambda _r: httpx.Response(204), settings=MAIL)
    monkeypatch.setattr(s, "_smtp_send", lambda *_a: time.sleep(0.5))
    with pytest.raises(SendError) as err:
        await s.send("email", "analyst@example.org", sample_message())
    assert err.value.code == "timeout" and err.value.retryable


def test_the_http_client_keeps_no_connections_alive() -> None:
    s = Sender(AlertSettings(), gate=fake_gate())
    pool = s.client._transport._inner._pool  # type: ignore[attr-defined]
    assert pool._max_keepalive_connections == 0

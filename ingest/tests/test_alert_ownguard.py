# ruff: noqa: F811
"""Alerts never carry the monitored system's own address (M25 security fix).

Webhooks and e-mail go through the identity check on the complete serialized payload. Owner
values are masked first; a residual leak, an unknown self address or an unreadable deny set sends
nothing at all: the fake webhook and the fake SMTP client receive zero requests.
"""

from __future__ import annotations

import base64
from typing import Any

import httpx
import pytest
from suckerpot_reporting import SelfTermRow, SelfTerms, load_self_terms

from ingest.alerts.config import AlertSettings
from ingest.alerts.messages import sample_message
from ingest.alerts.ownguard import ADDRESS_MASK, TERM_MASK, mask_message
from ingest.alerts.send import Sender, SendError

from .helpers import fake_gate
from .test_alert_send import FakeSMTP, smtp  # noqa: F401  (the fake client and its fixture)

SELF = "203.0.113.77"
OWNER = "dashboard.example.net"
DISCORD = "https://discord.com/api/webhooks/123456789012345678/" + "T" * 30
MAIL = AlertSettings.from_env(
    {"SMTP_HOST": "smtp.example.org", "SMTP_FROM": "alerts@example.org", "SMTP_USER": "u"}
)

FORMS = [
    SELF,
    f"http://{SELF}/login",
    "203.000.113.077",
    "3405803853",
    "0xCB00714D",
    "203.0.113[.]77",
    f"echo {base64.b64encode(f'go {SELF}/x'.encode()).decode()} | base64 -d",
    "::ffff:203.0.113.77",
]


def terms(*, address: bool = True) -> SelfTerms:
    rows = [SelfTermRow(kind="address", value=SELF, source="manual")] if address else []
    return load_self_terms(rows, {"API_ALLOWED_HOSTS": OWNER})


def provider(value: SelfTerms | None) -> Any:
    async def get() -> SelfTerms | None:
        return value

    return get


class Hooks:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def client(self) -> httpx.AsyncClient:
        def handle(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            return httpx.Response(204)

        return httpx.AsyncClient(transport=httpx.MockTransport(handle))


def planted(form: str) -> dict[str, Any]:
    msg = sample_message()
    msg["title"] = f"Scan from {form}"
    msg["summary"] = f"Probe against {form} seen"
    msg["facts"] = [["Host", form], ["Target", f"{form}:8080"]]
    return msg


def make(hooks: Hooks, value: SelfTerms | None, settings: AlertSettings | None = None) -> Sender:
    return Sender(settings or MAIL, client=hooks.client(), gate=fake_gate(), terms=provider(value))


@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("kind", ["discord", "teams"])
async def test_a_self_address_in_a_webhook_is_masked(kind: str, form: str) -> None:
    hooks = Hooks()
    url = (
        DISCORD
        if kind == "discord"
        else (
            "https://prod-1.westeurope.logic.azure.com/workflows/"
            "0123456789abcdef0123456789abcdef/triggers/manual/paths/invoke?sig=abc"
        )
    )
    await make(hooks, terms()).send(kind, url, planted(form))
    (request,) = hooks.requests
    body = request.content.decode()
    assert SELF not in body and "3405803853" not in body and "CB00714D" not in body.upper()
    assert "own address" in body


@pytest.mark.parametrize("form", FORMS)
async def test_a_self_address_in_an_email_is_masked(smtp: type[FakeSMTP], form: str) -> None:
    hooks = Hooks()
    await make(hooks, terms()).send("email", "analyst@example.org", planted(form))
    (conn,) = smtp.instances
    assert conn.sent is not None
    text = conn.sent[0].as_string()
    assert SELF not in text and "3405803853" not in text and ADDRESS_MASK in text


def test_owner_names_are_masked_in_the_facts() -> None:
    value = terms()
    out = mask_message(value, {"facts": [["Host", f"GET https://{OWNER}/x"], ["n", 5]]})
    assert OWNER not in str(out) and TERM_MASK in str(out) and out["facts"][1] == ["n", 5]


@pytest.mark.parametrize("kind", ["discord", "teams", "email"])
async def test_without_a_known_self_address_nothing_is_sent(
    smtp: type[FakeSMTP],
    kind: str,
) -> None:
    hooks = Hooks()
    url = "analyst@example.org" if kind == "email" else DISCORD
    with pytest.raises(SendError) as err:
        await make(hooks, terms(address=False)).send(kind, url, planted(SELF))
    assert err.value.code == "guard_failed:no_self_address" and err.value.retryable
    assert hooks.requests == [] and smtp.instances == []


@pytest.mark.parametrize("value", [None, "raises"])
async def test_an_unreadable_deny_set_sends_nothing(
    smtp: type[FakeSMTP], value: str | None
) -> None:
    hooks = Hooks()

    async def broken() -> SelfTerms | None:
        raise RuntimeError("db down")

    sender = Sender(MAIL, client=hooks.client(), gate=fake_gate(), terms=broken if value else None)
    for kind, target in (("discord", DISCORD), ("email", "analyst@example.org")):
        with pytest.raises(SendError) as err:
            await sender.send(kind, target, sample_message())
        assert err.value.code == "guard_failed:self_terms_unavailable"
    assert hooks.requests == [] and smtp.instances == []


async def test_a_residual_leak_in_the_rendered_payload_refuses_the_send(
    smtp: type[FakeSMTP],
) -> None:
    """The dashboard link is added after masking: an address there is caught by the final check."""
    settings = AlertSettings.from_env(
        {
            "SMTP_HOST": "smtp.example.org",
            "SMTP_FROM": "alerts@example.org",
            "ALERTS_DASHBOARD_URL": f"https://{SELF}",
        }
    )
    hooks = Hooks()
    for kind, target in (("discord", DISCORD), ("email", "analyst@example.org")):
        with pytest.raises(SendError) as err:
            await make(hooks, terms(), settings).send(kind, target, sample_message())
        assert err.value.code == "guard_failed:self_address"
    assert hooks.requests == [] and smtp.instances == []


async def test_a_clean_alert_still_goes_out(smtp: type[FakeSMTP]) -> None:
    hooks = Hooks()
    sender = make(hooks, terms())
    await sender.send("discord", DISCORD, sample_message())
    await sender.send("email", "analyst@example.org", sample_message())
    assert len(hooks.requests) == 1 and len(smtp.instances) == 1


async def test_a_sender_without_a_deny_set_never_sends(smtp: type[FakeSMTP]) -> None:
    hooks = Hooks()
    sender = Sender(MAIL, client=hooks.client(), gate=fake_gate())
    with pytest.raises(SendError) as err:
        await sender.send("discord", DISCORD, sample_message())
    assert err.value.code == "guard_failed:self_terms_unavailable"
    assert hooks.requests == [] and smtp.instances == []

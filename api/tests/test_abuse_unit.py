"""Abuse reports (M22): pure parts of the API (no database)."""

import json
from datetime import UTC, datetime

from suckerpot_reporting import (
    Evidence,
    GuardContext,
    ReportSettings,
    SelfTermRow,
    SelfTerms,
    load_self_terms,
)
from suckerpot_reporting.evidence import ReportOptions

from api import abuse, abuse_core

SELF = "203.0.113.77"
FULL = ReportSettings(
    reply_contact="reports@example.org",
    intro="Own intro.",
    outro="Own outro.",
    note="Own note.",
    subject_template="Report {count} {value}",
)
T0 = datetime(2026, 10, 30, 14, 0, tzinfo=UTC)


def evidence(text: str) -> Evidence:
    sub = {
        "type": "ip", "value": "198.51.100.23", "asn": 64500, "network": "EXAMPLE-NET",
        "country": "NL", "first_ts": T0, "last_ts": T0, "sessions": 1, "events": 2,
        "activities": [{
            "ts": T0, "src_ip": "198.51.100.23", "src_port": 4000, "dst_port": 22,
            "protocol": "tcp", "service": "ssh", "action": "command", "text": text,
        }],
    }  # fmt: skip
    return Evidence.model_validate(
        {"kind": "attack_source", "recipient": "abuse@example.net", "subjects": [sub],
         "window_start": T0, "window_end": T0, "demo": True}
    )  # fmt: skip


def terms() -> SelfTerms:
    return load_self_terms([SelfTermRow(kind="address", value=SELF, source="manual")], {})


def test_a_planted_address_blocks_the_render_and_the_codes_carry_no_value() -> None:
    ctx = GuardContext(allow_documentation=True)
    ok = abuse_core.render_checked(
        evidence("uname -a"),
        FULL,
        terms(),
        ctx,
        "text",
    )
    assert ok.guard.ok
    bad = abuse_core.render_checked(
        evidence(f"curl {SELF}"),
        FULL,
        terms(),
        ctx,
        "text",
    )
    assert not bad.guard.ok and "self_address" in bad.guard.codes
    resp = abuse_core.guard_failed_response(bad.guard.codes)
    assert SELF not in bytes(resp.body).decode()
    assert json.loads(bytes(resp.body))["code"] == "identity_guard_failed"


def test_missing_deny_set_fails_closed() -> None:
    r = abuse_core.render_checked(
        evidence("x"), FULL, None, GuardContext(allow_documentation=True), "text"
    )
    assert not r.guard.ok and r.guard.codes == ("self_terms_unavailable",)


def test_term_and_mailbox_validation() -> None:
    assert abuse._valid_term("address", "203.0.113.77") == "203.0.113.77"
    assert abuse._valid_term("address", "nope") is None
    assert abuse._valid_term("cidr", "203.0.113.0/24") == "203.0.113.0/24"
    assert abuse._valid_term("name", "Host.Example.NET.") == "host.example.net"
    assert abuse._valid_term("name", "bad name") is None
    assert abuse._mailbox(" Abuse@Example.NET ") == "abuse@example.net"


def test_times_are_rounded_unless_exact_is_chosen() -> None:
    bundle = abuse_core.SettingsBundle(ReportSettings(), {}, 0)
    assert abuse_core.effective_options(None, bundle).time_precision == "minute"
    exact = abuse_core.SettingsBundle(ReportSettings(), {"round_times": False}, 1)
    assert abuse_core.effective_options(None, exact).time_precision == "second"
    assert abuse_core.effective_options({"time_precision": "minute"}, exact) == ReportOptions()


def test_only_the_reply_contact_is_required() -> None:
    assert abuse_core.missing_for(ReportSettings()) == ("reply_contact",)
    assert abuse_core.missing_for(ReportSettings(), xarf=True) == ("reply_contact",)
    assert abuse_core.missing_for(ReportSettings(reply_contact="reports@example.org")) == ()
    assert abuse_core.missing_for(FULL) == ()

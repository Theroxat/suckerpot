"""Renderer golden tests and structural checks."""

from __future__ import annotations

import email
import email.policy
import json
import os
from typing import Any

import pytest
import yaml

from suckerpot_reporting import (
    RenderUnavailable,
    ReportOptions,
    ReportSettings,
    export_from_evidence,
    missing_settings,
    new_boundary,
    render_csv,
    render_eml,
    render_misp,
    render_stix,
    render_text,
    render_xarf,
    stix_dumps,
)
from tests.conftest import (
    EXPORT_ID,
    GOLDEN,
    SEED,
    SETTINGS,
    make_evidence,
    make_export,
    t,
)


def golden(name: str, actual: str) -> None:
    path = GOLDEN / name
    if os.environ.get("UPDATE_GOLDEN") == "1":
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(actual.encode("ascii"))
    assert actual.encode("ascii") == path.read_bytes(), f"golden mismatch: {name}"


def test_text_golden() -> None:
    golden("report.txt", render_text(make_evidence(), SETTINGS).body)


def test_text_minute_precision_and_options() -> None:
    ev = make_evidence(options=ReportOptions(defang=False, include_usernames=False))
    body = render_text(ev, SETTINGS).body
    assert "2026-10-30T15:39Z Commands" in body
    assert "http://203.0.113.9/bins/x86" in body
    assert "users:" not in body


def test_no_default_prose_everything_required() -> None:
    assert missing_settings(None) == ("intro", "outro", "note", "subject_template")
    assert "xarf_user_agent" in missing_settings(
        SETTINGS.model_copy(update={"xarf_user_agent": None}), xarf=True
    )
    for field in ("intro", "outro", "note", "subject_template"):
        bad = SETTINGS.model_copy(update={field: " "})
        with pytest.raises(RenderUnavailable) as exc:
            render_text(make_evidence(), bad)
        assert exc.value.code == "settings_incomplete"
    with pytest.raises(RenderUnavailable) as exc:
        render_text(make_evidence())
    assert exc.value.code == "settings_incomplete"
    with pytest.raises(RenderUnavailable):
        render_xarf(make_evidence(), SETTINGS.model_copy(update={"xarf_user_agent": None}))
    # signature is optional
    assert render_text(make_evidence(), SETTINGS.model_copy(update={"signature": None})).body


def test_demo_marking() -> None:
    msg = render_text(make_evidence(demo=True), SETTINGS)
    assert msg.subject.startswith("DEMO, DO NOT SEND: ")
    assert msg.body.startswith("DEMO DATA: DO NOT SEND")


def test_redaction_counts_line_is_opt_in() -> None:
    assert "lines removed" not in render_text(make_evidence(), SETTINGS).body
    assert "line removed" not in render_text(make_evidence(), SETTINGS).body
    on = make_evidence(options=ReportOptions(time_precision="second", show_redaction_counts=True))
    assert "(1 line removed, 2 addresses masked)" in render_text(on, SETTINGS).body


def test_subject_template_placeholders() -> None:
    cfg = SETTINGS.model_copy(
        update={"subject_template": "{count} from {value} {asn} {network} {date}"}
    )
    assert (
        render_text(make_evidence(), cfg).subject
        == "1 from 198.51.100.23 AS64500 EXAMPLE-NET 2026-10-30"
    )


def test_subject_line_is_single_bounded_line() -> None:
    msg = render_text(make_evidence(), SETTINGS)
    assert "\n" not in msg.subject and len(msg.subject) <= 150


def test_csv_golden_and_formula_guard() -> None:
    golden("evidence.csv", render_csv(make_evidence()).content)
    ev = make_evidence()
    evil = ev.subjects[0].model_copy(update={"network": "=cmd|' /C calc'!A0"})
    csv_text = render_csv(ev.model_copy(update={"subjects": (evil,)})).content
    assert ",'=cmd" in csv_text


def test_xarf_golden_and_round_trip() -> None:
    msg = render_xarf(make_evidence(), SETTINGS)
    assert msg.xarf and [a.name for a in msg.attachments] == ["report.txt", "evidence.txt"]
    golden("report.xarf.yaml", msg.attachments[0].content)
    data = yaml.safe_load(msg.attachments[0].content)
    required = {
        "Reported-From",
        "Category",
        "Report-Type",
        "Service",
        "Port",
        "Version",
        "User-Agent",
        "Date",
        "Source-Type",
        "Source",
        "Attachment",
        "Schema-URL",
        "Occurrences",
    }
    assert required <= data.keys()
    assert not [k for k in data if k.startswith("Destination")]
    assert data["Source"] == "198.51.100.23" and data["Source-Type"] == "ipv4"
    assert data["Port"] == 22 and data["Occurrences"] == 415
    assert data["Date"].endswith("+0000")
    assert data["User-Agent"] == "reporter/1.0"
    assert data["Schema-URL"].startswith("http") and data["Version"] == 0.2


def test_xarf_requires_reply_contact() -> None:
    with pytest.raises(RenderUnavailable):
        render_xarf(make_evidence(), ReportSettings(intro="x"))
    with pytest.raises(RenderUnavailable):
        render_xarf(make_evidence(), SETTINGS.model_copy(update={"reply_contact": None}))


def test_xarf_multi_subject_is_a_summary_with_csv() -> None:
    ev = make_evidence()
    two = ev.model_copy(
        update={
            "subjects": (
                ev.subjects[0],
                ev.subjects[0].model_copy(update={"value": "198.51.100.24"}),
            )
        }
    )
    msg = render_xarf(two, SETTINGS)
    assert not msg.xarf and [a.name for a in msg.attachments] == ["evidence.csv"]
    one = render_xarf(two, SETTINGS, subject="198.51.100.24")
    assert one.xarf and yaml.safe_load(one.attachments[0].content)["Source"] == "198.51.100.24"
    with pytest.raises(RenderUnavailable):
        render_xarf(two, SETTINGS, subject="203.0.113.250")
    assert msg.subject.startswith("Attack from 198.51.100.23")


def test_eml_golden_and_headers() -> None:
    raw = render_eml(
        render_xarf(make_evidence(), SETTINGS), boundary="===============1234567890123456789=="
    )
    golden("report.eml", raw.decode("ascii"))
    parsed = email.message_from_bytes(raw, policy=email.policy.default)
    assert parsed["To"] == "abuse@example.net" and parsed["X-ARF"] == "YES"
    for forbidden in ("From", "Date", "Message-ID", "User-Agent", "X-Mailer", "Reply-To"):
        assert parsed[forbidden] is None
    parts = list(parsed.iter_attachments())
    assert [p.get_filename() for p in parts] == ["report.txt", "evidence.txt"]
    plain = email.message_from_bytes(render_eml(render_text(make_evidence(), SETTINGS)))
    assert plain["X-ARF"] is None and not plain.is_multipart()
    assert b"\r\n" in raw and raw.isascii()


def test_eml_boundary_is_random_and_standard() -> None:
    import re

    msg = render_xarf(make_evidence(), SETTINGS)
    a, b = new_boundary(), new_boundary()
    assert a != b and re.fullmatch(r"={15}\d{19}==", a)
    assert render_eml(msg) != render_eml(msg)
    assert b"=_" not in render_eml(msg)


def test_eml_rejects_header_injection() -> None:
    msg = render_text(make_evidence(), SETTINGS)
    bad = type(msg)(to="a@example.net\r\nBcc: x@example.net", subject=msg.subject, body=msg.body)
    with pytest.raises(RenderUnavailable):
        render_eml(bad)
    sub = type(msg)(to=msg.to, subject="a\r\nBcc: x@example.net", body="b")
    assert b"\r\nBcc:" not in render_eml(sub)


# --- STIX / MISP -------------------------------------------------------------------------


def _walk(node: Any) -> Any:
    if isinstance(node, dict):
        for k, v in node.items():
            yield k
            yield from _walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk(v)


def test_stix_golden_and_valid() -> None:
    bundle = render_stix(make_export())
    golden("indicators.stix.json", stix_dumps(bundle))
    # stix2-validator ships without its 2.1 schemas on PyPI, so the OASIS library does the
    # structural check: it rejects missing properties, bad ids and custom (x_) properties.
    import stix2

    parsed = stix2.parse(bundle, allow_custom=False, version="2.1")
    assert parsed["type"] == "bundle" and len(parsed["objects"]) == len(bundle["objects"])
    types = {o["type"] for o in bundle["objects"]}
    assert "identity" not in types
    assert {
        "indicator",
        "malware",
        "relationship",
        "attack-pattern",
        "marking-definition",
        "campaign",
        "ipv4-addr",
        "url",
        "domain-name",
        "file",
    } <= types
    keys = set(_walk(bundle))
    assert "created_by_ref" not in keys and not [k for k in keys if str(k).startswith("x_")]
    text = stix_dumps(bundle)
    assert "monitored system" not in text and "Observed" not in text
    assert "campaign-17" not in text  # internal cluster key never exported
    assert any(o.get("name", "").startswith("Activity cluster ") for o in bundle["objects"])


def test_stix_ids_stable_per_seed_and_unlinkable() -> None:
    a = render_stix(make_export())
    b = render_stix(make_export())
    assert a == b
    other = make_export().model_copy(update={"id_seed": EXPORT_ID})
    ids_a = {o["id"] for o in a["objects"] if o["type"] != "marking-definition"}
    ids_b = {o["id"] for o in render_stix(other)["objects"] if o["type"] != "marking-definition"}
    assert ids_a.isdisjoint(ids_b)
    assert str(SEED) not in stix_dumps(a)


@pytest.mark.parametrize("tlp", ["clear", "green", "amber", "red"])
def test_stix_tlp_markings(tlp: str) -> None:
    bundle = render_stix(make_export(tlp=tlp))
    mark = bundle["objects"][0]
    assert mark["type"] == "marking-definition" and mark["definition_type"] == "tlp"
    assert all(
        mark["id"] in o["object_marking_refs"]
        for o in bundle["objects"][1:]
        if "object_marking_refs" in o
    )


def test_misp_needs_owner_description_and_stix_has_no_default() -> None:
    bare = make_export().model_copy(update={"description": ""})
    with pytest.raises(RenderUnavailable):
        render_misp(bare)
    assert all("description" not in o for o in render_stix(bare)["objects"])


def test_misp_golden_and_structure() -> None:
    event = render_misp(make_export())
    golden("indicators.misp.json", json.dumps(event, indent=2) + "\n")
    ev = event["Event"]
    assert set(ev) == {
        "uuid",
        "info",
        "date",
        "threat_level_id",
        "analysis",
        "distribution",
        "published",
        "timestamp",
        "Tag",
        "Attribute",
    }
    assert ev["published"] is False and ev["distribution"] == "0" and ev["analysis"] == "2"
    assert {"name": "tlp:green"} in ev["Tag"]
    for forbidden in ("Org", "Orgc", "event_creator_email", "sharing_group", "SharingGroup"):
        assert forbidden not in ev
    types = {a["type"] for a in ev["Attribute"]}
    assert {"ip-src", "url", "domain", "sha256", "sha1", "md5"} <= types
    for attr in ev["Attribute"]:
        assert {
            "uuid",
            "type",
            "category",
            "value",
            "to_ids",
            "first_seen",
            "last_seen",
        } <= attr.keys()
        assert attr["to_ids"] is True
    assert len({a["uuid"] for a in ev["Attribute"]}) == len(ev["Attribute"])
    assert "campaign-17" not in json.dumps(event)


def test_export_from_evidence() -> None:
    data = export_from_evidence(
        make_evidence(), export_id=EXPORT_ID, id_seed=SEED, created=t(18, 0, day=31)
    )
    assert data.items[0].role == "attack_source" and data.items[0].value == "198.51.100.23"
    bundle = render_stix(data)
    assert any(o["type"] == "indicator" for o in bundle["objects"])

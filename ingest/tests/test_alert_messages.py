"""Alert text safety and formatting (no database, no network)."""

import json

import pytest

from ingest.alerts.config import AlertSettings
from ingest.alerts.messages import (
    Candidate,
    build_digest,
    build_message,
    render_discord,
    render_email,
    render_teams,
)
from ingest.alerts.text import clean, clean_text, defang, mask_ip, show_ip

EVIL = "<script>alert(1)</script> @everyone [click](http://evil.example) ‮\x07"


def test_clean_removes_controls_and_bidi_and_truncates() -> None:
    out = clean("a\x00b‮c\r\nd\te" + "x" * 300, 50)
    assert out.startswith("ab")
    assert "‮" not in out and "\x00" not in out and "\n" not in out
    assert len(out) <= 50


@pytest.mark.parametrize(
    ("raw", "fake"),
    [
        ("http://evil.example/a.sh", "hxxp[://]evil[.]example/a[.]sh"),
        ("HTTPS://198.51.100.9:8080/x", "hxxps[://]198[.]51[.]100[.]9[:]8080/x"),
        ("evil.example", "evil[.]example"),
    ],
)
def test_defang(raw: str, fake: str) -> None:
    assert defang(raw) == fake


def test_ip_masking() -> None:
    assert mask_ip("203.0.113.77") == "203.0.x.x"
    assert mask_ip("2001:db8:1234::1") == "2001:0db8::x"
    assert mask_ip("not an ip") == "x.x.x.x"
    assert show_ip("203.0.113.77", True) == "203.0.x.x"
    assert show_ip("203.0.113.77", False) == "203[.]0[.]113[.]77"


def drop(**extra: object) -> Candidate:
    data = {
        "session_id": "s-1",
        "sensor": "ssh",
        "src_ip": "203.0.113.77",
        "country": "NL",
        "org": EVIL,
        "tags": ["malware-drop", EVIL],
    }
    return Candidate("malware_drop", "session:s-1", "severe", {**data, **extra})


def test_the_message_masks_the_address_by_default_choice() -> None:
    masked = build_message(drop(), mask_ips=True)
    plain = build_message(drop(), mask_ips=False)
    assert "203.0.113.77" not in json.dumps(masked)
    assert "203.0.113.77" not in json.dumps(plain)  # defanged even when shown
    assert ["Source", "203.0.x.x"] in masked["facts"]
    assert ["Source", "203[.]0[.]113[.]77"] in plain["facts"]
    assert masked["summary"].endswith("sensor.")
    assert masked["action"]


def test_hostile_text_cannot_become_markup_or_a_mention() -> None:
    msg = build_message(drop(), mask_ips=True)
    discord = render_discord(msg, "https://dash.example.org")
    assert discord["allowed_mentions"] == {"parse": []}
    flat = json.dumps(discord)
    assert "<script>" not in flat.replace("\\<script\\>", "")
    assert "[click](" not in flat  # brackets are escaped
    teams = json.dumps(render_teams(msg, "https://dash.example.org"))
    assert "[click](" not in teams
    subject, text, body = render_email(msg, "https://dash.example.org")
    assert "<script>" not in body and "&lt;script&gt;" in body
    assert "\n" not in subject and "\r" not in subject
    assert text.splitlines()[0] == msg["title"]


def test_links_only_with_a_dashboard_address() -> None:
    msg = build_message(drop(), mask_ips=True)
    assert "url" not in render_discord(msg)["embeds"][0]
    assert render_discord(msg, "https://dash.example.org")["embeds"][0]["url"].startswith(
        "https://dash.example.org/attacks/"
    )
    assert "actions" not in render_teams(msg)["attachments"][0]["content"]


def test_new_download_host_is_defanged() -> None:
    cand = Candidate(
        "new_download_host",
        "host:x",
        "warning",
        {"host": "http://evil.example/x", "sightings": 3, "sensors": ["ssh"], "family": "mirai"},
    )
    msg = build_message(cand, mask_ips=False)
    assert "evil.example" not in json.dumps(msg)
    assert "hxxp[://]evil[.]example/x" in json.dumps(msg)


def test_digest_lists_titles_and_takes_the_worst_severity() -> None:
    msgs = [build_message(drop(session_id=f"s{i}"), mask_ips=True) for i in range(14)]
    msgs[3]["severity"] = "info"
    digest = build_digest(msgs, "were waiting")
    assert digest["title"] == "14 alerts were waiting"
    assert digest["severity"] == "severe" and digest["digest"] is True
    assert len(digest["facts"]) == 10
    assert len(json.dumps(digest)) < 16_384


def test_unknown_rule_is_refused() -> None:
    with pytest.raises(ValueError, match="unknown"):
        build_message(Candidate("nope", "k", "info"), mask_ips=True)


def test_smtp_settings_are_validated() -> None:
    s = AlertSettings.from_env(
        {"SMTP_HOST": "smtp.example.org", "SMTP_FROM": "a@example.org", "SMTP_SECURITY": "ssl"}
    )
    assert s.smtp_configured and s.smtp_port == 465
    assert not AlertSettings.from_env({}).smtp_configured
    for env in (
        {"SMTP_SECURITY": "none"},
        {"SMTP_HOST": "bad host"},
        {"SMTP_FROM": "A <a@example.org>"},
        {"SMTP_PORT": "99999"},
        {"ALERTS_DASHBOARD_URL": "http://dash.example.org"},
    ):
        with pytest.raises(ValueError, match="must"):
            AlertSettings.from_env(env)


def test_clean_text_defangs_urls_and_www_in_free_text() -> None:
    raw = "see http://evil.example/x, HTTPS://a.test and www.bad.test or ftp://h.test"
    out = clean_text(raw)
    assert "http://" not in out.lower() and "https://" not in out.lower() and "ftp://" not in out
    assert "www." not in out
    assert "hxxp[://]evil.example/x" in out and "hxxps[://]a.test" in out
    assert clean_text(out) == out  # applying it twice changes nothing


def test_every_attacker_field_in_a_message_is_defanged() -> None:
    evil = "http://evil.example/a www.evil.test"
    campaign = Candidate(
        "new_campaign",
        "campaign:1",
        "severe",
        {
            "id": 1,
            "name": evil,
            "sources": 2,
            "sessions": 3,
            "sensors": [evil],
            "countries": [evil],
            "techniques": [evil],
        },
    )
    drop_data = {"sensor": evil, "org": evil, "country": evil, "tags": [evil]}
    drop = Candidate("malware_drop", "k", "severe", {**drop_data, "src_ip": "8.8.4.4"})
    cve = Candidate(
        "watched_cve_seen", "k", "warning", {"cve_id": "CVE-2026-1", "sessions": 1, "title": evil}
    )
    host = Candidate(
        "new_download_host", "k", "warning", {"host": "x", "family": evil, "sightings": 1}
    )
    for cand in (campaign, drop, cve, host):
        flat = json.dumps(build_message(cand, mask_ips=True)).lower()
        assert "http://" not in flat and "www." not in flat, cand.rule

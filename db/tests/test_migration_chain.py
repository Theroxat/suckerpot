"""The migration files form one linear chain; the table and provider lists agree."""

import re
from pathlib import Path

import pytest

from suckerpot_db import models
from suckerpot_db.retention import (
    ABUSE_PRUNE_PROC,
    ALERT_PRUNE_PROC,
    CAMPAIGN_PRUNE_PROC,
    SCRIPT_PRUNE_PROC,
    RetentionError,
    abuse_report_retention_days,
    campaigns_max_rows,
    scripts_max_rows,
)
from suckerpot_db.roles import (
    _GRANTS_ANALYZER,
    _GRANTS_API,
    _GRANTS_COLLECTOR,
    _GRANTS_INGEST,
)
from suckerpot_db.secretbox import PROVIDERS

VERSIONS = Path(__file__).resolve().parents[1] / "migrations" / "versions"
NEW_TABLES = {
    "attack_techniques",
    "technique_daily",
    "campaigns",
    "campaign_keys",
    "campaign_sessions",
    "blocklist_entries",
    "blocklist_overrides",
    "feed_tokens",
    "inventory_services",
    "scripts",
    "script_sessions",
    "script_explanations",
    "llm_requests",
    "alert_channels",
    "alert_rules",
    "watched_cves",
    "alert_outbox",
    "alert_cursors",
    "weekly_reports",
    "alert_test_requests",
    "indicator_contacts",
    "indicator_contact_checks",
    "fetch_targets",
    "fetch_attempts",
    "samples",
    "sample_analysis",
    "sample_sources",
    "sample_links",
}
M21_TABLES = {
    "fetch_targets",
    "fetch_attempts",
    "samples",
    "sample_analysis",
    "sample_sources",
    "sample_links",
}


def revisions() -> dict[str, tuple[str | None, str]]:
    out: dict[str, tuple[str | None, str]] = {}
    for path in sorted(VERSIONS.glob("*.py")):
        src = path.read_text()
        rev = re.search(r'^revision: str = "(\w+)"', src, re.M)
        down = re.search(r'^down_revision: str \| None = (None|"(\w+)")', src, re.M)
        assert rev and down, path.name
        out[rev.group(1)] = (down.group(2), path.name)
    return out


def test_the_chain_is_linear_up_to_0025() -> None:
    revs = revisions()
    assert len(revs) == len({d for d, _ in revs.values()})  # no two revisions share a parent
    heads = set(revs) - {d for d, _ in revs.values() if d}
    assert heads == {"0025"}
    for n in range(11, 22):
        assert revs[f"{n:04d}"][0] == f"{n - 1:04d}"


def test_every_new_revision_has_a_downgrade() -> None:
    for name in (n for _, n in revisions().values() if int(n[:4]) >= 11):
        assert "def downgrade() -> None:" in (VERSIONS / name).read_text()


def test_models_cover_the_new_tables() -> None:
    assert NEW_TABLES <= set(models.Base.metadata.tables)


def test_the_role_scripts_name_every_new_table() -> None:
    for script in (_GRANTS_INGEST, _GRANTS_API):
        for table in NEW_TABLES:
            assert f"'{table}'" in script, table


def test_feed_tokens_are_invisible_to_ingest() -> None:
    granted = re.findall(r"GRANT [A-Z, ]+ ON ([^']*?) TO", _GRANTS_INGEST.replace("\n", " "))
    assert not any("feed_tokens" in g for g in granted)
    assert not any(
        "alert_cursors" in g
        for g in re.findall(r"GRANT [A-Z, ]+ ON ([^']*?) TO", _GRANTS_API.replace("\n", " "))
    )


def test_the_provider_list_is_widened_everywhere() -> None:
    assert {"anthropic", "smtp"} <= set(PROVIDERS)
    src = (VERSIONS / "0013_scripts.py").read_text()
    new = re.search(r"_PROVIDERS_NEW = \((.*?)\)\n", src, re.S)
    assert new
    assert set(re.findall(r"'(\w+)'", new.group(1))) == set(PROVIDERS)


def test_prune_procedures_are_created_by_their_migrations() -> None:
    for proc, name in (
        (CAMPAIGN_PRUNE_PROC, "0011_campaigns.py"),
        (SCRIPT_PRUNE_PROC, "0013_scripts.py"),
        (ALERT_PRUNE_PROC, "0014_alerts.py"),
        (ABUSE_PRUNE_PROC, "0019_abuse_reports.py"),
    ):
        assert f"PROCEDURE {proc}(" in (VERSIONS / name).read_text()


def test_max_rows_settings() -> None:
    assert campaigns_max_rows({}) == 50_000
    assert scripts_max_rows({"SCRIPTS_MAX_ROWS": " "}) == 100_000
    assert campaigns_max_rows({"CAMPAIGNS_MAX_ROWS": "2000"}) == 2000
    for bad in ("12", "x", "99999999999"):
        with pytest.raises(RetentionError, match="CAMPAIGNS_MAX_ROWS"):
            campaigns_max_rows({"CAMPAIGNS_MAX_ROWS": bad})


def _grants(script: str) -> dict[str, set[str]]:
    """Map each table to the privileges a role script grants on it."""
    joined = re.sub(r"'\s+'", "", script)  # adjacent SQL string literals form one statement
    out: dict[str, set[str]] = {}
    for privs, tables in re.findall(r"'GRANT ([A-Z, ]+) ON ([a-z_, ]+) TO %I'", joined):
        for table in (t.strip() for t in tables.split(",")):
            out.setdefault(table, set()).update(p.strip() for p in privs.split(","))
    return out


def test_the_api_only_reads_the_collector_tables() -> None:
    granted = _grants(_GRANTS_API)
    for table in M21_TABLES:
        assert granted[table] == {"SELECT"}, table


READ_ONLY_FOR_INGEST = ("fetch_targets", "samples", "sample_links", "sample_sources")


def test_ingest_only_reads_the_payload_tables() -> None:
    """M22 drafts name fetched payloads and C2 addresses: SELECT on four tables, nothing else."""
    granted = _grants(_GRANTS_INGEST)
    for table in M21_TABLES:
        if table in READ_ONLY_FOR_INGEST:
            assert granted[table] == {"SELECT"}, table
        else:
            assert table not in granted, table


def test_collector_grants() -> None:
    g = _grants(_GRANTS_COLLECTOR)
    assert g["indicators"] == {"SELECT"}
    for table in ("fetch_targets", "fetch_attempts", "samples", "sample_sources"):
        assert g[table] >= {"SELECT", "INSERT", "UPDATE"}, table
    assert g["fetch_attempts"] >= {"DELETE"}
    assert "DELETE" not in g["samples"] | g["fetch_targets"] | g["sample_sources"]
    assert g["enrichment_status"] >= {"SELECT", "INSERT", "UPDATE"}
    for table in ("sample_analysis", "sample_links", "users", "events", "sessions"):
        assert table not in g, table


def test_analyzer_grants() -> None:
    g = _grants(_GRANTS_ANALYZER)
    assert g["samples"] == {"SELECT", "UPDATE"}
    assert g["sample_analysis"] >= {"SELECT", "INSERT", "UPDATE"}
    assert g["sample_links"] >= {"SELECT", "INSERT", "UPDATE"}
    assert g["fetch_targets"] == {"SELECT", "INSERT"}
    assert g["indicators"] == {"SELECT", "INSERT"}  # UPDATE is column-level
    assert "UPDATE (last_seen, sightings, trusted) ON indicators" in _GRANTS_ANALYZER
    for table in (
        "enrichment_status",
        "enrichment_quota",
        "fetch_attempts",
        "events",
        "sessions",
        "users",
        "provider_secrets",
    ):
        assert table not in g, table
    assert not any("DELETE" in p for p in g.values())


def test_collector_is_confined_to_its_own_shared_rows() -> None:
    assert "name IN ('collector', 'egress_collector')" in _GRANTS_COLLECTOR.replace("''", "'")
    assert "provider = 'collector'" in _GRANTS_COLLECTOR.replace("''", "'")
    assert "CREATE POLICY sp_collector_status" in _GRANTS_COLLECTOR
    assert "CREATE POLICY sp_collector_quota" in _GRANTS_COLLECTOR
    for script in (_GRANTS_INGEST, _GRANTS_API):
        assert "USING (true) WITH CHECK (true)" in script


M22_TABLES = {
    "rdap_bootstrap",
    "abuse_networks",
    "abuse_lookups",
    "abuse_recipients",
    "abuse_reports",
    "abuse_report_subjects",
    "abuse_report_requests",
    "report_settings",
    "report_self_terms",
}


def test_models_cover_the_m22_tables() -> None:
    assert M22_TABLES <= set(models.Base.metadata.tables)
    for script in (_GRANTS_INGEST, _GRANTS_API):
        for table in M22_TABLES:
            assert f"'{table}'" in script, table


def test_abuse_report_retention_setting() -> None:
    assert abuse_report_retention_days({}) == 730
    assert abuse_report_retention_days({"ABUSE_REPORT_RETENTION_DAYS": "90"}) == 90
    for bad in ("1", "x", "99999"):
        with pytest.raises(RetentionError, match="ABUSE_REPORT_RETENTION_DAYS"):
            abuse_report_retention_days({"ABUSE_REPORT_RETENTION_DAYS": bad})


def _update_columns(script: str, table: str) -> set[str]:
    joined = re.sub(r"'\s+'", "", script)
    found = re.findall(rf"'GRANT UPDATE \(([a-z0-9_, ]+)\) ON {table} TO %I'", joined)
    return {c.strip() for cols in found for c in cols.split(",")}


def test_m22_column_grants() -> None:
    api = _update_columns(_GRANTS_API, "abuse_reports")
    ingest = _update_columns(_GRANTS_INGEST, "abuse_reports")
    assert {"status", "notes", "options", "sent_at", "reviewed_by", "closed_at"} <= api
    assert not api & {"evidence", "content_sha256", "guard_ok", "recipient_id", "demo"}
    assert {"evidence", "status", "guard_ok"} <= ingest
    # M25: ingest may stamp a report it sent by SMTP (trigger: pending request required).
    assert not ingest & {"notes", "closed_at", "closed_by"}
    assert {"sent_at", "sent_by", "sent_via"} <= ingest
    assert "sent_via" in api
    for script in (_GRANTS_API, _GRANTS_INGEST):
        assert not re.search(r"GRANT [A-Z, ]*UPDATE[A-Z, ]* ON abuse_reports", script)


def test_m25_grants_keep_the_password_away_from_the_api() -> None:
    api = _grants(_GRANTS_API)
    assert {"INSERT", "UPDATE", "DELETE"} <= api["report_smtp"]
    select = re.search(
        r"GRANT SELECT \(([a-z_, ]+)\)\s*'?\s*'?ON report_smtp", re.sub(r"'\s+'", "", _GRANTS_API)
    )
    assert select and "password_set" in select.group(1)
    assert "password_ciphertext" not in select.group(1) and "password_nonce" not in select.group(1)
    assert _grants(_GRANTS_INGEST)["report_smtp"] == {"SELECT"}
    assert "report_smtp" not in _grants(_GRANTS_COLLECTOR)
    assert _update_columns(_GRANTS_API, "abuse_send_requests") == {"status"}
    assert _update_columns(_GRANTS_INGEST, "abuse_send_requests") == {
        "status",
        "error_code",
        "done_at",
        "started_at",
    }
    assert "DELETE" not in _grants(_GRANTS_API)["abuse_send_requests"]


def test_trusted_exit_grants() -> None:
    """M23: the API manages the ranges; ingest and the collector only read them."""
    assert _grants(_GRANTS_API)["egress_trusted_exits"] == {"SELECT", "INSERT", "DELETE"}
    assert _grants(_GRANTS_INGEST)["egress_trusted_exits"] == {"SELECT"}
    assert _grants(_GRANTS_COLLECTOR)["egress_trusted_exits"] == {"SELECT"}
    assert "egress_trusted_exits" not in _grants(_GRANTS_ANALYZER)


def test_check_request_grants() -> None:
    """M24: the API files "Check now" requests; ingest answers them. Nobody can delete."""
    assert _grants(_GRANTS_API)["egress_check_requests"] == {"SELECT", "INSERT"}
    assert _grants(_GRANTS_INGEST)["egress_check_requests"] == {"SELECT"}
    assert _update_columns(_GRANTS_INGEST, "egress_check_requests") == {"done_at"}
    assert not _update_columns(_GRANTS_API, "egress_check_requests")
    assert "egress_check_requests" not in _grants(_GRANTS_COLLECTOR)
    assert "egress_check_requests" not in _grants(_GRANTS_ANALYZER)


def test_m28_setup_progress_grants() -> None:
    assert _grants(_GRANTS_API)["setup_progress"] == {"SELECT", "INSERT", "UPDATE"}
    assert "setup_progress" not in _grants(_GRANTS_INGEST)
    assert "setup_progress" not in _grants(_GRANTS_COLLECTOR)

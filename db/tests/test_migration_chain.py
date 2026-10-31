"""The migration files form one linear chain; the table and provider lists agree."""

import re
from pathlib import Path

import pytest

from suckerpot_db import models
from suckerpot_db.retention import (
    ALERT_PRUNE_PROC,
    CAMPAIGN_PRUNE_PROC,
    SCRIPT_PRUNE_PROC,
    RetentionError,
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


def test_the_chain_is_linear_up_to_0018() -> None:
    revs = revisions()
    assert len(revs) == len({d for d, _ in revs.values()})  # no two revisions share a parent
    heads = set(revs) - {d for d, _ in revs.values() if d}
    assert heads == {"0018"}
    for n in range(11, 19):
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


def test_ingest_has_no_access_to_the_collector_tables() -> None:
    flat = _GRANTS_INGEST.replace("\n", " ")
    granted = " ".join(g for g in re.findall(r"GRANT [A-Z, ]+ ON ([^']*?) TO", flat))
    assert not any(t in granted for t in M21_TABLES)


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

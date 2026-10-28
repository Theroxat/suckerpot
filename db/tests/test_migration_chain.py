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
from suckerpot_db.roles import _GRANTS_API, _GRANTS_INGEST
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


def test_the_chain_is_linear_up_to_0016() -> None:
    revs = revisions()
    assert len(revs) == len({d for d, _ in revs.values()})  # no two revisions share a parent
    heads = set(revs) - {d for d, _ in revs.values() if d}
    assert heads == {"0016"}
    for n in range(11, 17):
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

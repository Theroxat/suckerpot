"""Alert channels, rules, the outbox and weekly reports (M18).

Revision ID: 0014
Revises: 0013

* ``alert_channels``: where alerts go. ``target_ciphertext`` holds the 12-byte nonce followed by
  the AES-GCM ciphertext of the webhook URL or address (SecretBox, AAD ``alert_channel:<id>``).
* ``alert_rules``: one row per rule kind, seeded disabled. ``enabled_at`` is when it was last
  switched on: a cursor older than that is stale and restarts at "now" (no replay of history).
* ``watched_cves``: CVE ids the owner wants an alert for.
* ``alert_outbox``: what was queued, sent or suppressed; unique per rule, key and channel so a
  restart never sends twice. Pruned after 30 days.
* ``alert_cursors``: ingest's progress per rule.
* ``weekly_reports``: the rendered weekly report, kept for two years.
* ``alert_test_requests``: "send a test message" requests (the API inserts, ingest answers).
* ``suckerpot_alert_prune``: retention (job created by ``suckerpot_db.retention``).

Grants are applied by ``suckerpot_db.roles``.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

RULE_KINDS = (
    "new_campaign",
    "new_download_host",
    "malware_drop",
    "watched_cve_seen",
    "weekly_report",
)

_PRUNE = """
CREATE OR REPLACE PROCEDURE suckerpot_alert_prune(job_id integer, config jsonb)
LANGUAGE plpgsql AS $$
DECLARE
    outbox_days integer := COALESCE((config ->> 'outbox_days')::integer, 30);
    report_days integer := COALESCE((config ->> 'report_days')::integer, 730);
BEGIN
    DELETE FROM alert_outbox WHERE created_at < now() - make_interval(days => outbox_days);
    DELETE FROM alert_test_requests WHERE requested_at < now() - INTERVAL '7 days';
    DELETE FROM weekly_reports WHERE week_start < current_date - report_days;
END
$$
"""


def upgrade() -> None:
    kinds = ", ".join(f"'{k}'" for k in RULE_KINDS)
    op.execute(
        """
        CREATE TABLE alert_channels (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            kind text NOT NULL CHECK (kind IN ('discord', 'teams', 'email')),
            name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
            enabled boolean NOT NULL DEFAULT true,
            target_ciphertext bytea NOT NULL
                CHECK (octet_length(target_ciphertext) BETWEEN 29 AND 2048),
            target_hint text NOT NULL DEFAULT '' CHECK (char_length(target_hint) <= 32),
            mask_ips boolean NOT NULL DEFAULT true,
            created_by text NOT NULL CHECK (char_length(created_by) <= 128),
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        f"""
        CREATE TABLE alert_rules (
            kind text PRIMARY KEY CHECK (kind IN ({kinds})),
            enabled boolean NOT NULL DEFAULT false,
            enabled_at timestamptz,
            channel_ids bigint[] NOT NULL DEFAULT '{{}}' CHECK (cardinality(channel_ids) <= 32),
            min_severity text NOT NULL DEFAULT 'warning'
                CHECK (min_severity IN ('info', 'notice', 'warning', 'severe')),
            settings jsonb NOT NULL DEFAULT '{{}}'::jsonb
                CHECK (octet_length(settings::text) <= 2048)
        )
        """
    )
    op.execute("INSERT INTO alert_rules (kind) VALUES " + ", ".join(f"('{k}')" for k in RULE_KINDS))
    op.execute(
        """
        CREATE TABLE watched_cves (
            cve_id text PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,10}$'),
            added_by text NOT NULL CHECK (char_length(added_by) <= 128),
            added_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        f"""
        CREATE TABLE alert_outbox (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            rule_kind text NOT NULL CHECK (rule_kind IN ({kinds})),
            dedupe_key text NOT NULL CHECK (char_length(dedupe_key) <= 128),
            channel_id bigint NOT NULL REFERENCES alert_channels (id) ON DELETE CASCADE,
            payload jsonb NOT NULL CHECK (octet_length(payload::text) <= 16384),
            state text NOT NULL DEFAULT 'pending'
                CHECK (state IN ('pending', 'sent', 'failed', 'suppressed')),
            attempts smallint NOT NULL DEFAULT 0,
            created_at timestamptz NOT NULL DEFAULT now(),
            sent_at timestamptz,
            error_code text CHECK (error_code IS NULL OR char_length(error_code) <= 64),
            UNIQUE (rule_kind, dedupe_key, channel_id)
        )
        """
    )
    op.execute("CREATE INDEX ix_alert_outbox_state ON alert_outbox (state, created_at)")
    op.execute("CREATE INDEX ix_alert_outbox_created_at ON alert_outbox (created_at DESC, id DESC)")
    op.execute(
        f"""
        CREATE TABLE alert_cursors (
            rule_kind text PRIMARY KEY CHECK (rule_kind IN ({kinds})),
            cursor jsonb NOT NULL DEFAULT '{{}}'::jsonb CHECK (octet_length(cursor::text) <= 4096)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE weekly_reports (
            week_start date PRIMARY KEY,
            html text NOT NULL CHECK (octet_length(html) <= 524288),
            summary jsonb NOT NULL CHECK (octet_length(summary::text) <= 16384),
            created_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE alert_test_requests (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            channel_id bigint NOT NULL REFERENCES alert_channels (id) ON DELETE CASCADE,
            requested_by text NOT NULL CHECK (char_length(requested_by) <= 128),
            requested_at timestamptz NOT NULL DEFAULT now(),
            state text NOT NULL DEFAULT 'queued'
                CHECK (state IN ('queued', 'done', 'refused', 'failed')),
            detail text CHECK (detail IS NULL OR char_length(detail) <= 128)
        )
        """
    )
    op.execute("CREATE INDEX ix_alert_test_requests_state ON alert_test_requests (state)")
    op.execute(_PRUNE)


def downgrade() -> None:
    op.execute(
        "SELECT delete_job(job_id) FROM timescaledb_information.jobs "
        "WHERE proc_name = 'suckerpot_alert_prune'"
    )
    op.execute("DROP PROCEDURE IF EXISTS suckerpot_alert_prune(integer, jsonb)")
    op.execute("DROP TABLE IF EXISTS alert_test_requests")
    op.execute("DROP TABLE IF EXISTS weekly_reports")
    op.execute("DROP TABLE IF EXISTS alert_cursors")
    op.execute("DROP TABLE IF EXISTS alert_outbox")
    op.execute("DROP TABLE IF EXISTS watched_cves")
    op.execute("DROP TABLE IF EXISTS alert_rules")
    op.execute("DROP TABLE IF EXISTS alert_channels")

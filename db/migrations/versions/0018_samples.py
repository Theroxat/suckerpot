"""Fetch targets, collected samples and their static analysis (M21).

Revision ID: 0018
Revises: 0017

The collector (outbound, through the VPN) downloads the URLs recorded as indicators and stores
each file in quarantine; the analyzer (no network) reads the files and writes the findings. These
tables hold only metadata: file content stays in the quarantine volume. Plain tables, not
hypertables: a few hundred rows a day at most. Grants are applied by ``suckerpot_db.roles``.

Chain: session -> indicator_sessions -> indicators (url) -> fetch_targets -> sample_sources ->
samples -> sample_links (next_url -> fetch_targets, c2_* -> indicators).
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE indicators DROP CONSTRAINT indicators_role_check")
    op.execute(
        "ALTER TABLE indicators ADD CONSTRAINT indicators_role_check "
        "CHECK (role IN ('download_host', 'contacted_host', 'hash', 'c2'))"
    )
    # The collector role may touch only its own rows of these two shared tables; the policies
    # are created by suckerpot_db.roles (every migrate run). The table owner is not subject to RLS.
    op.execute("ALTER TABLE enrichment_status ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE enrichment_quota ENABLE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE TABLE fetch_targets (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            url text NOT NULL UNIQUE CHECK (char_length(url) BETWEEN 1 AND 1024),
            scheme text NOT NULL,
            host text NOT NULL CHECK (char_length(host) <= 255),
            indicator_id bigint REFERENCES indicators (id) ON DELETE SET NULL,
            parent_sha256 text,
            depth smallint NOT NULL DEFAULT 0,
            status text NOT NULL DEFAULT 'pending' CHECK (status IN (
                'pending', 'fetched', 'failed', 'gone', 'refused', 'too_large',
                'unsupported', 'quarantine_full')),
            last_error text,
            attempts smallint NOT NULL DEFAULT 0,
            fetches smallint NOT NULL DEFAULT 0,
            first_seen timestamptz NOT NULL,
            last_attempt_at timestamptz,
            next_attempt_at timestamptz,
            last_sha256 text
        )
        """
    )
    op.execute(
        "CREATE INDEX ix_fetch_targets_due ON fetch_targets (next_attempt_at) "
        "WHERE status = 'pending'"
    )
    op.execute(
        """
        CREATE TABLE fetch_attempts (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            target_id bigint NOT NULL REFERENCES fetch_targets (id) ON DELETE CASCADE,
            started_at timestamptz NOT NULL,
            duration_ms integer,
            http_status smallint,
            bytes bigint,
            redirects smallint,
            outcome text NOT NULL,
            sha256 text
        )
        """
    )
    op.execute("CREATE INDEX ix_fetch_attempts_target ON fetch_attempts (target_id, started_at)")
    op.execute(
        """
        CREATE TABLE samples (
            sha256 text PRIMARY KEY CHECK (sha256 ~ '^[0-9a-f]{64}$'),
            sha1 text NOT NULL,
            md5 text NOT NULL,
            tlsh text,
            size bigint NOT NULL,
            kind text,
            arch text,
            bits smallint,
            endian text,
            linking text,
            packer text,
            family text,
            severity text NOT NULL DEFAULT 'notice',
            first_seen timestamptz NOT NULL,
            last_seen timestamptz NOT NULL,
            stored boolean NOT NULL DEFAULT true,
            analysis_status text NOT NULL DEFAULT 'pending'
                CHECK (analysis_status IN ('pending', 'done', 'failed', 'timeout')),
            analysis_version smallint NOT NULL DEFAULT 0
        )
        """
    )
    op.execute("CREATE INDEX ix_samples_last_seen ON samples (last_seen DESC, sha256)")
    op.execute(
        """
        CREATE TABLE sample_analysis (
            sha256 text PRIMARY KEY REFERENCES samples (sha256) ON DELETE CASCADE,
            analyzed_at timestamptz NOT NULL,
            elapsed_ms integer,
            yara jsonb NOT NULL DEFAULT '[]',
            strings text[] NOT NULL DEFAULT '{}',
            deobfuscated text
                CHECK (deobfuscated IS NULL OR octet_length(deobfuscated) <= 262144),
            deob_steps jsonb NOT NULL DEFAULT '[]',
            errors text[] NOT NULL DEFAULT '{}'
        )
        """
    )
    op.execute(
        """
        CREATE TABLE sample_sources (
            sha256 text NOT NULL REFERENCES samples (sha256) ON DELETE CASCADE,
            target_id bigint NOT NULL REFERENCES fetch_targets (id) ON DELETE CASCADE,
            first_fetched timestamptz NOT NULL,
            last_fetched timestamptz NOT NULL,
            PRIMARY KEY (sha256, target_id)
        )
        """
    )
    op.execute("CREATE INDEX ix_sample_sources_target ON sample_sources (target_id)")
    op.execute(
        """
        CREATE TABLE sample_links (
            sha256 text NOT NULL REFERENCES samples (sha256) ON DELETE CASCADE,
            kind text NOT NULL CHECK (kind IN ('next_url', 'c2_ip', 'c2_domain', 'c2_url')),
            value text NOT NULL CHECK (char_length(value) <= 1024),
            port integer,
            source text NOT NULL,
            confidence text NOT NULL,
            target_id bigint REFERENCES fetch_targets (id) ON DELETE SET NULL,
            indicator_id bigint REFERENCES indicators (id) ON DELETE SET NULL,
            PRIMARY KEY (sha256, kind, value)
        )
        """
    )


def downgrade() -> None:
    for table in ("enrichment_status", "enrichment_quota"):
        op.execute(
            "DO $$ DECLARE p record; BEGIN FOR p IN SELECT policyname FROM pg_policies "
            f"WHERE tablename = '{table}' LOOP "
            f"EXECUTE format('DROP POLICY %I ON {table}', p.policyname); END LOOP; END $$"
        )
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    for table in (
        "sample_links",
        "sample_sources",
        "sample_analysis",
        "samples",
        "fetch_attempts",
        "fetch_targets",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table}")
    op.execute("DELETE FROM indicators WHERE role = 'c2'")
    op.execute("ALTER TABLE indicators DROP CONSTRAINT indicators_role_check")
    op.execute(
        "ALTER TABLE indicators ADD CONSTRAINT indicators_role_check "
        "CHECK (role IN ('download_host', 'contacted_host', 'hash'))"
    )

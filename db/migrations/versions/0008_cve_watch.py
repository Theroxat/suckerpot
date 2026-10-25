"""CVE watch: the ``cve`` table, per-source sync state and two more provider keys.

Revision ID: 0008
Revises: 0007

Public vulnerability data (CISA KEV, NVD, GitHub advisories), written by ingest only and read by
the API. Grants are applied by ``suckerpot_db.roles`` after every upgrade. The provider key tables
also accept ``nvd`` and ``github`` (both keys are optional; they only raise rate limits).
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD = "('abuseipdb', 'greynoise', 'maxmind')"
NEW = "('abuseipdb', 'greynoise', 'maxmind', 'nvd', 'github')"


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE cve (
            cve_id text PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,10}$'),
            title text,
            description text,
            vendor text,
            product text,
            published_at timestamptz,
            modified_at timestamptz,
            cvss_score numeric(3, 1) CHECK (cvss_score BETWEEN 0 AND 10),
            cvss_severity text,
            cwes text[] NOT NULL DEFAULT '{}',
            ghsa_ids text[] NOT NULL DEFAULT '{}',
            refs text[] NOT NULL DEFAULT '{}',
            in_kev boolean NOT NULL DEFAULT false,
            kev_added_at date,
            kev_due_date date,
            kev_ransomware boolean,
            kev_action text,
            sources text[] NOT NULL DEFAULT '{}',
            first_seen_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute("CREATE INDEX ix_cve_published_at ON cve (published_at DESC)")
    op.execute("CREATE INDEX ix_cve_kev_added_at ON cve (kev_added_at DESC) WHERE in_kev")
    op.execute("CREATE INDEX ix_cve_cvss_score ON cve (cvss_score DESC)")
    op.execute(
        """
        CREATE TABLE cve_sync_state (
            source text PRIMARY KEY CHECK (source IN ('kev', 'nvd', 'github')),
            last_run_at timestamptz,
            last_success_at timestamptz,
            last_error text,
            items_last_run integer NOT NULL DEFAULT 0
        )
        """
    )
    for table in ("provider_secrets", "provider_test_requests"):
        op.execute(f"ALTER TABLE {table} DROP CONSTRAINT {table}_provider_check")
        op.execute(
            f"ALTER TABLE {table} ADD CONSTRAINT {table}_provider_check CHECK (provider IN {NEW})"
        )


def downgrade() -> None:
    for table in ("provider_secrets", "provider_test_requests"):
        op.execute(f"DELETE FROM {table} WHERE provider IN ('nvd', 'github')")
        op.execute(f"ALTER TABLE {table} DROP CONSTRAINT {table}_provider_check")
        op.execute(
            f"ALTER TABLE {table} ADD CONSTRAINT {table}_provider_check CHECK (provider IN {OLD})"
        )
    op.execute("DROP TABLE IF EXISTS cve_sync_state")
    op.execute("DROP TABLE IF EXISTS cve")

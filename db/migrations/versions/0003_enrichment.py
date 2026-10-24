"""Enrichment: IP reputation cache, daily provider quotas, status, extra indexes.

Revision ID: 0003
Revises: 0002
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE ip_reputation (
            ip inet PRIMARY KEY,
            abuse_score smallint,
            abuse_reports integer,
            abuse_checked_at timestamptz,
            gn_noise boolean,
            gn_riot boolean,
            gn_classification text,
            gn_name text,
            gn_checked_at timestamptz,
            updated_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE enrichment_quota (
            provider text NOT NULL,
            day date NOT NULL,
            used integer NOT NULL DEFAULT 0,
            PRIMARY KEY (provider, day)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE enrichment_status (
            name text PRIMARY KEY,
            detail jsonb NOT NULL DEFAULT '{}',
            updated_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute("CREATE INDEX ix_sessions_asn ON sessions (asn) WHERE asn IS NOT NULL")
    op.execute(
        "CREATE INDEX ix_events_country_ts ON events (country, ts DESC) WHERE country IS NOT NULL"
    )
    # Analytics queries: events by type over time, sessions by recency.
    op.execute("CREATE INDEX ix_events_type_ts ON events (type, ts DESC)")
    op.execute("CREATE INDEX ix_sessions_last_event_at ON sessions (last_event_at DESC)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_sessions_last_event_at")
    op.execute("DROP INDEX IF EXISTS ix_events_type_ts")
    op.execute("DROP INDEX IF EXISTS ix_events_country_ts")
    op.execute("DROP INDEX IF EXISTS ix_sessions_asn")
    op.execute("DROP TABLE IF EXISTS enrichment_status")
    op.execute("DROP TABLE IF EXISTS enrichment_quota")
    op.execute("DROP TABLE IF EXISTS ip_reputation")

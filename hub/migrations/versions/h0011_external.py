"""External tier: the hub's copy of CC0 third-party lists (design M36 sections 5 and 7).

Revision ID: h0011
Revises: h0010

``external_entries`` holds the addresses of a public CC0 list as the hub last saw them (the days
are the hub's own first and last sighting in the source, never a node day). ``external_feed_state``
holds the fetch bookkeeping per source. Neither table references a node, a target or an
observation, and no column holds a client address.
"""

from __future__ import annotations

from alembic import op

revision = "h0011"
down_revision = "h0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE external_entries (
            source text NOT NULL,
            value text NOT NULL,
            family smallint NOT NULL,
            ports integer[] NOT NULL DEFAULT '{}',
            families text[] NOT NULL DEFAULT '{}',
            first_seen date NOT NULL,
            last_seen date NOT NULL,
            PRIMARY KEY (source, value),
            CONSTRAINT external_entries_family CHECK (family IN (4, 6)),
            CONSTRAINT external_entries_days CHECK (first_seen <= last_seen)
        )
        """
    )
    op.execute("CREATE INDEX ix_external_entries_last_seen ON external_entries (last_seen)")
    op.execute(
        """
        CREATE TABLE external_feed_state (
            source text PRIMARY KEY,
            last_try_at timestamptz,
            last_ok_at timestamptz,
            last_error text,
            entry_count integer NOT NULL DEFAULT 0
        )
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE external_feed_state")
    op.execute("DROP TABLE external_entries")

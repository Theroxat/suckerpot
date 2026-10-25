"""Search indexes and benign (research) scanner flags (M19).

Revision ID: 0015
Revises: 0014

* ``sessions.benign`` / ``scanner_name``: a research scanner (a known, harmless crawler) is flagged
  so the dashboard can hide it. ``events.benign`` is nullable and set on new rows only (a
  metadata-only ADD COLUMN, safe on the compressed hypertable).
* Prefix indexes for the header search (indicator values and campaign names).

Known limitation: the continuous aggregates are not split by ``benign``, so long-window charts
include research-scanner events (the web UI says so in its documentation, not per chart).
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE sessions ADD COLUMN benign boolean NOT NULL DEFAULT false")
    op.execute(
        "ALTER TABLE sessions ADD COLUMN scanner_name text "
        "CHECK (scanner_name IS NULL OR char_length(scanner_name) <= 64)"
    )
    op.execute("ALTER TABLE events ADD COLUMN benign boolean")
    op.execute("CREATE INDEX ix_sessions_not_benign ON sessions (started_at DESC) WHERE NOT benign")
    op.execute("CREATE INDEX ix_indicators_value_prefix ON indicators (value text_pattern_ops)")
    op.execute("CREATE INDEX ix_campaigns_name_prefix ON campaigns (lower(name) text_pattern_ops)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_campaigns_name_prefix")
    op.execute("DROP INDEX IF EXISTS ix_indicators_value_prefix")
    op.execute("DROP INDEX IF EXISTS ix_sessions_not_benign")
    op.execute("ALTER TABLE events DROP COLUMN IF EXISTS benign")
    op.execute("ALTER TABLE sessions DROP COLUMN IF EXISTS scanner_name")
    op.execute("ALTER TABLE sessions DROP COLUMN IF EXISTS benign")

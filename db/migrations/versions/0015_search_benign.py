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
    # Ingest has no UPDATE on events. This is the only write it may make there: clear the benign
    # flag of one scanner session's earlier events. It runs as the table owner, with a fixed search
    # path, and does nothing else. Only the ingest role gets EXECUTE (db/suckerpot_db/roles.py).
    op.execute(
        """
        CREATE FUNCTION retract_benign(ids text[]) RETURNS void
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
        BEGIN
            IF cardinality(ids) > 1000 THEN
                RAISE EXCEPTION 'retract_benign: too many sessions';
            END IF;
            UPDATE events e SET benign = false FROM sessions s
            WHERE s.session_id = ANY(ids) AND e.session_id = s.session_id
              AND e.ts >= s.started_at AND e.benign IS TRUE;
        END $$
        """
    )
    op.execute("REVOKE ALL ON FUNCTION retract_benign(text[]) FROM PUBLIC")
    op.execute("CREATE INDEX ix_campaigns_name_prefix ON campaigns (lower(name) text_pattern_ops)")


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS retract_benign(text[])")
    op.execute("DROP INDEX IF EXISTS ix_campaigns_name_prefix")
    op.execute("DROP INDEX IF EXISTS ix_indicators_value_prefix")
    op.execute("DROP INDEX IF EXISTS ix_sessions_not_benign")
    op.execute("ALTER TABLE events DROP COLUMN IF EXISTS benign")
    op.execute("ALTER TABLE sessions DROP COLUMN IF EXISTS scanner_name")
    op.execute("ALTER TABLE sessions DROP COLUMN IF EXISTS benign")

"""First-run setup progress (M28): one row that remembers how far the wizard got.

Revision ID: 0025
Revises: 0022

* ``setup_progress``: a single row (``CHECK id = 1``). ``steps`` maps a step id to ``done`` or
  ``skipped``; the API validates the keys against a constant list and caps the document at 4 KiB.
* Grants (``suckerpot_db.roles``): the API role may SELECT, INSERT and UPDATE; ingest has none.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0025"
# Chained on 0022 in this branch; the integration step re-chains it after 0023 and 0024.
down_revision: str | None = "0022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE setup_progress (
            id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
            started_at timestamptz NOT NULL DEFAULT now(),
            finished_at timestamptz,
            skipped_at timestamptz,
            finished_by text CHECK (char_length(finished_by) <= 120),
            steps jsonb NOT NULL DEFAULT '{}'::jsonb
                CHECK (jsonb_typeof(steps) = 'object' AND pg_column_size(steps) <= 4096)
        )
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS setup_progress")

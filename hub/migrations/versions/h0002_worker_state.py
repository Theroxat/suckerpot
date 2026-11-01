"""Worker bookkeeping and a quieter change cursor.

Revision ID: h0002
Revises: h0001

``worker_state`` holds job markers only (for example the last day reputation was processed).
The ``targets`` trigger now moves ``seq`` only when something a node can see has changed, so an
hourly consensus run that finds nothing new does not make every node re-download every target.
"""

from __future__ import annotations

from alembic import op

revision = "h0002"
down_revision = "h0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE worker_state (
            key text PRIMARY KEY,
            value text NOT NULL
        )
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION targets_bump_seq() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'UPDATE'
               AND (to_jsonb(OLD) - ARRAY['seq', 'updated_at', 'weight', 'report_id',
                                          'confirmed_day', 'node_count', 'country_count'])
                   = (to_jsonb(NEW) - ARRAY['seq', 'updated_at', 'weight', 'report_id',
                                            'confirmed_day', 'node_count', 'country_count'])
               AND (OLD.node_count >= 25) = (NEW.node_count >= 25)
               AND (OLD.node_count >= 10) = (NEW.node_count >= 10)
               AND (OLD.country_count >= 3) = (NEW.country_count >= 3)
               AND (OLD.country_count = NEW.country_count OR OLD.country_count < 3) THEN
                NEW.seq := OLD.seq;
            ELSE
                NEW.seq := nextval('targets_seq');
            END IF;
            RETURN NEW;
        END
        $$
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS worker_state")

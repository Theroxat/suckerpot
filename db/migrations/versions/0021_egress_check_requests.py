"""Egress "Check now" requests (M24).

Revision ID: 0021
Revises: 0020

The dashboard's "Check now" inserts a row; ingest polls pending rows every few seconds, wakes
its egress gate and stamps ``done_at``. Grants are applied by ``suckerpot_db.roles``: the API
selects and inserts; ingest selects and updates ``done_at`` only. Neither can delete: an
AFTER INSERT trigger (SECURITY DEFINER, fixed search_path) keeps the newest 100 rows.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0021"
down_revision: str | None = "0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

KEEP_ROWS = 100


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE egress_check_requests (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            requested_at timestamptz NOT NULL DEFAULT now(),
            requested_by text CHECK (char_length(requested_by) <= 120),
            done_at timestamptz
        )
        """
    )
    op.execute(
        "CREATE INDEX ix_egress_check_requests_pending ON egress_check_requests (id) "
        "WHERE done_at IS NULL"
    )
    op.execute(
        f"""
        CREATE FUNCTION egress_check_requests_trim() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
        BEGIN
            -- By rank, not id arithmetic: a forced huge id cannot prune the others.
            DELETE FROM egress_check_requests WHERE id IN (
                SELECT id FROM egress_check_requests ORDER BY id DESC OFFSET {KEEP_ROWS});
            RETURN NULL;
        END
        $$
        """
    )
    op.execute("REVOKE ALL ON FUNCTION egress_check_requests_trim() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER egress_check_requests_trim AFTER INSERT ON egress_check_requests "
        "FOR EACH ROW EXECUTE FUNCTION egress_check_requests_trim()"
    )


def downgrade() -> None:
    op.execute("DROP TABLE egress_check_requests")
    op.execute("DROP FUNCTION egress_check_requests_trim()")

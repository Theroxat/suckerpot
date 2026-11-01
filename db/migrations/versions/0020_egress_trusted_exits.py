"""Trusted VPN exit ranges, added from the dashboard (M23).

Revision ID: 0020
Revises: 0019

When the owner uploads a new VPN configuration, the exit address may leave the ranges derived
from ``.env``. The API stores the /24 (IPv4) or /48 (IPv6) the egress gate observed once the
owner trusts it; ingest and the collector read the table (once a minute) and add the ranges to
their allow-list. At most 8 rows (a trigger, so no writer can exceed it). Grants are applied by
``suckerpot_db.roles``: the API selects, inserts and deletes; ingest and the collector select.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0020"
down_revision: str | None = "0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

MAX_ROWS = 8


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE egress_trusted_exits (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            cidr cidr NOT NULL UNIQUE,
            created_at timestamptz NOT NULL DEFAULT now(),
            created_by text
        )
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION egress_trusted_exits_cap() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            -- Serialise concurrent inserts so the count below cannot be raced.
            PERFORM pg_advisory_xact_lock(hashtext('egress_trusted_exits'));
            IF (SELECT count(*) FROM egress_trusted_exits) >= {MAX_ROWS} THEN
                RAISE EXCEPTION 'at most {MAX_ROWS} trusted exit ranges'
                    USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER egress_trusted_exits_cap BEFORE INSERT ON egress_trusted_exits "
        "FOR EACH ROW EXECUTE FUNCTION egress_trusted_exits_cap()"
    )


def downgrade() -> None:
    op.execute("DROP TABLE egress_trusted_exits")
    op.execute("DROP FUNCTION egress_trusted_exits_cap()")

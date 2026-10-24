"""Least-privilege roles for ingest (write) and api (read-only).

Revision ID: 0002
Revises: 0001

The role logic lives in ``suckerpot_db.roles``. The migrate entrypoint re-applies it after
every ``alembic upgrade`` so password rotation and grant changes take effect on each run;
this revision applies it once for plain ``alembic upgrade head`` users and drops the roles
on downgrade.
"""

from collections.abc import Sequence

from alembic import op

from suckerpot_db.roles import apply_roles, drop_roles

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    apply_roles(op.get_bind())


def downgrade() -> None:
    drop_roles(op.get_bind())

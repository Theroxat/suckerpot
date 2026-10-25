"""Sessions get a best-effort ``client_tool`` (the RDP sensor's guess: FreeRDP, nmap, ...).

Revision ID: 0007
Revises: 0006

The column is nullable and has no index: it is only displayed. Existing grants are table-level,
so no role change is needed.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE sessions ADD COLUMN client_tool text")


def downgrade() -> None:
    op.execute("ALTER TABLE sessions DROP COLUMN IF EXISTS client_tool")

"""New nodes start at reputation 0.6.

Revision ID: h0003
Revises: h0002

Reputation otherwise only rises through confirmed targets. Five eligible nodes must be able to
confirm at the start (5 x 0.6 = 3.0 = HUB_MIN_WEIGHT), or a new network would never confirm
anything. Existing rows are left alone.
"""

from __future__ import annotations

from alembic import op

revision = "h0003"
down_revision = "h0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE nodes ALTER COLUMN reputation SET DEFAULT 0.6")


def downgrade() -> None:
    op.execute("ALTER TABLE nodes ALTER COLUMN reputation SET DEFAULT 0.5")

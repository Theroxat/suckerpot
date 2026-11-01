"""Batch item counts and the dropper hash of a C2 sighting.

Revision ID: h0004
Revises: h0003

``batches.items`` is how many observation rows the batch held: a node counts as active on a day
only when it submitted data, so empty batches cannot keep Sybil nodes eligible. ``observations.via``
holds the ``via_sha256`` of a C2 sighting: a C2 target is confirmed only together with a dropper
that at least two eligible nodes fetched.
"""

from __future__ import annotations

from alembic import op

revision = "h0004"
down_revision = "h0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE batches ADD COLUMN items integer NOT NULL DEFAULT 0")
    op.execute("ALTER TABLE observations ADD COLUMN via text")


def downgrade() -> None:
    op.execute("ALTER TABLE observations DROP COLUMN via")
    op.execute("ALTER TABLE batches DROP COLUMN items")

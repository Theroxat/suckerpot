"""How many nodes asserted a payload link (security review of M30, finding M3).

Revision ID: h0007
Revises: h0006

``payload_links`` ties a payload host to a URL it served; the feeds drop a host once every URL
it served is taken down. One row per day and link used to be enough, so a single member could
force such a removal, or block one by linking the host to a URL that is still up.

``payload_links.nodes`` counts the eligible nodes that asserted the link on that day. A node sends
one batch per day, so each batch adds one to each of its links; no node id is stored. The feed job
acts on a link only when at least ``HUB_MIN_NODES`` nodes asserted it on one day.

Existing rows count as one node, and ``target_hosts`` (built from those rows) is emptied: the
feed job rebuilds it from links that are k-supported.
"""

from __future__ import annotations

from alembic import op

revision = "h0007"
down_revision = "h0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE payload_links ADD COLUMN nodes integer NOT NULL DEFAULT 1 CHECK (nodes >= 1)"
    )
    op.execute("DELETE FROM target_hosts")


def downgrade() -> None:
    op.execute("ALTER TABLE payload_links DROP COLUMN nodes")

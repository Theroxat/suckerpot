"""List scope of delisting decisions (security review of M30, finding H1).

Revision ID: h0006
Revises: h0005

A delisting request that concerns the ``inbound`` list must never take a value off the outbound
lists (a bot address that is also a malware host or a C2). Two columns carry that scope:

* ``delist_requests.scope``: the list the request applies to, fixed when it is filed. It is the
  list the requester named, or ``inbound`` when the value was on ``inbound`` only, or NULL (every
  list) for a request about a value that is on an outbound list too, which an operator reviews
  before anything changes.
* ``feed_allow.list``: the list an allow-list row applies to, NULL for every list. An accepted
  request copies its scope; rows added with ``hub.admin allow add`` apply to every list.

Existing open requests that were suppressed only ever concerned ``inbound``; existing requests
that named a list keep that list. Existing allow-list rows that came from a delisting are scoped
the same way through their request (their note holds the request id).
"""

from __future__ import annotations

from alembic import op

revision = "h0006"
down_revision = "h0005"
branch_labels = None
depends_on = None

LISTS = "'inbound', 'outbound', 'outbound-domains'"


def upgrade() -> None:
    op.execute("ALTER TABLE delist_requests ADD COLUMN scope text")
    op.execute(
        "ALTER TABLE delist_requests ADD CONSTRAINT delist_requests_scope "
        f"CHECK (scope IS NULL OR scope IN ({LISTS}))"
    )
    op.execute(
        "UPDATE delist_requests SET scope = coalesce(list, "
        "CASE WHEN state = 'suppressed' THEN 'inbound' END)"
    )
    op.execute("ALTER TABLE feed_allow ADD COLUMN list text")
    op.execute(
        "ALTER TABLE feed_allow ADD CONSTRAINT feed_allow_list "
        f"CHECK (list IS NULL OR list IN ({LISTS}))"
    )
    op.execute(
        """
        UPDATE feed_allow fa SET list = dr.scope
        FROM delist_requests dr
        WHERE fa.source = 'delist' AND fa.note = 'delisting ' || dr.id
        """
    )


def downgrade() -> None:
    op.execute("ALTER TABLE feed_allow DROP COLUMN list")
    op.execute("ALTER TABLE delist_requests DROP COLUMN scope")

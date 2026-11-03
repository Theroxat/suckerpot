"""Link verification: verifier roles, tasks, attestations and daily counters (design M32 7.1).

Revision ID: h0009
Revises: h0008

``verify_tasks`` holds the clear link a verifier fetches (revealed early by reporters, never
written to ``targets.value``) and deletes it with the task 14 days after the end. The only node
reference in a task is the live lease. Reporters are counted, never stored per task. No address
column about a client.

Deviation from the design DDL: the lower-cased host of ``url`` is named ``site``, not ``host``,
because the hub privacy test refuses any column named like a client address (``host`` included).
"""

from __future__ import annotations

from alembic import op

revision = "h0009"
down_revision = "h0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE node_roles (
            node_id uuid NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
            role text NOT NULL CHECK (role IN ('verifier')),
            granted_day date NOT NULL,
            PRIMARY KEY (node_id, role)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE verify_tasks (
            id text PRIMARY KEY,
            url_b text NOT NULL UNIQUE,
            url text,
            site text,
            state text NOT NULL CHECK (state IN ('waiting_reveal', 'pending_review', 'queued',
                'leased', 'attested', 'failed', 'refused', 'expired')),
            refusal text,
            reporters int NOT NULL,
            reporter_cohorts int NOT NULL,
            last_report_day date NOT NULL,
            created_day date NOT NULL,
            revealed_day date,
            release_at timestamptz,
            lease_node uuid REFERENCES nodes (id) ON DELETE SET NULL,
            lease_until timestamptz,
            attempts smallint NOT NULL DEFAULT 0,
            ended_day date
        )
        """
    )
    op.execute("CREATE INDEX verify_tasks_state ON verify_tasks (state)")
    op.execute("CREATE INDEX verify_tasks_site_revealed ON verify_tasks (site, revealed_day)")
    op.execute(
        """
        CREATE TABLE verify_attestations (
            task_id text NOT NULL REFERENCES verify_tasks (id) ON DELETE CASCADE,
            node_id uuid NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
            day date NOT NULL,
            outcome text NOT NULL,
            sha256 text,
            size int,
            file_type text,
            family text,
            malware_like boolean NOT NULL DEFAULT false,
            PRIMARY KEY (task_id, node_id)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE verify_daily (
            day date PRIMARY KEY,
            created int NOT NULL DEFAULT 0,
            revealed int NOT NULL DEFAULT 0,
            refused int NOT NULL DEFAULT 0,
            queued int NOT NULL DEFAULT 0,
            attested int NOT NULL DEFAULT 0,
            malware_like int NOT NULL DEFAULT 0,
            expired int NOT NULL DEFAULT 0
        )
        """
    )
    op.execute(
        """
        ALTER TABLE abusech_submissions
            ADD COLUMN basis text NOT NULL DEFAULT 'consensus'
                CHECK (basis IN ('consensus', 'verified')),
            ADD COLUMN verify_task_id text
        """
    )


def downgrade() -> None:
    op.execute("ALTER TABLE abusech_submissions DROP COLUMN IF EXISTS verify_task_id")
    op.execute("ALTER TABLE abusech_submissions DROP COLUMN IF EXISTS basis")
    op.execute("DROP TABLE IF EXISTS verify_daily")
    op.execute("DROP TABLE IF EXISTS verify_attestations")
    op.execute("DROP TABLE IF EXISTS verify_tasks")
    op.execute("DROP TABLE IF EXISTS node_roles")

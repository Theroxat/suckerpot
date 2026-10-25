"""Dashboard users and the audit log.

Revision ID: 0010
Revises: 0009

* ``users``: additional dashboard accounts (the owner account stays in ``.env`` and has no row).
  The password is an argon2id hash; ``session_version`` is bumped to end every session of the
  user at once (password change or reset, disable, role change, deletion, "revoke sessions").
* ``audit_log``: who did what to whom, with a bounded ``details`` document that never holds a
  secret. ``suckerpot_audit_prune`` deletes entries older than a year; the job is created by
  ``suckerpot_db.retention.apply_policies``.

Grants are applied by ``suckerpot_db.roles``: the API reads and writes ``users`` and appends to
``audit_log``; ingest has no access to either.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PRUNE = """
CREATE OR REPLACE PROCEDURE suckerpot_audit_prune(job_id integer, config jsonb)
LANGUAGE plpgsql AS $$
DECLARE
    days integer := COALESCE((config ->> 'retention_days')::integer, 365);
BEGIN
    DELETE FROM audit_log WHERE ts < now() - make_interval(days => days);
END
$$
"""


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE users (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            username text NOT NULL
                CHECK (char_length(username) BETWEEN 3 AND 32
                       AND username ~ '^[A-Za-z0-9][A-Za-z0-9._-]*$'),
            display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 64),
            role text NOT NULL CHECK (role IN ('admin', 'viewer')),
            password_hash text NOT NULL CHECK (char_length(password_hash) <= 512),
            must_change_password boolean NOT NULL DEFAULT true,
            disabled boolean NOT NULL DEFAULT false,
            created_at timestamptz NOT NULL DEFAULT now(),
            created_by text NOT NULL,
            last_login_at timestamptz,
            prev_login_at timestamptz,
            password_changed_at timestamptz,
            failed_logins integer NOT NULL DEFAULT 0,
            locked_until timestamptz,
            session_version integer NOT NULL DEFAULT 0
        )
        """
    )
    op.execute("CREATE UNIQUE INDEX ux_users_username_lower ON users (lower(username))")
    op.execute(
        """
        CREATE TABLE audit_log (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            ts timestamptz NOT NULL DEFAULT now(),
            actor text NOT NULL CHECK (char_length(actor) <= 128),
            action text NOT NULL CHECK (char_length(action) <= 64),
            target text CHECK (target IS NULL OR char_length(target) <= 128),
            ip text CHECK (ip IS NULL OR char_length(ip) <= 64),
            details jsonb NOT NULL DEFAULT '{}'::jsonb
                CHECK (octet_length(details::text) <= 2048)
        )
        """
    )
    op.execute("CREATE INDEX ix_audit_log_ts ON audit_log (ts DESC, id DESC)")
    op.execute("CREATE INDEX ix_audit_log_actor_ts ON audit_log (lower(actor), ts DESC)")
    op.execute("CREATE INDEX ix_audit_log_action_ts ON audit_log (action, ts DESC)")
    op.execute(_PRUNE)


def downgrade() -> None:
    op.execute(
        "SELECT delete_job(job_id) FROM timescaledb_information.jobs "
        "WHERE proc_name = 'suckerpot_audit_prune'"
    )
    op.execute("DROP PROCEDURE IF EXISTS suckerpot_audit_prune(integer, jsonb)")
    op.execute("DROP TABLE IF EXISTS audit_log")
    op.execute("DROP TABLE IF EXISTS users")

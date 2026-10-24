"""Least-privilege roles for ingest (write) and api (read-only).

Revision ID: 0002
Revises: 0001

Role names and passwords come from the environment at migration time
(POSTGRES_INGEST_USER/PASSWORD, POSTGRES_API_USER/PASSWORD). The values travel as bound
parameters into transaction-local settings and are quoted server-side with format('%I'/'%L'),
so they are never interpolated into SQL text by Python, written to files or logged.
"""

import os
from collections.abc import Sequence

from alembic import op
from sqlalchemy import text

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

INGEST_DEFAULT = "suckerpot_ingest"
API_DEFAULT = "suckerpot_api"

_CREATE_ROLE = """
DO $$
DECLARE
    r text := current_setting('suckerpot.role_name');
    pw text := current_setting('suckerpot.role_password');
    t text := current_setting('suckerpot.role_timeout');
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
        EXECUTE format(
            'ALTER ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE '
            'NOREPLICATION NOBYPASSRLS', r, pw);
    ELSE
        EXECUTE format(
            'CREATE ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE '
            'NOREPLICATION NOBYPASSRLS', r, pw);
    END IF;
    EXECUTE format('ALTER ROLE %I SET statement_timeout = %L', r, t);
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), r);
    EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', r);
END
$$
"""

_GRANTS_INGEST = """
DO $$
DECLARE r text := current_setting('suckerpot.role_name');
BEGIN
    EXECUTE format('GRANT SELECT, INSERT ON events TO %I', r);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON sessions TO %I', r);
    EXECUTE format('GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO %I', r);
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT ON TABLES TO %I', r);
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE ON SEQUENCES TO %I', r);
END
$$
"""

_GRANTS_API = """
DO $$
DECLARE r text := current_setting('suckerpot.role_name');
BEGIN
    EXECUTE format('GRANT SELECT ON events, sessions TO %I', r);
    EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO %I', r);
END
$$
"""

_DROP_ROLE = """
DO $$
DECLARE r text := current_setting('suckerpot.role_name');
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
        EXECUTE format('DROP OWNED BY %I', r);
        EXECUTE format('DROP ROLE %I', r);
    END IF;
END
$$
"""


def _role(kind: str, default_name: str) -> tuple[str, str]:
    name = os.environ.get(f"POSTGRES_{kind}_USER", default_name)
    password = os.environ.get(f"POSTGRES_{kind}_PASSWORD", "")
    return name, password


def _set(name: str, password: str, timeout: str) -> None:
    conn = op.get_bind()
    # is_local=true: the settings vanish at the end of the migration transaction.
    for key, value in (
        ("suckerpot.role_name", name),
        ("suckerpot.role_password", password),
        ("suckerpot.role_timeout", timeout),
    ):
        conn.execute(text("SELECT set_config(:k, :v, true)"), {"k": key, "v": value})


def upgrade() -> None:
    owner = os.environ.get("POSTGRES_USER", "")
    roles = {"INGEST": _role("INGEST", INGEST_DEFAULT), "API": _role("API", API_DEFAULT)}
    for kind, (name, password) in roles.items():
        if not password:
            raise RuntimeError(f"POSTGRES_{kind}_PASSWORD must be set to create the {kind} role")
        if name == owner:
            raise RuntimeError(f"POSTGRES_{kind}_USER must differ from POSTGRES_USER")
    if roles["INGEST"][0] == roles["API"][0]:
        raise RuntimeError("POSTGRES_INGEST_USER and POSTGRES_API_USER must differ")

    name, password = roles["INGEST"]
    _set(name, password, "30s")
    op.execute(_CREATE_ROLE)
    op.execute(_GRANTS_INGEST)

    name, password = roles["API"]
    _set(name, password, "5s")
    op.execute(_CREATE_ROLE)
    op.execute(_GRANTS_API)


def downgrade() -> None:
    for kind, default in (("INGEST", INGEST_DEFAULT), ("API", API_DEFAULT)):
        name, _ = _role(kind, default)
        _set(name, "", "")
        op.execute(_DROP_ROLE)

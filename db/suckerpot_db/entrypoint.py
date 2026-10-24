"""Migrate entrypoint: enforce the secrets policy, run the command, then re-apply the roles.

Policy: owner, ingest and api database passwords are at least 24 characters long and pairwise
distinct, unless SUCKERPOT_ALLOW_DEFAULT_SECRETS=1 (development and CI only). Only variable
names are ever printed, never values.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from collections.abc import Mapping

from sqlalchemy.ext.asyncio import create_async_engine

from suckerpot_db.diskguard import DiskGuardError, apply_disk_guard
from suckerpot_db.engine import database_url_from_env
from suckerpot_db.retention import RetentionError, apply_retention
from suckerpot_db.roles import RoleError, apply_roles

MIN_LENGTH = 24
SECRET_VARS = ("POSTGRES_PASSWORD", "POSTGRES_INGEST_PASSWORD", "POSTGRES_API_PASSWORD")


def check_secrets(env: Mapping[str, str]) -> list[str]:
    """Return a list of human-readable problems (empty when the policy is satisfied)."""
    problems = [f"{name} is not set" for name in SECRET_VARS if not env.get(name)]
    if env.get("SUCKERPOT_ALLOW_DEFAULT_SECRETS") == "1":
        return problems
    for name in SECRET_VARS:
        value = env.get(name)
        if value and len(value) < MIN_LENGTH:
            problems.append(f"{name} must be at least {MIN_LENGTH} characters")
    values = [(n, env[n]) for n in SECRET_VARS if env.get(n)]
    for i, (a, va) in enumerate(values):
        for b, vb in values[i + 1 :]:
            if va == vb:
                problems.append(f"{a} and {b} must be different")
    return problems


def main(argv: list[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    problems = check_secrets(os.environ)
    if problems:
        print("migrate: refusing to run, secrets policy violated:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print(
            "Set strong, distinct passwords in .env "
            "(SUCKERPOT_ALLOW_DEFAULT_SECRETS=1 bypasses the length/uniqueness checks "
            "for local development only).",
            file=sys.stderr,
        )
        sys.exit(1)
    if not args:
        args = ["alembic", "upgrade", "head"]
    rc = subprocess.run(args, check=False).returncode  # noqa: S603
    if rc == 0 and is_upgrade(args):
        try:
            asyncio.run(_apply_roles())
        except RoleError as exc:
            print(f"migrate: {exc}", file=sys.stderr)
            sys.exit(1)
        except Exception as exc:
            print(
                f"migrate: applying database roles failed ({type(exc).__name__})", file=sys.stderr
            )
            sys.exit(1)
        print("migrate: database roles applied", file=sys.stderr)
        try:
            days = asyncio.run(_apply_retention())
        except (RetentionError, DiskGuardError) as exc:
            print(f"migrate: {exc}", file=sys.stderr)
            sys.exit(1)
        except Exception as exc:
            print(
                f"migrate: applying retention policies failed ({type(exc).__name__})",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"migrate: retention policies applied (raw events kept {days} days)", file=sys.stderr)
    sys.exit(rc)


def is_upgrade(args: list[str]) -> bool:
    """True for ``alembic upgrade ...`` (also ``python -m alembic upgrade ...``)."""
    head = args[:4]
    return "upgrade" in head and any(a == "alembic" or a.endswith("/alembic") for a in head)


async def _apply_roles() -> None:
    engine = create_async_engine(database_url_from_env())
    try:
        async with engine.begin() as conn:
            await conn.run_sync(apply_roles)
    finally:
        await engine.dispose()


async def _apply_retention() -> int:
    # Autocommit: refreshing a continuous aggregate cannot run inside a transaction block.
    engine = create_async_engine(database_url_from_env(), isolation_level="AUTOCOMMIT")
    try:
        async with engine.connect() as conn:
            days = await conn.run_sync(apply_retention)
            limit = await conn.run_sync(apply_disk_guard)
            print(f"migrate: disk guard ceiling {limit // 1048576} MB", file=sys.stderr)
            return days
    finally:
        await engine.dispose()


if __name__ == "__main__":
    main()

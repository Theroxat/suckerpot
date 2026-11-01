"""One-shot migrate entrypoint: check passwords, run Alembic, then apply the database roles."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys

from sqlalchemy.ext.asyncio import create_async_engine

from .roles import RoleError, apply_roles, check_passwords


async def _apply() -> None:
    engine = create_async_engine(os.environ["HUB_MIGRATE_DATABASE_URL"])
    try:
        async with engine.begin() as conn:
            await conn.run_sync(apply_roles)
    finally:
        await engine.dispose()


def main() -> None:
    problems = check_passwords(os.environ)
    if problems:
        print("hub-migrate: refusing to run:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        sys.exit(1)
    rc = subprocess.run(["alembic", "upgrade", "head"], check=False).returncode  # noqa: S607
    if rc != 0:
        sys.exit(rc)
    try:
        asyncio.run(_apply())
    except RoleError as exc:
        print(f"hub-migrate: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(
            f"hub-migrate: applying database roles failed ({type(exc).__name__})", file=sys.stderr
        )
        sys.exit(1)
    print("hub-migrate: schema and roles are up to date", file=sys.stderr)


if __name__ == "__main__":
    main()

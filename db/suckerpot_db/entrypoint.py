"""Migrate entrypoint: enforce the secrets policy, then exec the command (alembic upgrade head).

Policy: owner, ingest and api database passwords are at least 24 characters long and pairwise
distinct, unless SUCKERPOT_ALLOW_DEFAULT_SECRETS=1 (development and CI only). Only variable
names are ever printed, never values.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping

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
    os.execvp(args[0], args)  # noqa: S606


if __name__ == "__main__":
    main()

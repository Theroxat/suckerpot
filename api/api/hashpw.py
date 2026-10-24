"""Generate the ``ADMIN_PASSWORD_HASH`` value.

    docker compose run --rm api python -m api.hashpw

Prompts twice (no echo) and prints the argon2id PHC string, nothing else, on stdout.
``--stdin`` reads the password from one line of standard input instead (scripts).
The password is never written anywhere.
"""

from __future__ import annotations

import getpass
import sys
from collections.abc import Callable, Sequence

from argon2 import PasswordHasher

MIN_LENGTH = 12


def main(
    argv: Sequence[str] | None = None,
    *,
    prompt: Callable[[str], str] = getpass.getpass,
    stdin: Callable[[], str] = sys.stdin.readline,
) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--stdin"]:
        password = stdin().rstrip("\r\n")
    elif not args:
        password = prompt("Password: ")
        if prompt("Repeat password: ") != password:
            print("Passwords do not match.", file=sys.stderr)
            return 1
    else:
        print("usage: python -m api.hashpw [--stdin]", file=sys.stderr)
        return 2
    if len(password) < MIN_LENGTH:
        print(f"Use at least {MIN_LENGTH} characters.", file=sys.stderr)
        return 1
    print(PasswordHasher().hash(password))
    if sys.stderr.isatty():
        print(
            "Put it in .env between single quotes: ADMIN_PASSWORD_HASH='<value>' "
            "(the $ signs must not be expanded).",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Password policy and one-time temporary passwords for dashboard accounts.

Rules (the API enforces them; the web form only repeats them to save a round trip):

* 12 to 256 characters;
* not one of the most common passwords (``data/common-passwords.txt``, see the header of that
  file for its source), also when digits or symbols were added at the end;
* not equal to, and not containing, the username.

Nothing here logs, stores or returns a password.
"""

from __future__ import annotations

import re
import secrets
from functools import cache
from pathlib import Path

MIN_LENGTH = 12
MAX_LENGTH = 256
COMMON_FILE = Path(__file__).parent / "data" / "common-passwords.txt"
# No 0/O, 1/l/I or other look-alikes: a temporary password is read off a screen and typed.
TEMP_ALPHABET = "abcdefghjkmnpqrstuvwxyzACDEFGHJKLMNPQRTUVWXYZ2346789"
TEMP_GROUPS = 4
TEMP_GROUP_LEN = 5  # 20 characters from 53 symbols: about 114 bits

# Short roots that the 12+ character list cannot contain: "password" + digits is still weak.
COMMON_ROOTS = frozenset(
    {
        "password", "passw0rd", "p@ssw0rd", "p@ssword", "qwerty", "qwertyuiop", "azerty",
        "azertyuiop",
        "letmein", "welcome", "admin", "administrator", "iloveyou", "monkey", "dragon", "football",
        "baseball", "master", "sunshine", "princess", "changeme", "secret", "abc", "abcdef",
        "abcdefgh", "trustno", "superman", "batman", "starwars", "whatever", "freedom", "shadow",
        "michael", "jordan", "hunter", "ranger", "login", "root", "test", "guest", "default",
        "honeypot", "suckerpot", "dashboard", "console", "123456", "123456789", "1q2w3e4r",
    }
)  # fmt: skip
_TRAILING = re.compile(r"[\d!@#$%^&*._-]+$")

TOO_SHORT = "too_short"
TOO_LONG = "too_long"
COMMON = "common"
CONTAINS_USERNAME = "contains_username"

MESSAGES = {
    TOO_SHORT: f"Use at least {MIN_LENGTH} characters.",
    TOO_LONG: f"Use at most {MAX_LENGTH} characters.",
    COMMON: "That password is too common. Choose something less guessable.",
    CONTAINS_USERNAME: "The password must not contain the username.",
}


@cache
def common_passwords() -> frozenset[str]:
    """The bundled list, lower-cased. Read once."""
    lines = COMMON_FILE.read_text(encoding="utf-8").splitlines()
    return frozenset(line.strip() for line in lines if line.strip() and not line.startswith("#"))


def check_password(password: str, username: str = "") -> str | None:
    """The code of the first rule the password breaks, or None when it is acceptable."""
    if len(password) < MIN_LENGTH:
        return TOO_SHORT
    if len(password) > MAX_LENGTH:
        return TOO_LONG
    lowered = password.lower()
    common = common_passwords()
    root = _TRAILING.sub("", lowered)
    if lowered in common or root in common or root in COMMON_ROOTS:
        return COMMON
    name = username.strip().lower()
    if name and name in lowered:
        return CONTAINS_USERNAME
    return None


def generate_temporary_password() -> str:
    """A strong one-time password such as ``kP3mR-4tqXw-nH8yD-aVu6c``."""
    while True:
        groups = [
            "".join(secrets.choice(TEMP_ALPHABET) for _ in range(TEMP_GROUP_LEN))
            for _ in range(TEMP_GROUPS)
        ]
        password = "-".join(groups)
        if check_password(password) is None:
            return password

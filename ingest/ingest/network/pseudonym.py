"""Random node pseudonyms ``adjective-noun-NN`` (design M32 section 8.3).

The word lists are shared with the installer (``suckerpot_netproto`` package data). A generated
name still passes the M29 shape rules and the identity guard before it is used.
"""

from __future__ import annotations

import random
import re
from collections.abc import Awaitable, Callable
from functools import lru_cache

from suckerpot_db.network_names import pseudonym_problem
from suckerpot_netproto import defaults

MAX_TRIES = 20
_SHAPE = re.compile(r"^([a-z]+)-([a-z]+)-(\d{2})$")


@lru_cache(maxsize=1)
def _words() -> tuple[tuple[str, ...], tuple[str, ...]]:
    return defaults.pseudonym_words()


def generate(rng: random.Random | None = None) -> str:
    """One random name. Two digits only: the M29 rules refuse four digits in a row."""
    r = rng or random.SystemRandom()
    adjectives, nouns = _words()
    return f"{r.choice(adjectives)}-{r.choice(nouns)}-{r.randint(10, 99)}"


def is_generated(name: str | None) -> bool:
    """True for a name built from the shared word lists (as opposed to one the operator chose)."""
    if not name:
        return False
    m = _SHAPE.fullmatch(name)
    if m is None:
        return False
    adjectives, nouns = _words()
    return m.group(1) in adjectives and m.group(2) in nouns


async def fresh(
    ok: Callable[[str], Awaitable[bool]], rng: random.Random | None = None
) -> str | None:
    """A generated name that passes the local shape rules and ``ok`` (the identity guard)."""
    for _ in range(MAX_TRIES):
        name = generate(rng)
        if pseudonym_problem(name) is None and await ok(name):
            return name
    return None

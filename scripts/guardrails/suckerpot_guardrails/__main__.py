"""``python -m suckerpot_guardrails [compose files...]``: print violations, exit 1 on any."""

from __future__ import annotations

import sys
from pathlib import Path

from suckerpot_guardrails.compose import check_compose, load_compose


def main(argv: list[str]) -> int:
    root = Path(__file__).resolve().parents[3]
    base = [root / "docker-compose.yml"]
    overlays = [root / "docker-compose.ci.yml", root / "docker-compose.it.yml"]
    files = [Path(a) for a in argv] or base
    problems = check_compose(load_compose(files))
    if not argv:
        for overlay in overlays:
            if overlay.exists():
                problems += [
                    f"[{overlay.name}] {p}" for p in check_compose(load_compose([*base, overlay]))
                ]
    for problem in problems:
        print(f"guardrails: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

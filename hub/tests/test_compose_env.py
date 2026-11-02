"""Guardrail: every HUB_* variable config.py reads is wired in compose and documented."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

HUB = Path(__file__).resolve().parents[1]

# Set by compose itself (not from .env), or only meaningful in the test overlay.
NOT_FROM_ENV = {
    "HUB_DATABASE_URL",
    "HUB_WORKER_DATABASE_URL",
    "HUB_SIGNING_KEY_FILE",
    "HUB_TRUST_PROXY",
    "HUB_ALLOW_DOCUMENTATION",
}
# Built from other documented variables or fixed by compose, so absent from .env.example.
NOT_IN_EXAMPLE = NOT_FROM_ENV


def _read_vars() -> set[str]:
    source = (HUB / "hub" / "config.py").read_text(encoding="utf-8")
    return set(re.findall(r'"(HUB_[A-Z0-9_]+)"', source))


def _compose_env() -> dict[str, str]:
    doc = yaml.safe_load((HUB / "docker-compose.yml").read_text(encoding="utf-8"))
    env: dict[str, str] = {}
    for name in ("hub-api", "hub-worker"):
        env.update({str(k): str(v) for k, v in doc["services"][name]["environment"].items()})
    return env


def test_config_reads_some_variables() -> None:
    assert len(_read_vars()) > 30


def test_every_variable_is_in_compose_with_the_code_default() -> None:
    env = _compose_env()
    missing = sorted(v for v in _read_vars() - {"HUB_ALLOW_DOCUMENTATION"} if v not in env)
    assert not missing, f"not passed by compose: {missing}"
    for name in sorted(_read_vars() - NOT_FROM_ENV):
        assert re.fullmatch(r"\$\{" + name + r":-[^}]*\}", env[name]), (
            f"{name} must be ${{{name}:-default}} in compose"
        )


def test_every_variable_is_in_env_example() -> None:
    text = (HUB / ".env.example").read_text(encoding="utf-8")
    listed = set(re.findall(r"^(HUB_[A-Z0-9_]+)=", text, flags=re.M))
    missing = sorted(_read_vars() - NOT_IN_EXAMPLE - listed)
    assert not missing, f"missing from .env.example: {missing}"


def test_tor_exclusion_has_no_switch() -> None:
    """Security review L5: Tor exits are always excluded, so no file may offer to turn it off."""
    for name in ("docker-compose.yml", ".env.example", "README.md", "hub/config.py"):
        assert "HUB_FEED_EXCLUDE_TOR" not in (HUB / name).read_text(encoding="utf-8"), name


def test_tor_exits_are_excluded_whatever_the_environment_says() -> None:
    from hub.config import Settings
    from hub.feeds.filter import TOR, build_exclusions

    s = Settings.from_env({"HUB_FEED_EXCLUDE_TOR": "false", "HUB_ALLOW_DOCUMENTATION": "1"})
    excl = build_exclusions(s, never_rows=[], allow_rows=[], range_rows=[("tor", "203.0.113.7/32")])
    assert excl.classify("203.0.113.7", is_domain=False) == TOR


def test_feed_key_command_names_the_key_file() -> None:
    """gen-feed-key needs --out; the documented command writes where the compose secret reads."""
    for name in (".env.example", "docker-compose.yml", "README.md"):
        text = (HUB / name).read_text(encoding="utf-8")
        for line in text.splitlines():
            if "gen-feed-key" in line and "docker compose run" in line:
                assert "--out /keys/feed_key" in line, (name, line)

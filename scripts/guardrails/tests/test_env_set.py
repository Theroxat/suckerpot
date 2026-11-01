"""scripts/env-set.sh (just sensors, just set) and scripts/env-migrate.sh (run by just update)."""

import re
import stat
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import ROOT, Sandbox

SENSORS = "ssh telnet web rdp redis docker mysql adb mssql smb sip synology".split()

BASE_ENV = """\
# my comment
COMPOSE_PROJECT_NAME=demo
SUCKERPOT_VOLUME_PREFIX=demo
DASHBOARD_PORT=8443
COOKIE_SECURE=true
# keep this comment
ABUSE_REPORTS_ENABLED=false
POSTGRES_PASSWORD=ownerpassword-aaaaaaaaaaaaaaaaaaaa
"""


def test_set_changes_allowed_keys_keeps_comments(sandbox: Sandbox) -> None:
    sandbox.write_env(BASE_ENV)
    proc = sandbox.run(
        "scripts/env-set.sh", "set", "ABUSE_REPORTS_ENABLED=true", "NEWFLAG_ENABLED=false"
    )
    assert proc.returncode == 0, proc.stderr
    text = (sandbox.root / ".env").read_text()
    assert "ABUSE_REPORTS_ENABLED=true\n" in text
    assert "ABUSE_REPORTS_ENABLED=false" not in text
    assert text.count("ABUSE_REPORTS_ENABLED") == 1
    assert "# my comment\n" in text and "# keep this comment\n" in text
    assert text.endswith("NEWFLAG_ENABLED=false\n")
    assert stat.S_IMODE((sandbox.root / ".env").stat().st_mode) == 0o600
    assert "true" not in proc.stdout  # names only


@pytest.mark.parametrize(
    "pair",
    [
        "POSTGRES_PASSWORD=x",
        "SESSION_SECRET=x",
        "ADMIN_PASSWORD_HASH=x",
        "SETTINGS_ENCRYPTION_KEY=x",
        "ABUSEIPDB_API_KEY=x",
        "VIRUSTOTAL_API_KEY=x",
        "VPN_WG_PRIVATE_KEY=x",
        "VPN_WG_ENDPOINT_IP=198.51.100.1",
        "SOMETHING_PASSWORD_ENABLED=true",
        "COMPOSE_PROJECT_NAME=other",
        "SUCKERPOT_VOLUME_PREFIX=other",
        "COMPOSE_FILE=evil.yml",
        "lowercase=1",
        "NOEQUALS",
    ],
)
def test_set_refuses_secret_looking_and_unlisted_keys(sandbox: Sandbox, pair: str) -> None:
    sandbox.write_env(BASE_ENV)
    proc = sandbox.run("scripts/env-set.sh", "set", pair)
    assert proc.returncode != 0
    assert (sandbox.root / ".env").read_text() == BASE_ENV


@pytest.mark.parametrize(
    "pair",
    [
        "ABUSE_REPORTS_ENABLED=maybe",
        "SENSOR_SSH=2",
        "DASHBOARD_PORT=0",
        "DASHBOARD_PORT=70000",
        "SSH_HOST_PORT=abc",
        "API_ALLOWED_HOSTS=a b",
        "API_ALLOWED_HOSTS=$(id)",
        "API_ALLOWED_HOSTS=a;b",
        "API_ALLOWED_HOSTS=`id`",
        "INDICATORS_IGNORE=" + "a" * 600,
    ],
)
def test_set_refuses_bad_values(sandbox: Sandbox, pair: str) -> None:
    sandbox.write_env(BASE_ENV)
    proc = sandbox.run("scripts/env-set.sh", "set", pair)
    assert proc.returncode != 0
    assert (sandbox.root / ".env").read_text() == BASE_ENV


def test_set_is_all_or_nothing(sandbox: Sandbox) -> None:
    sandbox.write_env(BASE_ENV)
    proc = sandbox.run("scripts/env-set.sh", "set", "COOKIE_SECURE=false", "SESSION_SECRET=x")
    assert proc.returncode != 0
    assert (sandbox.root / ".env").read_text() == BASE_ENV


def test_set_allows_the_network_hub_key_only_for_hub_key(sandbox: Sandbox) -> None:
    sandbox.write_env(BASE_ENV)
    ok = sandbox.run("scripts/env-set.sh", "set", "NETWORK_HUB_KEY=abc123")
    assert ok.returncode == 0, ok.stderr
    assert "abc123" not in ok.stdout + ok.stderr


def test_set_reverts_when_the_port_check_refuses(sandbox: Sandbox) -> None:
    sandbox.write_env(BASE_ENV)
    # The dashboard on the SSH sensor's standard port is refused by check-ports.sh.
    proc = sandbox.run("scripts/env-set.sh", "set", "DASHBOARD_PORT=22")
    assert proc.returncode != 0
    assert (sandbox.root / ".env").read_text() == BASE_ENV


def test_sensors_sets_all_twelve_lines(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    sandbox.write_env(BASE_ENV)
    proc = sandbox.run("scripts/env-set.sh", "sensors", "ssh,web")
    assert proc.returncode == 0, proc.stderr
    env = parse_env(sandbox.root / ".env")
    for s in SENSORS:
        assert env[f"SENSOR_{s.upper()}"] == ("1" if s in ("ssh", "web") else "0")
    again = sandbox.run("scripts/env-set.sh", "sensors", "all")
    assert again.returncode == 0
    env = parse_env(sandbox.root / ".env")
    assert all(env[f"SENSOR_{s.upper()}"] == "1" for s in SENSORS)
    text = (sandbox.root / ".env").read_text()
    assert text.count("SENSOR_SSH=") == 1


def test_sensors_without_argument_prints_the_selection(sandbox: Sandbox) -> None:
    sandbox.write_env(BASE_ENV + "SENSOR_TELNET=0\n")
    proc = sandbox.run("scripts/env-set.sh", "sensors")
    assert proc.returncode == 0
    assert re.search(r"telnet\s+off", proc.stdout)
    assert re.search(r"ssh\s+on", proc.stdout)
    assert (sandbox.root / ".env").read_text() == BASE_ENV + "SENSOR_TELNET=0\n"


def test_sensors_refuses_unknown_and_empty(sandbox: Sandbox) -> None:
    sandbox.write_env(BASE_ENV)
    assert sandbox.run("scripts/env-set.sh", "sensors", "ssh,bogus").returncode != 0
    assert sandbox.run("scripts/env-set.sh", "sensors", "none").returncode != 0
    assert (sandbox.root / ".env").read_text() == BASE_ENV


def test_env_set_needs_an_env_file(sandbox: Sandbox) -> None:
    proc = sandbox.run("scripts/env-set.sh", "set", "COOKIE_SECURE=true")
    assert proc.returncode != 0
    assert not (sandbox.root / ".env").exists()


# ----------------------------------------------------------------- env-migrate


def test_migrate_adds_missing_secrets_and_never_changes_a_line(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    sandbox.write_env(BASE_ENV + "SESSION_SECRET=keepme-keepme-keepme-keepme-keepme\n")
    before = (sandbox.root / ".env").read_text()
    proc = sandbox.run("scripts/env-migrate.sh")
    assert proc.returncode == 0, proc.stderr
    after = (sandbox.root / ".env").read_text()
    assert after.startswith(before)  # nothing before was touched
    assert "# added by just update" in after
    env = parse_env(sandbox.root / ".env")
    assert env["SESSION_SECRET"] == "keepme-keepme-keepme-keepme-keepme"  # noqa: S105
    assert env["POSTGRES_PASSWORD"] == "ownerpassword-aaaaaaaaaaaaaaaaaaaa"  # noqa: S105
    assert len(env["REDIS_PASSWORD"]) >= 24
    assert len(env["SETTINGS_ENCRYPTION_KEY"]) >= 32
    assert env["SUCKERPOT_INSTALL_MODE"] == "source"
    values = [env[k] for k in env if k.endswith("_PASSWORD") and k != "POSTGRES_PASSWORD"]
    assert len(values) == len(set(values))
    assert "REDIS_PASSWORD" in proc.stdout
    for value in values:
        assert value not in proc.stdout
    assert stat.S_IMODE((sandbox.root / ".env").stat().st_mode) == 0o600


def test_migrate_never_invents_the_database_owner_password(sandbox: Sandbox) -> None:
    sandbox.write_env("COMPOSE_PROJECT_NAME=demo\n")
    proc = sandbox.run("scripts/env-migrate.sh")
    assert proc.returncode == 0, proc.stderr
    assert "POSTGRES_PASSWORD=" not in (sandbox.root / ".env").read_text()
    assert "POSTGRES_PASSWORD" in proc.stdout


def test_migrate_twice_changes_nothing_the_second_time(sandbox: Sandbox) -> None:
    sandbox.write_env(BASE_ENV)
    assert sandbox.run("scripts/env-migrate.sh").returncode == 0
    once = (sandbox.root / ".env").read_text()
    again = sandbox.run("scripts/env-migrate.sh")
    assert again.returncode == 0
    assert (sandbox.root / ".env").read_text() == once
    assert "added 0 variable(s)" in again.stdout


def test_lib_settable_patterns_match_the_design() -> None:
    text = (ROOT / "scripts/lib/env.sh").read_text()
    for pattern in ("'*_ENABLED'", "'*_HOST_PORT'", "DASHBOARD_BIND", "'SITE_*'", "'SENSOR_*'"):
        assert pattern in text

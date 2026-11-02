"""scripts/update.sh and scripts/rollback.sh, run against fake docker and git (see conftest.py)."""

import re
import stat
from collections.abc import Callable
from pathlib import Path

from conftest import ROOT, Sandbox

OLD = "a" * 40
NEW = "b" * 40

ENV = """\
COMPOSE_PROJECT_NAME=demo
SUCKERPOT_VOLUME_PREFIX=demo
SUCKERPOT_INSTALL_MODE=images
SUCKERPOT_VERSION=v0.8.0
DASHBOARD_PORT=8443
POSTGRES_PASSWORD=ownerpassword-aaaaaaaaaaaaaaaaaaaa
"""


def prepare(sb: Sandbox, mode: str = "images", branch: str = "") -> None:
    sb.write_env(ENV.replace("images", mode))
    sb.git_mode("normal")
    sb.git_set("head", OLD)
    sb.git_set("tagcommit", NEW)
    sb.git_set("describe", "v0.8.0")
    sb.git_set("tags", "v0.8.0\nv0.9.0\nv0.7.0\n")
    sb.git_set("notes", "Adds the setup wizard.")
    sb.git_set("branch", branch)
    sb.env["SHIM_RUNNING_VERSION"] = "v0.9.0"
    sb.env["SHIM_EXISTING_VOLUMES"] = "demo_backups"


def run_update(sb: Sandbox, *args: str, stdin: str = "") -> tuple[int, str]:
    proc = sb.run("scripts/update.sh", *args, stdin=stdin)
    return proc.returncode, proc.stdout + proc.stderr


def test_update_images_mode_full_flow(sandbox: Sandbox) -> None:
    prepare(sandbox)
    rc, out = run_update(sandbox, "--yes")
    assert rc == 0, out
    calls = sandbox.calls()
    joined = "\n".join(calls)
    assert "Adds the setup wizard." in out
    # Backup first, then code, then images, then start.
    order = [
        joined.index("backup-service.sh now preupdate"),
        joined.index("git checkout --quiet v0.9.0"),
        joined.index("cosign"),
        joined.index("docker compose up -d --no-build --pull never --wait --wait-timeout 600"),
    ]
    assert order == sorted(order)
    # Pulled by the digest cosign verified, then tagged; never pulled by tag.
    assert "docker pull --quiet ghcr.io/theroxat/suckerpot-api@sha256:" in joined
    assert "docker tag ghcr.io/theroxat/suckerpot-api@sha256:" in joined
    assert "docker compose pull --policy missing" in joined
    assert "docker compose pull\n" not in joined + "\n"
    assert re.search(r"SUCKERPOT_VERSION=v0\.9\.0", (sandbox.root / ".env").read_text())
    assert "# added by just update" in (sandbox.root / ".env").read_text()
    state = sandbox.root / ".suckerpot-state" / "last-update.json"
    assert stat.S_IMODE(state.stat().st_mode) == 0o600
    assert stat.S_IMODE(state.parent.stat().st_mode) == 0o700
    text = state.read_text()
    assert f'"from_ref": "{OLD}"' in text
    assert '"from_version": "v0.8.0"' in text
    assert '"dump": "suckerpot-preupdate-20261101T020000Z.dump"' in text
    assert '"mode": "images"' in text
    assert '"api": "sha256:0123456789abcdef"' in text
    assert "just rollback" in out


def test_update_takes_the_newest_tag_and_asks_to_confirm(sandbox: Sandbox) -> None:
    prepare(sandbox)
    rc, out = run_update(sandbox, stdin="n\n")
    assert rc != 0
    assert "target:  v0.9.0" in out
    assert not any("backup-service.sh" in c for c in sandbox.calls())
    assert not any(c.startswith("git checkout") for c in sandbox.calls())


def test_update_to_a_given_version(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.env["SHIM_RUNNING_VERSION"] = "v0.7.0"
    rc, out = run_update(sandbox, "--yes", "v0.7.0")
    assert rc == 0, out
    assert "git checkout --quiet v0.7.0" in sandbox.calls()


def test_update_refuses_an_unknown_or_malformed_version(sandbox: Sandbox) -> None:
    prepare(sandbox)
    assert run_update(sandbox, "--yes", "v9.9.9")[0] != 0
    assert run_update(sandbox, "--yes", "v1.2")[0] != 0
    assert not any(c.startswith("git checkout") for c in sandbox.calls())


def test_update_stops_when_the_backup_fails(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.env["SHIM_BACKUP_RC"] = "1"
    rc, out = run_update(sandbox, "--yes")
    assert rc != 0
    assert "nothing was changed" in out
    assert not any(c.startswith("git checkout") for c in sandbox.calls())
    assert (sandbox.root / ".env").read_text().count("v0.8.0") == 1


def test_update_needs_a_healthy_backup_service(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.env["SHIM_BACKUP_HEALTH"] = "unhealthy"
    rc, out = run_update(sandbox, "--yes")
    assert rc != 0
    assert "backup" in out
    assert not any("backup-service.sh now" in c for c in sandbox.calls())


def test_no_backup_needs_the_typed_phrase(sandbox: Sandbox) -> None:
    prepare(sandbox)
    rc, _ = run_update(sandbox, "--yes", "--no-backup", stdin="yes\n")
    assert rc != 0
    assert not any(c.startswith("git checkout") for c in sandbox.calls())
    rc, out = run_update(sandbox, "--yes", "--no-backup", stdin="no backup\n")
    assert rc == 0, out
    assert '"dump": ""' in (sandbox.root / ".suckerpot-state" / "last-update.json").read_text()


def test_source_mode_refuses_local_changes(sandbox: Sandbox) -> None:
    prepare(sandbox, mode="source")
    sandbox.git_set("dirty", " M docker-compose.yml\n")
    rc, out = run_update(sandbox, "--yes")
    assert rc != 0
    assert "local changes" in out
    assert not any("backup-service.sh" in c for c in sandbox.calls())


def test_source_mode_on_a_branch_pulls_fast_forward_only(sandbox: Sandbox) -> None:
    prepare(sandbox, mode="source", branch="main")
    sandbox.env["SHIM_RUNNING_VERSION"] = "v0.8.0"
    rc, out = run_update(sandbox, "--yes")
    assert rc == 0, out
    assert "git pull --ff-only --quiet" in sandbox.calls()
    assert "docker compose build" in sandbox.calls()
    assert "docker compose pull" not in sandbox.calls()


def test_failed_start_prints_the_rollback_and_never_rolls_back(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.env["SHIM_UP_RC"] = "1"
    rc, out = run_update(sandbox, "--yes")
    assert rc != 0
    assert "just rollback" in out
    assert "suckerpot-preupdate-20261101T020000Z.dump" in out
    calls = "\n".join(sandbox.calls())
    assert "restore" not in calls
    assert calls.count("git checkout") == 1


def test_wrong_running_version_is_a_failure(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.env["SHIM_RUNNING_VERSION"] = "v0.8.0"
    rc, out = run_update(sandbox, "--yes")
    assert rc != 0
    assert "reports version" in out


def test_update_refuses_worktrees_and_missing_names(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.git_mode("linked")
    assert run_update(sandbox, "--yes")[0] != 0
    sandbox.git_mode("normal")
    sandbox.write_env("DASHBOARD_PORT=8443\n")
    assert run_update(sandbox, "--yes")[0] != 0
    sandbox.write_env("COMPOSE_PROJECT_NAME=sp-test\nSUCKERPOT_VOLUME_PREFIX=sp-test\n")
    assert run_update(sandbox, "--yes")[0] != 0
    assert not any("backup-service.sh" in c for c in sandbox.calls())


# ------------------------------------------------------------------- rollback


def calls_of(sb: Sandbox) -> list[str]:
    return sb.calls()


def write_state(sb: Sandbox, dump: str = "suckerpot-preupdate-20261101T020000Z.dump") -> None:
    state = sb.root / ".suckerpot-state"
    state.mkdir(exist_ok=True)
    (state / "last-update.json").write_text(
        "{\n"
        '  "from_version": "v0.8.0",\n'
        f'  "from_ref": "{OLD}",\n'
        '  "from_branch": "",\n'
        '  "mode": "images",\n'
        f'  "dump": "{dump}",\n'
        '  "target": "v0.9.0",\n'
        '  "at": "2026-11-01T02:00:00Z",\n'
        '  "images": {\n  }\n}\n'
    )


def test_rollback_restores_code_images_and_dump(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.write_env(ENV.replace("v0.8.0", "v0.9.0"))
    write_state(sandbox)
    # restore-db.sh has its own tests and confirmation; here it is replaced by a recorder.
    (sandbox.root / "scripts" / "restore-db.sh").write_text('echo "restore-db $*" >> "$SHIM_LOG"\n')
    proc = sandbox.run("scripts/rollback.sh", stdin="rollback\n")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "restore-db volume:suckerpot-preupdate-20261101T020000Z.dump" in calls_of(sandbox)
    calls = sandbox.calls()
    joined = "\n".join(calls)
    assert f"git checkout --quiet {OLD}" in calls
    assert "SUCKERPOT_VERSION=v0.8.0" in (sandbox.root / ".env").read_text()
    assert "docker compose pull --policy missing" in calls
    order = [
        joined.index("git checkout"),
        joined.index("cosign"),
        joined.index("docker compose up -d --no-build --pull never --wait --wait-timeout 600"),
    ]
    assert order == sorted(order)
    assert "events received since that dump are lost" in proc.stdout.lower()


def test_rollback_needs_the_typed_word(sandbox: Sandbox) -> None:
    prepare(sandbox)
    write_state(sandbox)
    for answer in ("yes\n", "\n", "Rollback\n"):
        proc = sandbox.run("scripts/rollback.sh", stdin=answer)
        assert proc.returncode != 0
    assert not any(c.startswith("git checkout") for c in sandbox.calls())


def test_rollback_without_state_or_dump_does_nothing(sandbox: Sandbox) -> None:
    prepare(sandbox)
    assert sandbox.run("scripts/rollback.sh", stdin="rollback\n").returncode != 0
    write_state(sandbox, dump="")
    proc = sandbox.run("scripts/rollback.sh", stdin="rollback\n")
    assert proc.returncode != 0
    assert "no backup" in proc.stderr or "without a backup" in proc.stderr
    assert not any(c.startswith("git checkout") for c in sandbox.calls())


def test_rollback_rejects_a_tampered_dump_name(sandbox: Sandbox) -> None:
    prepare(sandbox)
    write_state(sandbox, dump="x;rm -rf /.dump")
    proc = sandbox.run("scripts/rollback.sh", stdin="rollback\n")
    assert proc.returncode != 0
    assert not sandbox.docker_calls()


def test_update_and_rollback_use_only_the_documented_commands(
    parse_env: Callable[[Path], dict[str, str]],
) -> None:
    """The scripts never remove volumes or data, and never run compose with a project override."""
    for rel in ("scripts/update.sh", "scripts/rollback.sh", "scripts/install.sh"):
        code = "\n".join(
            line
            for line in (ROOT / rel).read_text().splitlines()
            if not line.lstrip().startswith("#")
        )
        assert "down -v" not in code and "--volumes" not in code
        assert "volume rm" not in code and "volume prune" not in code
        assert "system prune" not in code
        assert not re.search(r"compose\s+(-p|--project-name)\b", code)


def test_update_ignores_stale_exported_values(sandbox: Sandbox) -> None:
    """`just` exports the OLD .env; the update must start the stack with the NEW file."""
    prepare(sandbox)
    sandbox.env["SUCKERPOT_VERSION"] = "v0.8.0"
    sandbox.env["DASHBOARD_PORT"] = "8443"
    rc, out = run_update(sandbox, "--yes")
    assert rc == 0, out
    up = [c for c in sandbox.calls() if c.startswith("ENV_AT_UP")]
    assert up and all("SUCKERPOT_VERSION=unset" in c and "DASHBOARD_PORT=unset" in c for c in up)
    assert "SUCKERPOT_VERSION=v0.9.0" in (sandbox.root / ".env").read_text()


def test_update_verifies_before_anything_runs_and_fails_closed(sandbox: Sandbox) -> None:
    prepare(sandbox)
    (sandbox.root / "scripts/verify-images.sh").write_text("#!/bin/sh\nexit 1\n")
    rc, out = run_update(sandbox, "--yes")
    assert rc != 0
    assert "signatures could not be verified" in out
    assert not any(c.startswith("docker compose up") for c in sandbox.docker_calls())
    rc, out = run_update(sandbox, "--yes", "--skip-verify", "--force")
    assert rc == 0, out
    assert "NOT checked" in out


def test_rollback_checks_the_dump_before_changing_anything(sandbox: Sandbox) -> None:
    prepare(sandbox)
    write_state(sandbox)
    sandbox.env["SHIM_DUMP_MISSING"] = "1"
    proc = sandbox.run("scripts/rollback.sh", stdin="rollback\n")
    assert proc.returncode != 0
    assert "no longer in the backups volume" in proc.stderr
    assert not any(c.startswith("git checkout") for c in sandbox.calls())
    assert not any(c.startswith("docker compose") for c in sandbox.docker_calls())
    assert "SUCKERPOT_VERSION=v0.8.0" in (sandbox.root / ".env").read_text()


def test_rollback_checks_ports_and_ignores_stale_values(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.write_env(ENV.replace("v0.8.0", "v0.9.0"))
    write_state(sandbox)
    (sandbox.root / "scripts" / "restore-db.sh").write_text("true\n")
    sandbox.env["SUCKERPOT_VERSION"] = "v0.9.0"
    proc = sandbox.run("scripts/rollback.sh", stdin="rollback\n")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "check-ports: ok" in proc.stdout
    up = [c for c in sandbox.calls() if c.startswith("ENV_AT_UP")]
    assert up and all("SUCKERPOT_VERSION=unset" in c for c in up)
    # A bad port layout in .env stops the rollback before the stack is started.
    sandbox.write_env(ENV.replace("v0.8.0", "v0.9.0") + "SSH_HOST_PORT=8443\n")
    proc = sandbox.run("scripts/rollback.sh", stdin="rollback\n")
    assert proc.returncode != 0


def test_rollback_refuses_unverifiable_images(sandbox: Sandbox) -> None:
    prepare(sandbox)
    write_state(sandbox)
    (sandbox.root / "scripts" / "restore-db.sh").write_text("true\n")
    (sandbox.root / "scripts/verify-images.sh").write_text("#!/bin/sh\nexit 1\n")
    proc = sandbox.run("scripts/rollback.sh", stdin="rollback\n")
    assert proc.returncode != 0
    assert "could not be verified" in proc.stderr
    assert not any(c.startswith("docker compose up") for c in sandbox.docker_calls())


def test_rollback_never_lets_docker_create_the_backups_volume(sandbox: Sandbox) -> None:
    prepare(sandbox)
    write_state(sandbox)
    sandbox.env["SHIM_EXISTING_VOLUMES"] = ""
    proc = sandbox.run("scripts/rollback.sh", stdin="rollback\n")
    assert proc.returncode != 0
    assert "does not exist" in proc.stderr
    assert not any(c.startswith("docker run") for c in sandbox.docker_calls())


def test_unfinished_update_blocks_a_new_one_unless_forced(sandbox: Sandbox) -> None:
    prepare(sandbox)
    rc, out = run_update(sandbox, "--yes")
    assert rc == 0, out
    state = sandbox.root / ".suckerpot-state" / "last-update.json"
    assert '"completed": true' in state.read_text()
    state.write_text(state.read_text().replace('"completed": true', '"completed": false'))
    rc, out = run_update(sandbox, "--yes")
    assert rc != 0
    assert "never finished" in out
    rc, out = run_update(sandbox, "--yes", "--force")
    assert "never finished" not in out

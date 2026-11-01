"""scripts/install.sh: what it writes, what it refuses, and that it never looks up an address.

Every run happens in the sandbox of conftest.py (fake docker, git, curl, ss on PATH).
"""

import re
import stat
from collections.abc import Callable
from pathlib import Path

from conftest import ROOT, Sandbox, is_real_docker_untouched

SECRET_NAMES = [
    line.strip()
    for line in (ROOT / "scripts/lib/env.sh")
    .read_text()
    .split("SECRET_VARS=(", 1)[1]
    .split(")", 1)[0]
    .split()
]
PASSWORD = "correct horse battery"  # noqa: S105
ALL_IFACES = "0.0.0.0"  # noqa: S104


def dry_run(
    sb: Sandbox, *extra: str, out: str = "out.env", stdin: str | None = None
) -> tuple[Path, int, str]:
    target = sb.root / out
    proc = sb.run(
        "scripts/install.sh",
        "--yes",
        "--dry-run",
        "--env-out",
        str(target),
        "--sensors",
        "ssh,web",
        "--admin-password-stdin",
        *extra,
        stdin=PASSWORD + "\n" if stdin is None else stdin,
    )
    return target, proc.returncode, proc.stdout + proc.stderr


def test_only_the_fake_docker_is_reachable(sandbox: Sandbox) -> None:
    assert is_real_docker_untouched(sandbox)


def test_secret_list_matches_env_example() -> None:
    example = (ROOT / ".env.example").read_text()
    assert len(SECRET_NAMES) >= 20
    for name in SECRET_NAMES:
        assert re.search(rf"^{name}=", example, re.MULTILINE), name


def test_dry_run_writes_a_complete_env(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    target, rc, out = dry_run(sandbox)
    assert rc == 0, out
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    env = parse_env(target)
    values = []
    for name in SECRET_NAMES:
        assert len(env[name]) >= 24, name
        values.append(env[name])
    assert len(set(values)) == len(values), "secrets must be pairwise different"
    assert len(env["SESSION_SECRET"]) >= 64
    assert "change-me" not in "\n".join(
        line for line in target.read_text().splitlines() if not line.startswith("#")
    )
    assert env["COMPOSE_PROJECT_NAME"] == "suckerpot"
    assert env["SUCKERPOT_VOLUME_PREFIX"] == "suckerpot"
    assert env["SENSOR_SSH"] == "1"
    assert env["SENSOR_WEB"] == "1"
    assert env["SENSOR_TELNET"] == "0"
    assert env["COMPOSE_PROFILES"] == "egress"
    assert env["COOKIE_SECURE"] == "true"
    assert env["DASHBOARD_BIND"] == "127.0.0.1"
    assert re.fullmatch(r"'\$argon2[^']+'", env["ADMIN_PASSWORD_HASH"])
    # The password is never written, and nothing was run.
    assert PASSWORD not in target.read_text()
    assert sandbox.docker_calls() == []
    assert not (sandbox.root / ".env").exists()
    assert not (sandbox.root / "install.log").exists()


def test_dry_run_secrets_differ_between_runs(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    a, rc_a, _ = dry_run(sandbox, out="a.env")
    b, rc_b, _ = dry_run(sandbox, out="b.env")
    assert rc_a == rc_b == 0
    assert parse_env(a)["POSTGRES_PASSWORD"] != parse_env(b)["POSTGRES_PASSWORD"]


def test_https_tunnel_sets_hosts_origins_and_secure_cookie(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    target, rc, out = dry_run(
        sandbox, "--public-host", "dash.example.org", "--project", "demo", "--prefix", "demo-data"
    )
    assert rc == 0, out
    env = parse_env(target)
    assert env["API_ALLOWED_HOSTS"] == "dash.example.org"
    assert env["API_ALLOWED_ORIGINS"] == "https://dash.example.org"
    assert env["COOKIE_SECURE"] == "true"
    assert env["COMPOSE_PROJECT_NAME"] == "demo"
    assert env["SUCKERPOT_VOLUME_PREFIX"] == "demo-data"


def test_wireguard_file_is_parsed_without_printing_keys(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    conf = sandbox.root / "wg.conf"
    conf.write_text(
        "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
        "Address = 198.51.100.2/32\nDNS = 198.51.100.1\n"
        "[Peer]\nPublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n"
        "Endpoint = 198.51.100.7:51820\nAllowedIPs = 0.0.0.0/0\n"
    )
    target, rc, out = dry_run(sandbox, "--wg-conf", str(conf))
    assert rc == 0, out
    env = parse_env(target)
    assert env["VPN_WG_ENDPOINT_IP"] == "198.51.100.7"
    assert env["VPN_WG_ENDPOINT_PORT"] == "51820"
    assert env["VPN_WG_ADDRESSES"] == "198.51.100.2/32"
    assert env["VPN_WG_PRIVATE_KEY"].startswith("AAAAAAAA")
    assert "AAAAAAAAAAAAAAAA" not in out


def test_wireguard_hostname_endpoint_is_refused(sandbox: Sandbox) -> None:
    conf = sandbox.root / "wg.conf"
    conf.write_text(
        "[Interface]\nPrivateKey = a\nAddress = 198.51.100.2/32\n"
        "[Peer]\nPublicKey = b\nEndpoint = vpn.example.org:51820\n"
    )
    _, rc, out = dry_run(sandbox, "--wg-conf", str(conf))
    assert rc != 0
    assert "IPv4" in out


def test_refuses_when_env_exists(sandbox: Sandbox) -> None:
    sandbox.write_env("COMPOSE_PROJECT_NAME=suckerpot\n")
    before = (sandbox.root / ".env").read_text()
    target, rc, out = dry_run(sandbox)
    assert rc != 0
    assert "already installed" in out
    assert not target.exists()
    assert (sandbox.root / ".env").read_text() == before


def test_refuses_to_overwrite_an_existing_env_out(sandbox: Sandbox) -> None:
    (sandbox.root / "out.env").write_text("keep\n")
    _, rc, _ = dry_run(sandbox)
    assert rc != 0
    assert (sandbox.root / "out.env").read_text() == "keep\n"


def test_refuses_throwaway_and_bad_names(sandbox: Sandbox) -> None:
    for name in ("sp-it-abc123-1", "sp-test", "sp-ci", "Bad Name", "-lead", "UPPER", "a" * 42):
        for flag in ("--project", "--prefix"):
            args = (flag, name) if flag == "--project" else ("--project", "okname", flag, name)
            target, rc, out = dry_run(sandbox, *args, out=f"n{abs(hash((name, flag)))}.env")
            assert rc != 0, (flag, name, out)
            assert not target.exists()


def test_refuses_a_linked_worktree(sandbox: Sandbox) -> None:
    sandbox.git_mode("linked")
    target, rc, out = dry_run(sandbox)
    assert rc != 0
    assert "worktree" in out
    assert not target.exists()


def test_normal_git_checkout_is_accepted(sandbox: Sandbox) -> None:
    sandbox.git_mode("normal")
    _, rc, out = dry_run(sandbox)
    assert rc == 0, out


def test_refuses_unknown_sensor_and_short_password(sandbox: Sandbox) -> None:
    _, rc, out = dry_run(sandbox, "--sensors", "ssh,nope")
    assert rc != 0
    assert "unknown sensor" in out
    _, rc, out = dry_run(sandbox, stdin="short\n")
    assert rc != 0
    assert "12 characters" in out


def test_dry_run_requires_env_out(sandbox: Sandbox) -> None:
    proc = sandbox.run("scripts/install.sh", "--yes", "--dry-run")
    assert proc.returncode != 0


def test_interactive_answers_come_from_the_terminal(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    answers = sandbox.root / "answers"
    # mode, sensors, access, admin user, password x2, wireguard, public address
    answers.write_text("source\nssh,telnet\nl\nowner\n" + PASSWORD + "\n" + PASSWORD + "\n\n\n")
    target = sandbox.root / "i.env"
    proc = sandbox.run(
        "scripts/install.sh",
        "--dry-run",
        "--env-out",
        str(target),
        extra_env={"SELFHOSTR_TTY": str(answers)},
    )
    assert proc.returncode == 0, proc.stderr
    env = parse_env(target)
    assert env["ADMIN_USERNAME"] == "owner"
    assert env["SENSOR_TELNET"] == "1"
    assert env["SENSOR_WEB"] == "0"
    assert env["SUCKERPOT_INSTALL_MODE"] == "source"
    assert PASSWORD not in proc.stdout + proc.stderr


def _real_run(sb: Sandbox, *extra: str, stdin: str = PASSWORD + "\n") -> tuple[int, str]:
    proc = sb.run(
        "scripts/install.sh",
        "--yes",
        "--images",
        "--version",
        "v0.8.0",
        "--sensors",
        "ssh,web",
        "--admin-password-stdin",
        *extra,
        stdin=stdin,
    )
    return proc.returncode, proc.stdout + proc.stderr


def test_full_install_with_fake_docker(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    rc, out = _real_run(sandbox)
    assert rc == 0, out
    env_path = sandbox.root / ".env"
    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600
    env = parse_env(env_path)
    assert env["SUCKERPOT_INSTALL_MODE"] == "images"
    assert env["SUCKERPOT_VERSION"] == "v0.8.0"
    assert env["ADMIN_PASSWORD_HASH"].startswith("'$argon2")
    calls = "\n".join(sandbox.calls())
    # The password reached the hasher on stdin only.
    assert (sandbox.shim / "hash-stdin").read_text() == PASSWORD + "\n"
    assert PASSWORD not in calls
    assert PASSWORD not in out
    for name in SECRET_NAMES:
        assert env[name] not in calls
        assert env[name] not in out
    assert "docker pull ghcr.io/theroxat/suckerpot-api:v0.8.0" in calls
    assert "--network none" in calls
    assert "docker volume create suckerpot_db-data" in calls
    assert "docker compose pull" in calls
    assert "docker compose up -d --wait --wait-timeout 600" in calls
    assert "curl -fsS --max-time 5 http://127.0.0.1:8443/healthz" in calls
    log = (sandbox.root / "install.log").read_text()
    assert PASSWORD not in log
    assert all(env[name] not in log for name in SECRET_NAMES)
    # Nothing outside the shims was reached, and no compose call names a stack other than .env's.
    assert " -p " not in calls


def test_full_install_generates_and_prints_the_password_once(sandbox: Sandbox) -> None:
    proc = sandbox.run(
        "scripts/install.sh", "--yes", "--images", "--version", "v0.8.0", "--sensors", "ssh"
    )
    assert proc.returncode == 0, proc.stderr
    printed = re.findall(r"password .*: (\S+)", proc.stdout)
    assert len(printed) == 1
    assert len(printed[0]) >= 20
    assert printed[0] not in "\n".join(sandbox.calls())
    assert (sandbox.shim / "hash-stdin").read_text() == printed[0] + "\n"


def test_install_refuses_existing_volumes_and_adopts_nothing(sandbox: Sandbox) -> None:
    sandbox.env["SHIM_EXISTING_VOLUMES"] = "suckerpot_db-data"
    rc, out = _real_run(sandbox)
    assert rc != 0
    assert "already exist" in out
    assert not (sandbox.root / ".env").exists()
    assert not any(c.startswith("docker volume create") for c in sandbox.docker_calls())


def test_install_refuses_any_volume_of_the_prefix(sandbox: Sandbox) -> None:
    sandbox.env["SHIM_EXISTING_VOLUMES"] = "suckerpot_backups"
    rc, out = _real_run(sandbox)
    assert rc != 0
    assert "already exist" in out
    assert not (sandbox.root / ".env").exists()


def test_install_refuses_existing_containers_of_the_project(sandbox: Sandbox) -> None:
    sandbox.env["SHIM_PROJECT_CONTAINERS"] = "0123456789ab"
    rc, out = _real_run(sandbox)
    assert rc != 0
    assert "Containers of the compose project" in out
    assert not (sandbox.root / ".env").exists()


def test_install_refuses_low_memory_and_low_disk(sandbox: Sandbox) -> None:
    (sandbox.shim / "meminfo").write_text("MemTotal:        1000000 kB\n")
    rc, out = _real_run(sandbox)
    assert rc != 0
    assert "2 GiB" in out
    (sandbox.shim / "meminfo").write_text("MemTotal:        8000000 kB\n")
    sandbox.env["SELFHOSTR_FREE_DISK_KB"] = str(5 * 1024 * 1024)
    rc, out = _real_run(sandbox)
    assert rc != 0
    assert "15 GiB" in out
    assert not (sandbox.root / ".env").exists()


def test_busy_ssh_port_is_mapped_to_2222_and_admin_port_protected(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    (sandbox.shim / "ss-output").write_text(
        "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 128 [::]:22 [::]:*\n"
    )
    rc, out = _real_run(sandbox)
    assert rc == 0, out
    env = parse_env(sandbox.root / ".env")
    assert env["SSH_HOST_PORT"] == "2222"
    assert env["ADMIN_SSH_PORT"] == "22"
    assert env["SENSOR_SSH"] == "1"


def test_other_busy_port_turns_that_sensor_off(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    (sandbox.shim / "ss-output").write_text("tcp LISTEN 0 128 0.0.0.0:80 0.0.0.0:*\n")
    rc, out = _real_run(sandbox)
    assert rc == 0, out
    assert "web sensor is left off" in out
    assert parse_env(sandbox.root / ".env")["SENSOR_WEB"] == "0"


def test_lowmem_overlay_goes_into_compose_file(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    rc, out = _real_run(sandbox, "--lowmem", "on")
    assert rc != 0 and "docker-compose.lowmem.yml" in out
    (sandbox.root / "docker-compose.lowmem.yml").write_text("services: {}\n")
    rc, out = _real_run(sandbox, "--lowmem", "on")
    assert rc == 0, out
    env = parse_env(sandbox.root / ".env")
    assert env["COMPOSE_FILE"] == "docker-compose.yml:docker-compose.lowmem.yml"


def test_source_mode_builds_here(sandbox: Sandbox) -> None:
    proc = sandbox.run(
        "scripts/install.sh",
        "--yes",
        "--source",
        "--sensors",
        "ssh",
        "--admin-password-stdin",
        stdin=PASSWORD + "\n",
    )
    assert proc.returncode == 0, proc.stderr
    calls = "\n".join(sandbox.calls())
    assert "docker build -q -f api/Dockerfile -t suckerpot-install-api ." in calls
    assert "docker compose up -d --build --wait --wait-timeout 900" in calls
    assert "docker compose pull" not in calls


def test_a_failed_start_stops_with_a_named_reason(sandbox: Sandbox) -> None:
    sandbox.env["SHIM_UP_RC"] = "1"
    rc, out = _real_run(sandbox)
    assert rc != 0
    assert "did not become healthy" in out


def test_script_never_looks_up_a_public_address() -> None:
    forbidden = ("ipify", "icanhazip", "ifconfig.me", "checkip", "ipinfo", "myip", "wget", "nc ")
    for rel in (
        "scripts/install.sh",
        "scripts/update.sh",
        "scripts/rollback.sh",
        "scripts/lib/env.sh",
    ):
        text = (ROOT / rel).read_text()
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        for word in forbidden:
            assert word not in code, (rel, word)
        for line in code.splitlines():
            if re.search(r"\bcurl\b", line):
                assert "healthz" in line, (rel, line)
                assert re.search(r"http://(\$hbind|\$bind|127\.0\.0\.1)", line), (rel, line)


def test_images_install_verifies_signatures_after_the_pull(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    rc, out = _real_run(sandbox)
    assert rc == 0, out
    calls = sandbox.docker_calls()
    pull = next(i for i, c in enumerate(calls) if c == "docker compose pull")
    verify = next(i for i, c in enumerate(calls) if "cosign" in c and " verify " in c)
    up = next(i for i, c in enumerate(calls) if c.startswith("docker compose up"))
    assert pull < verify < up
    env = parse_env(sandbox.root / ".env")
    assert env["SUCKERPOT_IMAGE_PREFIX"].startswith("ghcr.io/")
    assert env["UPDATE_CHECK_ENABLED"] == "false"


def test_failed_signature_check_starts_nothing(sandbox: Sandbox) -> None:
    (sandbox.root / "scripts/verify-images.sh").write_text("#!/bin/sh\nexit 1\n")
    rc, out = _real_run(sandbox)
    assert rc != 0
    assert "signatures could not be verified" in out
    assert not any(c.startswith("docker compose up") for c in sandbox.docker_calls())


def test_skip_verify_is_explicit_and_loud(sandbox: Sandbox) -> None:
    (sandbox.root / "scripts/verify-images.sh").write_text("#!/bin/sh\nexit 1\n")
    rc, out = _real_run(sandbox, "--skip-verify")
    assert rc == 0, out
    assert "NOT checked" in out


def test_lan_bind_needs_a_tunnel_or_an_explicit_flag(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    _, rc, out = dry_run(sandbox, "--dashboard-bind", ALL_IFACES)
    assert rc != 0
    assert "--allow-lan" in out
    target, rc, out = dry_run(sandbox, "--dashboard-bind", ALL_IFACES, "--allow-lan")
    assert rc == 0, out
    assert parse_env(target)["COOKIE_SECURE"] == "false"
    target, rc, out = dry_run(
        sandbox, "--dashboard-bind", ALL_IFACES, "--public-host", "dash.example.org", out="b.env"
    )
    assert rc == 0, out
    assert parse_env(target)["COOKIE_SECURE"] == "true"


def test_a_failed_install_leaves_no_temporary_env(sandbox: Sandbox) -> None:
    sandbox.env["SHIM_PROJECT_CONTAINERS"] = "0123456789ab"
    _real_run(sandbox)
    assert not list(sandbox.root.glob(".env*.tmp")) and not (sandbox.root / ".env.tmp").exists()

"""Update and rollback when Docker cannot change an existing network: one recreate, never `-v`."""

import pytest
from conftest import Sandbox
from test_update import ENV, prepare, run_update, write_state

UP = "docker compose up -d --no-build --pull never --wait --wait-timeout 600"

# The first `up` fails like compose does when a bridge must change; `down` and the second `up`
# are scripted by environment variables.
WRAPPER = r"""#!/bin/sh
case "$*" in
  "compose up "*)
    echo "docker $*" >> "$SHIM_LOG"
    n=$(cat "$SHIM_DIR/up-count" 2>/dev/null || echo 0)
    n=$((n + 1)); echo "$n" > "$SHIM_DIR/up-count"
    if [ "$n" = 1 ] && [ -n "${SHIM_UP1_ERR:-}" ]; then echo "$SHIM_UP1_ERR" >&2; exit 1; fi
    if [ "$n" = 2 ] && [ -n "${SHIM_UP2_FAIL:-}" ]; then echo "unrelated failure" >&2; exit 1; fi
    exit 0 ;;
  "compose down"*)
    echo "docker $*" >> "$SHIM_LOG"
    if [ -n "${SHIM_DOWN_ERR:-}" ]; then echo "$SHIM_DOWN_ERR" >&2; exit 1; fi
    exit 0 ;;
  "network ls "*) echo "demo_sp-ingress"; exit 0 ;;
  "network inspect "*) echo "someone-elses-container "; exit 0 ;;
esac
exec "$SHIM_DIR/docker-base" "$@"
"""

NET_ERR = "Error response from daemon: network demo_sp-ingress needs to be recreated"


def wrap(sb: Sandbox) -> None:
    docker = sb.shim / "docker"
    docker.rename(sb.shim / "docker-base")
    docker.write_text(WRAPPER)
    docker.chmod(0o755)


def test_update_recreates_the_stack_once_when_a_network_must_change(sandbox: Sandbox) -> None:
    prepare(sandbox)
    wrap(sandbox)
    sandbox.env["SHIM_UP1_ERR"] = NET_ERR
    rc, out = run_update(sandbox, "--yes")
    assert rc == 0, out
    calls = sandbox.calls()
    assert calls.count(UP) == 2
    assert "docker compose down --remove-orphans" in calls
    assert calls.index(UP) < calls.index("docker compose down --remove-orphans")
    assert "data volumes are kept" in out


def test_an_unrelated_failure_is_not_retried(sandbox: Sandbox) -> None:
    prepare(sandbox)
    wrap(sandbox)
    sandbox.env["SHIM_UP1_ERR"] = "service api is unhealthy"
    rc, _ = run_update(sandbox, "--yes")
    assert rc != 0
    assert not any("compose down" in c for c in sandbox.calls())
    assert sandbox.calls().count(UP) == 1


def test_lines_that_only_mention_networks_do_not_trigger_a_down(sandbox: Sandbox) -> None:
    prepare(sandbox)
    wrap(sandbox)
    sandbox.env["SHIM_UP1_ERR"] = (
        " Network demo_sp-backend Created\n Network demo_sp-ingress Created\n"
        " Container demo-migrate-1 Error\ndependency failed to start: container migrate exited (1)"
    )
    rc, _ = run_update(sandbox, "--yes")
    assert rc != 0
    assert not any("compose down" in c for c in sandbox.calls())
    assert sandbox.calls().count(UP) == 1


@pytest.mark.parametrize(
    "wording",
    [
        "Network demo_sp-ingress needs to be recreated - option gateway_mode_ipv4 has changed",
        "failed to remove network demo_sp-ingress: network has active endpoints",
        "network demo_sp-ingress was found but has incorrect label com.docker.compose.network",
        "network sp-hubgate declared as external, but could not be found",
        "network demo_sp-ingress: config for the network changed",
    ],
)
def test_compose_wordings_that_ask_for_a_recreate(sandbox: Sandbox, wording: str) -> None:
    prepare(sandbox)
    wrap(sandbox)
    sandbox.env["SHIM_UP1_ERR"] = wording
    rc, out = run_update(sandbox, "--yes")
    assert rc == 0, out
    assert "docker compose down --remove-orphans" in sandbox.calls()


def test_it_recreates_only_once(sandbox: Sandbox) -> None:
    prepare(sandbox)
    wrap(sandbox)
    sandbox.env["SHIM_UP1_ERR"] = NET_ERR
    sandbox.env["SHIM_UP2_FAIL"] = "1"
    rc, _ = run_update(sandbox, "--yes")
    assert rc != 0
    calls = sandbox.calls()
    assert calls.count(UP) == 2
    assert calls.count("docker compose down --remove-orphans") == 1


def test_a_foreign_container_stops_the_update_and_is_never_disconnected(
    sandbox: Sandbox,
) -> None:
    prepare(sandbox)
    wrap(sandbox)
    sandbox.env["SHIM_UP1_ERR"] = NET_ERR
    sandbox.env["SHIM_DOWN_ERR"] = "network demo_sp-ingress has active endpoints"
    rc, out = run_update(sandbox, "--yes")
    assert rc != 0
    assert "network demo_sp-ingress still has containers" in out
    assert "docker network disconnect demo_sp-ingress someone-elses-container" in out
    calls = sandbox.calls()
    assert calls.count(UP) == 1
    assert not any(c.startswith("docker network disconnect") for c in calls)


def test_rollback_recreates_the_stack_too(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.write_env(ENV.replace("v0.8.0", "v0.9.0"))
    write_state(sandbox)
    (sandbox.root / "scripts" / "restore-db.sh").write_text('echo "restore-db $*" >> "$SHIM_LOG"\n')
    wrap(sandbox)
    sandbox.env["SHIM_UP1_ERR"] = NET_ERR
    proc = sandbox.run("scripts/rollback.sh", stdin="rollback\n")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    calls = sandbox.calls()
    assert calls.count(UP) == 2 and "docker compose down --remove-orphans" in calls
    assert not any(" -v" in c for c in calls if "compose down" in c)

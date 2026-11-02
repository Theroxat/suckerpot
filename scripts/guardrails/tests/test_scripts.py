"""Shell guards of M28: sensor switches in check-ports.sh, the all-or-nothing VPN variables and the
idle mode of the vpn entrypoint."""

import shutil
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
PATH = "/usr/local/bin:/usr/bin:/bin"


@pytest.fixture
def scripts(tmp_path: Path) -> Path:
    """A copy of the scripts in a folder without a .env, so only the given variables count."""
    dest = tmp_path / "scripts"
    dest.mkdir()
    for name in ("check-ports.sh", "check-vpn-env.sh"):
        shutil.copy(ROOT / "scripts" / name, dest / name)
    return dest


def _run(script: Path, **env: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["/bin/sh", str(script)],
        env={"PATH": PATH, **env},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_ports_default_layout_is_ok(scripts: Path) -> None:
    assert _run(scripts / "check-ports.sh").returncode == 0


def test_ports_switch_must_be_zero_or_one(scripts: Path) -> None:
    result = _run(scripts / "check-ports.sh", SENSOR_SSH="2")
    assert result.returncode == 1
    assert "SENSOR_SSH must be 0 or 1" in result.stderr


def test_ports_clash_is_checked_between_enabled_sensors(scripts: Path) -> None:
    result = _run(scripts / "check-ports.sh", SSH_HOST_PORT="2323", TELNET_HOST_PORT="2323")
    assert result.returncode == 1
    assert "both use port 2323" in result.stderr


def test_ports_disabled_sensor_takes_no_part_in_clashes(scripts: Path) -> None:
    result = _run(
        scripts / "check-ports.sh", SENSOR_SSH="0", SSH_HOST_PORT="2323", TELNET_HOST_PORT="2323"
    )
    assert result.returncode == 0, result.stderr


def test_ports_disabled_sensor_takes_no_part_in_the_admin_check(scripts: Path) -> None:
    refused = _run(scripts / "check-ports.sh", ADMIN_SSH_PORT="22")
    assert refused.returncode == 1
    allowed = _run(scripts / "check-ports.sh", ADMIN_SSH_PORT="22", SENSOR_SSH="0")
    assert allowed.returncode == 0, allowed.stderr


@pytest.mark.parametrize("port", ["22", "23", "80", "443", "5555", "5001"])
def test_dashboard_is_refused_on_a_sensor_port_even_when_that_sensor_is_off(
    scripts: Path, port: str
) -> None:
    result = _run(
        scripts / "check-ports.sh",
        DASHBOARD_PORT=port,
        SENSOR_SSH="0",
        SENSOR_TELNET="0",
        SENSOR_WEB="0",
        SENSOR_ADB="0",
        SENSOR_SYNOLOGY="0",
    )
    assert result.returncode == 1
    assert "is a service port" in result.stderr


def test_dashboard_clash_with_an_enabled_sensor_host_port(scripts: Path) -> None:
    result = _run(scripts / "check-ports.sh", DASHBOARD_PORT="9000", SSH_HOST_PORT="9000")
    assert result.returncode == 1


PROFILE = {"COMPOSE_PROFILES": "egress"}
PASSWORDS = {
    "EGRESS_PROXY_PASSWORD": "a" * 24,
    "POSTGRES_COLLECTOR_PASSWORD": "b" * 24,
    "POSTGRES_ANALYZER_PASSWORD": "c" * 24,
}
WG = {
    "VPN_WG_PRIVATE_KEY": "k" * 43 + "=",
    "VPN_WG_ADDRESSES": "198.51.100.2/32",
    "VPN_WG_PEER_PUBLIC_KEY": "p" * 43 + "=",
    "VPN_WG_ENDPOINT_IP": "8.8.4.4",
    "VPN_WG_ENDPOINT_PORT": "51820",
}


def test_vpn_env_all_wireguard_values_empty_is_accepted(scripts: Path) -> None:
    result = _run(scripts / "check-vpn-env.sh", **PROFILE, **PASSWORDS)
    assert result.returncode == 0, result.stderr


def test_vpn_env_complete_set_is_accepted(scripts: Path) -> None:
    result = _run(scripts / "check-vpn-env.sh", **PROFILE, **PASSWORDS, **WG)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("missing", sorted(WG))
def test_vpn_env_partial_set_is_refused(scripts: Path, missing: str) -> None:
    env = {k: v for k, v in WG.items() if k != missing}
    result = _run(scripts / "check-vpn-env.sh", **PROFILE, **PASSWORDS, **env)
    assert result.returncode == 1
    assert missing in result.stderr
    assert WG["VPN_WG_PRIVATE_KEY"] not in result.stderr


def test_vpn_env_idle_install_still_needs_strong_passwords(scripts: Path) -> None:
    weak = {**PASSWORDS, "EGRESS_PROXY_PASSWORD": "short"}
    result = _run(scripts / "check-vpn-env.sh", **PROFILE, **weak)
    assert result.returncode == 1


def test_vpn_env_without_the_profile_is_skipped(scripts: Path) -> None:
    assert _run(scripts / "check-vpn-env.sh").returncode == 0


# --- vpn idle mode -------------------------------------------------------------------------


def _fake_gluetun(tmp_path: Path) -> Path:
    fake = tmp_path / "gluetun"
    fake.write_text(f"#!/bin/sh\necho started > {tmp_path}/started\nsleep 30\n", encoding="utf-8")
    fake.chmod(0o755)
    return fake


def _entrypoint(tmp_path: Path, **env: str) -> subprocess.Popen[str]:
    conf = tmp_path / "conf"
    conf.mkdir(exist_ok=True)
    return subprocess.Popen(  # noqa: S603
        ["/bin/sh", str(ROOT / "vpn" / "entrypoint.sh")],
        env={
            "PATH": PATH,
            "VPN_CONFIG_DIR": str(conf),
            "VPN_GLUETUN_BIN": str(_fake_gluetun(tmp_path)),
            "VPN_SNAPSHOT": str(tmp_path / "snapshot"),
            "VPN_IDLE_MARKER": str(tmp_path / "idle"),
            "VPN_IDLE_INTERVAL": "1",
            **env,
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _wait_for(path: Path, seconds: float = 5.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if path.exists():
            return True
        time.sleep(0.05)
    return path.exists()


def test_idle_mode_starts_nothing_and_leaves_when_wg_env_appears(tmp_path: Path) -> None:
    proc = _entrypoint(tmp_path)
    try:
        assert _wait_for(tmp_path / "idle")
        time.sleep(1.5)
        assert proc.poll() is None  # still waiting
        assert not (tmp_path / "started").exists()  # gluetun never ran
        (tmp_path / "conf" / "wg.env").write_text("x\n", encoding="utf-8")
        assert proc.wait(timeout=10) == 0  # restart path
    finally:
        if proc.poll() is None:
            proc.kill()
    assert not (tmp_path / "idle").exists()
    assert not (tmp_path / "started").exists()
    assert "no VPN configuration yet; waiting" in (proc.stderr.read() if proc.stderr else "")


def test_idle_mode_marker_is_removed_on_termination(tmp_path: Path) -> None:
    proc = _entrypoint(tmp_path)
    try:
        assert _wait_for(tmp_path / "idle")
        proc.terminate()
        assert proc.wait(timeout=10) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
    assert not (tmp_path / "idle").exists()


def test_env_values_present_do_not_trigger_idle_mode(tmp_path: Path) -> None:
    proc = _entrypoint(tmp_path, WIREGUARD_PRIVATE_KEY="k" * 43 + "=", WIREGUARD_ADDRESSES="")
    try:
        assert _wait_for(tmp_path / "started")
        assert not (tmp_path / "idle").exists()
    finally:
        proc.kill()


COMPOSE_AND_IMAGE_DEFAULTS = {
    "VPN_SERVICE_PROVIDER": "custom",
    "VPN_TYPE": "wireguard",
    "WIREGUARD_IMPLEMENTATION": "userspace",
    "WIREGUARD_PERSISTENT_KEEPALIVE_INTERVAL": "25s",
    "WIREGUARD_PRIVATE_KEY": "",
    "WIREGUARD_PUBLIC_KEY": "",
    "WIREGUARD_ADDRESSES": "",
    "WIREGUARD_ENDPOINT_IP": "",
    "WIREGUARD_ENDPOINT_PORT": "",
    "WIREGUARD_MTU": "1400",
    "WIREGUARD_PRIVATE_KEY_SECRETFILE": "/run/secrets/wireguard_private_key",
    "WIREGUARD_PRESHARED_KEY_SECRETFILE": "/run/secrets/wireguard_preshared_key",
    "WIREGUARD_ADDRESSES_SECRETFILE": "/run/secrets/wireguard_addresses",
}


def test_compose_env_and_image_defaults_still_go_idle(tmp_path: Path) -> None:
    proc = _entrypoint(tmp_path, **COMPOSE_AND_IMAGE_DEFAULTS)
    try:
        assert _wait_for(tmp_path / "idle")
        time.sleep(1.2)
        assert proc.poll() is None
        assert not (tmp_path / "started").exists()
    finally:
        proc.kill()


def test_compose_env_with_keys_set_is_not_idle(tmp_path: Path) -> None:
    env = {**COMPOSE_AND_IMAGE_DEFAULTS, "WIREGUARD_PRIVATE_KEY": "k" * 43 + "="}
    proc = _entrypoint(tmp_path, **env)
    try:
        assert _wait_for(tmp_path / "started")
        assert not (tmp_path / "idle").exists()
    finally:
        proc.kill()


def test_invalid_uploaded_file_is_not_idle_and_fails_closed(tmp_path: Path) -> None:
    conf = tmp_path / "conf"
    conf.mkdir()
    (conf / "wg.env").write_text("anything\n", encoding="utf-8")
    proc = _entrypoint(tmp_path)
    assert proc.wait(timeout=10) == 1
    assert not (tmp_path / "idle").exists()
    assert not (tmp_path / "started").exists()


def test_health_script_is_healthy_only_in_idle_mode_or_when_gluetun_is(tmp_path: Path) -> None:
    marker = tmp_path / "idle"
    gluetun = tmp_path / "gluetun-health"
    gluetun.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    gluetun.chmod(0o755)
    env = {"PATH": PATH, "VPN_IDLE_MARKER": str(marker), "VPN_GLUETUN_BIN": str(gluetun)}
    health = ["/bin/sh", str(ROOT / "vpn" / "health.sh")]

    def code() -> int:
        return subprocess.run(health, env=env, capture_output=True, check=False).returncode  # noqa: S603

    assert code() == 1  # no marker: gluetun's own check decides (here: unhealthy)
    marker.write_text("", encoding="utf-8")
    assert code() == 0

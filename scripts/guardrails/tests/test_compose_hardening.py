"""The generic hardening rule and the network isolation rules: each one bites on a broken copy."""

import copy
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from suckerpot_guardrails import (
    check_bridge_names,
    check_compose,
    check_hardening,
    check_top_level,
    load_compose,
)
from suckerpot_guardrails.compose import BRIDGE_NAMES, MAX_BRIDGE_NAME

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "docker-compose.yml"
LOWMEM = ROOT / "docker-compose.lowmem.yml"
PARTICIPANT = ROOT / "docker-compose.participant.yml"
IT = ROOT / "docker-compose.it.yml"
PARTICIPANT_IT = ROOT / "docker-compose.participant-it.yml"

# Every supported stack: full (base), participant (base + overlay), each with the low-memory overlay.
STACKS = {
    "full": [BASE],
    "full-lowmem": [BASE, LOWMEM],
    "participant": [BASE, PARTICIPANT],
    "participant-lowmem": [BASE, LOWMEM, PARTICIPANT],
}


@pytest.fixture
def good() -> dict[str, Any]:
    return copy.deepcopy(load_compose([BASE]))


def _with(good: dict[str, Any], mutate: Callable[[dict[str, Any]], None]) -> list[str]:
    mutate(good)
    return check_compose(good)


def _has(problems: list[str], needle: str) -> bool:
    return any(needle in p for p in problems)


@pytest.mark.parametrize("stack", STACKS)
def test_every_supported_stack_is_hardened(stack: str) -> None:
    compose = load_compose(STACKS[stack])
    assert check_hardening(compose["services"]) == []
    assert check_compose(compose) == []
    assert check_bridge_names(compose) == []


# --- One failing fixture per hardening rule ----------------------------------------------------

SERVICE_MUTATIONS: list[tuple[str, str, Callable[[dict[str, Any]], None], str]] = [
    ("read_only", "ingest", lambda s: s.pop("read_only"), "must set read_only: true"),
    ("read_only false", "db", lambda s: s.update(read_only=False), "must set read_only: true"),
    ("cap_drop", "redis", lambda s: s.update(cap_drop=["NET_RAW"]), "must set cap_drop: [ALL]"),
    (
        "no-new-privileges",
        "sensor-ssh",
        lambda s: s.update(security_opt=[]),
        "must set security_opt no-new-privileges:true",
    ),
    (
        "seccomp unconfined",
        "sensor-web",
        lambda s: s["security_opt"].append("seccomp=unconfined"),
        "must not set security_opt seccomp=unconfined",
    ),
    (
        "apparmor unconfined",
        "sensor-web",
        lambda s: s["security_opt"].append("apparmor:unconfined"),
        "must not set security_opt apparmor:unconfined",
    ),
    (
        "label disable",
        "api",
        lambda s: s["security_opt"].append("label=disable"),
        "must not set security_opt label=disable",
    ),
    ("no user", "ingest", lambda s: s.pop("user"), "must run as a numeric non-root user"),
    ("root user", "db", lambda s: s.update(user="0:0"), "must run as a numeric non-root user"),
    ("root gid", "db", lambda s: s.update(user="70:0"), "must run as a numeric non-root user"),
    (
        "named user",
        "redis",
        lambda s: s.update(user="redis"),
        "must run as a numeric non-root user",
    ),
    ("uid only", "ingest", lambda s: s.update(user="10001"), "must run as a numeric non-root"),
    ("uid and name", "ingest", lambda s: s.update(user="10001:app"), "must run as a numeric"),
    ("leading zero", "ingest", lambda s: s.update(user="010001:10001"), "must run as a numeric"),
    ("three parts", "ingest", lambda s: s.update(user="1:2:3"), "must run as a numeric"),
    ("empty gid", "ingest", lambda s: s.update(user="10001:"), "must run as a numeric"),
    ("group_add", "ingest", lambda s: s.update(group_add=["docker"]), "must not set group_add"),
    (
        "cgroup_parent",
        "ingest",
        lambda s: s.update(cgroup_parent="/system.slice"),
        "must not set cgroup_parent",
    ),
    ("runtime", "sensor-ssh", lambda s: s.update(runtime="runc"), "must not set runtime"),
    ("secrets", "api", lambda s: s.update(secrets=["db_password"]), "must not use secrets"),
    (
        "secrets, long form",
        "api",
        lambda s: s.update(secrets=[{"source": "x", "target": "/run/x"}]),
        "must not use secrets 'x'",
    ),
    ("configs", "ingest", lambda s: s.update(configs=["rules"]), "must not use configs 'rules'"),
    ("mem_limit", "api", lambda s: s.pop("mem_limit"), "must set mem_limit"),
    ("memswap_limit", "api", lambda s: s.pop("memswap_limit"), "must set memswap_limit"),
    (
        "swap allowed",
        "api",
        lambda s: s.update(memswap_limit="2g"),
        "memswap_limit must equal mem_limit",
    ),
    ("cpus", "db", lambda s: s.pop("cpus"), "must set cpus"),
    ("pids_limit", "sensor-rdp", lambda s: s.pop("pids_limit"), "must set pids_limit"),
    ("pids_limit -1", "sensor-rdp", lambda s: s.update(pids_limit=-1), "pids_limit must be"),
    (
        "oom_kill_disable",
        "db",
        lambda s: s.update(oom_kill_disable=True),
        "must not set oom_kill_disable",
    ),
    ("healthcheck", "ingest", lambda s: s.pop("healthcheck"), "must have a healthcheck"),
    (
        "healthcheck disabled",
        "redis",
        lambda s: s.update(healthcheck={"disable": True}),
        "must have a healthcheck",
    ),
    (
        "healthcheck NONE",
        "redis",
        lambda s: s.update(healthcheck={"test": ["NONE"]}),
        "must have a healthcheck",
    ),
    (
        "one-shot that restarts",
        "migrate",
        lambda s: s.update(restart="unless-stopped"),
        "is exempt from a healthcheck only as a one-shot job",
    ),
    (
        "tmpfs without noexec",
        "ingest",
        lambda s: s.update(tmpfs=["/scratch:rw,nosuid,nodev,size=16m"]),
        "tmpfs /scratch must be mounted noexec",
    ),
    (
        "tmpfs as a bare string",
        "ingest",
        lambda s: s.update(tmpfs="/scratch"),
        "tmpfs /scratch must be mounted noexec,nosuid,nodev",
    ),
    ("privileged", "sensor-smb", lambda s: s.update(privileged=True), "must not set privileged"),
    (
        "network_mode",
        "ingest",
        lambda s: s.update(network_mode="host"),
        "must not set network_mode",
    ),
    ("pid host", "ingest", lambda s: s.update(pid="host"), "must not set pid"),
    ("ipc host", "ingest", lambda s: s.update(ipc="host"), "must not set ipc"),
    ("uts host", "ingest", lambda s: s.update(uts="host"), "must not set uts"),
    ("userns host", "ingest", lambda s: s.update(userns_mode="host"), "must not set userns_mode"),
    ("volumes_from", "api", lambda s: s.update(volumes_from=["db"]), "must not set volumes_from"),
    (
        "devices",
        "sensor-adb",
        lambda s: s.update(devices=["/dev/kvm:/dev/kvm"]),
        "must not map device /dev/kvm",
    ),
    (
        "vpn extra device",
        "vpn",
        lambda s: s["devices"].append("/dev/mem:/dev/mem"),
        "must not map device /dev/mem",
    ),
    (
        "vpn tun remapped",
        "vpn",
        lambda s: s.update(devices=["/dev/net/tun:/dev/other"]),
        "must not map device",
    ),
    ("cap_add", "ingest", lambda s: s.update(cap_add=["NET_RAW"]), "must not add capabilities"),
    (
        "vpn extra cap",
        "vpn",
        lambda s: s["cap_add"].append("SYS_ADMIN"),
        "must not add capabilities ['SYS_ADMIN']",
    ),
    (
        "sysctls",
        "sensor-sip",
        lambda s: s.update(sysctls={"net.ipv4.ip_forward": "1"}),
        "must not set sysctl net.ipv4.ip_forward",
    ),
    (
        "vpn other sysctl",
        "vpn",
        lambda s: s.update(sysctls=["net.ipv4.conf.all.src_valid_mark=1", "kernel.x=1"]),
        "must not set sysctl kernel.x",
    ),
    (
        "docker socket",
        "ingest",
        lambda s: s["volumes"].append("/var/run/docker.sock:/var/run/docker.sock:ro"),
        "must not mount the Docker socket",
    ),
    (
        "docker socket, long form",
        "api",
        lambda s: s["volumes"].append(
            {"type": "bind", "source": "/run/docker.sock", "target": "/s", "read_only": True}
        ),
        "must not mount the Docker socket",
    ),
    (
        "bind mount of a host path",
        "sensor-ssh",
        lambda s: s["volumes"].append("/etc:/host-etc:ro"),
        "must not bind mount /etc",
    ),
    (
        "bind mount of a repo file not on the list",
        "ingest",
        lambda s: s["volumes"].append("./ingest/rules:/rules:ro"),
        "must not bind mount ./ingest/rules",
    ),
    (
        "allowed bind mount made writable",
        "backup",
        lambda s: s.update(
            volumes=["./scripts/backup-service.sh:/backup-service.sh", "backups:/backups"]
        ),
        "must bind mount ./scripts/backup-service.sh read-only",
    ),
    (
        "allowed file on another service",
        "ingest",
        lambda s: s["volumes"].append("./vpn/health.sh:/vpn/health.sh:ro"),
        "must not bind mount ./vpn/health.sh",
    ),
    (
        "tmpfs through volumes",
        "ingest",
        lambda s: s["volumes"].append({"type": "tmpfs", "target": "/x"}),
        "must not use a tmpfs mount",
    ),
]


@pytest.mark.parametrize(
    ("service", "mutate", "needle"),
    [(svc, m, n) for _, svc, m, n in SERVICE_MUTATIONS],
    ids=[i for i, *_ in SERVICE_MUTATIONS],
)
def test_hardening_rule_bites(
    good: dict[str, Any],
    service: str,
    mutate: Callable[[dict[str, Any]], None],
    needle: str,
) -> None:
    mutate(good["services"][service])
    problems = check_hardening(good["services"])
    assert _has(problems, f"service '{service}' {needle}"), problems
    # check_compose runs the same loop.
    assert _has(check_compose(good), needle)


def test_a_new_service_gets_every_rule(good: dict[str, Any]) -> None:
    good["services"]["extra"] = {"image": "example/thing:1.0", "networks": ["backend"]}
    problems = check_hardening(good["services"])
    for needle in (
        "read_only",
        "cap_drop",
        "no-new-privileges",
        "non-root user",
        "mem_limit",
        "cpus",
        "pids_limit",
        "healthcheck",
    ):
        assert any(p.startswith("service 'extra' ") and needle in p for p in problems), needle


def test_vpn_is_the_only_root_service(good: dict[str, Any]) -> None:
    assert "user" not in good["services"]["vpn"]
    good["services"]["hubproxy"].pop("user")
    assert _has(check_hardening(good["services"]), "service 'hubproxy' must run as a numeric")


# --- Images ------------------------------------------------------------------------------------


def test_third_party_images_are_pinned_by_tag_and_digest() -> None:
    for name, svc in load_compose([BASE])["services"].items():
        if "build" not in svc:
            image = svc["image"]
            assert "@sha256:" in image, name
            assert ":" in image.split("@")[0].split("/")[-1], name  # the tag stays readable


@pytest.mark.parametrize(
    "image",
    [
        "timescale/timescaledb:2.31.0-pg17",
        "timescale/timescaledb@sha256:" + "a" * 64,
        "timescale/timescaledb:2.31.0-pg17@sha256:" + "a" * 63,
    ],
)
def test_unpinned_third_party_image_is_refused(good: dict[str, Any], image: str) -> None:
    good["services"]["db"]["image"] = image
    assert _has(check_compose(good), "service 'db' third-party image must be pinned")


# --- Networks ----------------------------------------------------------------------------------


def test_every_internal_network_has_an_isolated_gateway() -> None:
    for name, cfg in load_compose([BASE])["networks"].items():
        assert cfg["enable_ipv6"] is False, name
        bridge = cfg["driver_opts"]["com.docker.network.bridge.name"]
        assert bridge == BRIDGE_NAMES[name] and len(bridge) <= MAX_BRIDGE_NAME, name
        if cfg.get("internal"):
            assert cfg["driver_opts"]["com.docker.network.bridge.gateway_mode_ipv4"] == "isolated"


def test_bridge_names_are_unique() -> None:
    assert len(set(BRIDGE_NAMES.values())) == len(BRIDGE_NAMES)


def test_missing_isolated_gateway_is_refused(good: dict[str, Any]) -> None:
    def mutate(c: dict[str, Any]) -> None:
        c["networks"]["sensors-ssh"]["driver_opts"].pop(
            "com.docker.network.bridge.gateway_mode_ipv4"
        )

    assert _has(_with(good, mutate), "network 'sensors-ssh' must set")


def test_a_new_internal_network_needs_the_isolated_gateway(good: dict[str, Any]) -> None:
    problems = _with(
        good, lambda c: c["networks"].update({"extra": {"internal": True, "enable_ipv6": False}})
    )
    assert _has(problems, "network 'extra' must set com.docker.network.bridge.gateway_mode_ipv4")
    assert _has(check_bridge_names(good), "network 'extra' has no fixed bridge name")


@pytest.mark.parametrize("net", ["backend", "ingress", "hub-uplink"])
def test_ipv6_is_refused(good: dict[str, Any], net: str) -> None:
    assert _has(_with(good, lambda c: c["networks"][net].pop("enable_ipv6")), f"'{net}' must set")
    good["networks"][net]["enable_ipv6"] = True
    assert _has(check_compose(good), f"network '{net}' must set enable_ipv6: false")


def test_long_bridge_name_is_refused(good: dict[str, Any]) -> None:
    def mutate(c: dict[str, Any]) -> None:
        c["networks"]["tools"]["driver_opts"]["com.docker.network.bridge.name"] = (
            "sp-tools-and-more"
        )

    assert _has(_with(good, mutate), "longer than 15 characters")


def test_wrong_bridge_name_is_refused(good: dict[str, Any]) -> None:
    good["networks"]["backend"]["driver_opts"]["com.docker.network.bridge.name"] = "sp-other"
    assert _has(check_bridge_names(good), "network 'backend' must set the bridge name sp-backend")


# --- Test overlays never take the live stack's names -----------------------------------------


def _fixed_names(cfg: dict[str, Any]) -> list[str]:
    opts = cfg.get("driver_opts") or {}
    return [v for v in (cfg.get("name"), opts.get("com.docker.network.bridge.name")) if v]


def test_integration_overlay_has_no_fixed_name_on_its_networks() -> None:
    merged = load_compose([BASE, IT])
    used = {n for svc in ("db", "redis") for n in merged["services"][svc]["networks"]}
    assert used == {"backend"}
    for net in used:
        assert _fixed_names(merged["networks"][net]) == [], net
        assert merged["networks"][net]["internal"] is True


def test_participant_e2e_overlay_has_no_fixed_name_on_any_network() -> None:
    merged = load_compose([BASE, PARTICIPANT_IT])
    for net, cfg in merged["networks"].items():
        if cfg.get("external"):
            continue  # the pre-made test uplink, named after the throwaway project
        assert _fixed_names(cfg) == [], net
        assert cfg["enable_ipv6"] is False, net
        if cfg.get("internal"):
            assert cfg["driver_opts"]["com.docker.network.bridge.gateway_mode_ipv4"] == "isolated"
    # Same networks as the base file: nothing added, nothing lost.
    assert set(merged["networks"]) == set(load_compose([BASE])["networks"])


# --- Top-level volumes, secrets and configs ----------------------------------------------------


@pytest.mark.parametrize(
    "files",
    [[BASE], [BASE, IT], [BASE, ROOT / "docker-compose.ci.yml"], [BASE, PARTICIPANT_IT]],
    ids=["base", "it", "ci", "participant-it"],
)
def test_every_volume_is_external_or_plain(files: list[Path]) -> None:
    assert check_top_level(load_compose(files)) == []


@pytest.mark.parametrize(
    ("volume", "needle"),
    [
        (
            {"driver_opts": {"type": "none", "o": "bind", "device": "/etc"}},
            "volume 'x' must not set driver_opts",
        ),
        ({"driver": "rclone"}, "volume 'x' must use the default local driver"),
        (
            {"driver": "local", "driver_opts": {"type": "nfs", "device": ":/export"}},
            "volume 'x' must not set driver_opts",
        ),
    ],
    ids=["local bind", "other driver", "nfs"],
)
def test_host_path_volume_is_refused(
    good: dict[str, Any], volume: dict[str, Any], needle: str
) -> None:
    good["volumes"]["x"] = volume
    assert _has(check_top_level(good), needle)
    assert _has(check_compose(good), needle)


def test_plain_local_volume_is_accepted(good: dict[str, Any]) -> None:
    good["volumes"]["x"] = {"driver": "local", "name": "test-x"}
    assert check_top_level(good) == []


def test_external_volume_options_are_not_ours(good: dict[str, Any]) -> None:
    good["volumes"]["x"] = {"external": True, "name": "x"}
    assert check_top_level(good) == []


@pytest.mark.parametrize("key", ["secrets", "configs"])
def test_top_level_file_secret_or_config_is_refused(good: dict[str, Any], key: str) -> None:
    good[key] = {"x": {"file": "/etc/shadow"}}
    assert _has(check_compose(good), f"top-level {key} 'x' is not allowed")


# --- The CLI checks the same renderings as the tests --------------------------------------------


def test_cli_checks_the_lowmem_renderings(monkeypatch: pytest.MonkeyPatch) -> None:
    from suckerpot_guardrails import __main__ as cli

    seen: list[list[str]] = []
    real = load_compose

    def spy(paths: Any) -> Any:
        paths = list(paths)
        seen.append([p.name for p in paths])
        return real(paths)

    monkeypatch.setattr(cli, "load_compose", spy)
    assert cli.main([]) == 0
    for combo in (
        ["docker-compose.yml", "docker-compose.lowmem.yml"],
        ["docker-compose.yml", "docker-compose.participant.yml"],
        ["docker-compose.yml", "docker-compose.lowmem.yml", "docker-compose.participant.yml"],
    ):
        assert combo in seen, combo

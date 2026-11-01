"""Each rule must fail on a broken snippet (the checker itself is tested here)."""

import copy
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from suckerpot_guardrails import (
    check_compose,
    check_vpn_entrypoint,
    find_hash_named_files,
    load_compose,
)
from suckerpot_guardrails.compose import _merge

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def good() -> dict[str, Any]:
    return copy.deepcopy(load_compose([ROOT / "docker-compose.yml"]))


def _with(good: dict[str, Any], mutate: Callable[[dict[str, Any]], None]) -> list[str]:
    mutate(good)
    return check_compose(good)


def _has(problems: list[str], needle: str) -> bool:
    return any(needle in p for p in problems)


def test_egress_network_is_refused(good: dict[str, Any]) -> None:
    problems = _with(good, lambda c: c["networks"].update({"egress": {}}))
    assert _has(problems, "network 'egress' must not exist")
    assert _has(problems, "network 'egress' must be internal")


def test_non_internal_network_is_refused(good: dict[str, Any]) -> None:
    problems = _with(good, lambda c: c["networks"]["backend"].update({"internal": False}))
    assert _has(problems, "network 'backend' must be internal")


def test_masquerade_on_ingress_is_refused(good: dict[str, Any]) -> None:
    def mutate(c: dict[str, Any]) -> None:
        c["networks"]["ingress"]["driver_opts"].pop(
            "com.docker.network.bridge.enable_ip_masquerade"
        )

    assert _has(_with(good, mutate), "enable_ip_masquerade=false")


def test_icc_on_vpn_uplink_is_refused(good: dict[str, Any]) -> None:
    def mutate(c: dict[str, Any]) -> None:
        c["networks"]["vpn-uplink"]["driver_opts"].pop("com.docker.network.bridge.enable_icc")

    assert _has(_with(good, mutate), "enable_icc=false")


def test_non_sensor_on_ingress_is_refused(good: dict[str, Any]) -> None:
    problems = _with(
        good, lambda c: c["services"]["db"].update({"networks": ["backend", "ingress"]})
    )
    assert _has(problems, "network 'ingress' members must be exactly")


def test_extra_egress_proxy_member_is_refused(good: dict[str, Any]) -> None:
    problems = _with(good, lambda c: c["services"]["api"]["networks"].append("egress-proxy"))
    assert _has(problems, "network 'egress-proxy' members must be exactly")


def test_ingest_on_uplink_is_refused(good: dict[str, Any]) -> None:
    problems = _with(good, lambda c: c["services"]["ingest"]["networks"].append("vpn-uplink"))
    assert _has(problems, "service 'ingest' is on non-internal network 'vpn-uplink'")


def test_missing_dns_is_refused(good: dict[str, Any]) -> None:
    problems = _with(good, lambda c: c["services"]["collector"].pop("dns"))
    assert _has(problems, "service 'collector' must set dns")


def test_analyzer_on_egress_proxy_is_refused(good: dict[str, Any]) -> None:
    problems = _with(good, lambda c: c["services"]["analyzer"]["networks"].append("egress-proxy"))
    assert _has(problems, "network 'egress-proxy' members must be exactly")


def test_vpn_extra_capability_is_refused(good: dict[str, Any]) -> None:
    problems = _with(good, lambda c: c["services"]["vpn"]["cap_add"].append("NET_RAW"))
    assert _has(problems, "cap_add must be exactly [NET_ADMIN]")


def test_vpn_extra_device_is_refused(good: dict[str, Any]) -> None:
    problems = _with(good, lambda c: c["services"]["vpn"]["devices"].append("/dev/mem:/dev/mem"))
    assert _has(problems, "devices must be exactly /dev/net/tun")


def test_vpn_ports_are_refused(good: dict[str, Any]) -> None:
    problems = _with(good, lambda c: c["services"]["vpn"].update({"ports": ["8888:8888"]}))
    assert _has(problems, "service 'vpn' must not publish ports")


def test_vpn_unpinned_image_is_refused(good: dict[str, Any]) -> None:
    problems = _with(
        good, lambda c: c["services"]["vpn"].update({"image": "qmcgaw/gluetun:latest"})
    )
    assert _has(problems, "pinned by sha256")


def test_vpn_outbound_subnets_are_refused(good: dict[str, Any]) -> None:
    def mutate(c: dict[str, Any]) -> None:
        c["services"]["vpn"]["environment"]["FIREWALL_OUTBOUND_SUBNETS"] = "198.51.100.0/24"

    assert _has(_with(good, mutate), "FIREWALL_OUTBOUND_SUBNETS")


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("cap_add", ["SYS_ADMIN"]),
        ("devices", ["/dev/net/tun:/dev/net/tun"]),
        ("privileged", True),
        ("pid", "host"),
        ("ipc", "host"),
        ("network_mode", "host"),
        ("network_mode", "service:vpn"),
    ],
)
def test_privileges_elsewhere_are_refused(good: dict[str, Any], key: str, value: Any) -> None:
    problems = _with(good, lambda c: c["services"]["ingest"].update({key: value}))
    assert _has(problems, f"service 'ingest' must not set {key}")


def test_published_port_on_ingest_is_refused(good: dict[str, Any]) -> None:
    problems = _with(good, lambda c: c["services"]["ingest"].update({"ports": ["9000:9000"]}))
    assert _has(problems, "service 'ingest' must not publish ports")


@pytest.mark.parametrize("var", ["HTTP_PROXY", "https_proxy", "ALL_PROXY", "NO_PROXY"])
def test_proxy_variables_are_refused(good: dict[str, Any], var: str) -> None:
    def mutate(c: dict[str, Any]) -> None:
        c["services"]["ingest"]["environment"][var] = "http://vpn:8888"

    assert _has(_with(good, mutate), "must not set")


def test_analyzer_quarantine_must_be_read_only(good: dict[str, Any]) -> None:
    problems = _with(
        good, lambda c: c["services"]["analyzer"].update({"volumes": ["quarantine:/quarantine"]})
    )
    assert _has(problems, "service 'analyzer' must mount quarantine read-only")


def test_api_quarantine_must_be_read_only(good: dict[str, Any]) -> None:
    problems = _with(
        good, lambda c: c["services"]["api"].update({"volumes": ["quarantine:/quarantine"]})
    )
    assert _has(problems, "service 'api' must mount quarantine read-only")


def test_ingest_cannot_mount_quarantine(good: dict[str, Any]) -> None:
    def mutate(c: dict[str, Any]) -> None:
        c["services"]["ingest"]["volumes"].append("quarantine:/quarantine:ro")

    assert _has(_with(good, mutate), "service 'ingest' must not mount quarantine")


def test_long_form_read_write_mount_is_refused(good: dict[str, Any]) -> None:
    mount = {"type": "volume", "source": "quarantine", "target": "/quarantine"}
    problems = _with(good, lambda c: c["services"]["analyzer"].update({"volumes": [mount]}))
    assert _has(problems, "read-only")


def test_hash_named_file_is_found(tmp_path: Path) -> None:
    (tmp_path / "ab").mkdir()
    (tmp_path / "ab" / ("c" * 64)).write_bytes(b"x")
    (tmp_path / "ab" / "readme").write_bytes(b"x")
    assert find_hash_named_files(tmp_path) == [str(Path("ab") / ("c" * 64))]


def test_merge_extends_lists_and_resets_keys() -> None:
    assert _merge({"a": [1]}, {"a": [2]}) == {"a": [1, 2]}


def test_unnamed_proxy_bridge_is_refused(good: dict[str, Any]) -> None:
    problems = _with(good, lambda c: c["networks"]["egress-proxy"].pop("driver_opts"))
    assert _has(problems, "network 'egress-proxy' must set the bridge name sp-egress")


def test_unnamed_samples_bridge_is_refused(good: dict[str, Any]) -> None:
    problems = _with(good, lambda c: c["networks"]["samples"].pop("driver_opts"))
    assert _has(problems, "network 'samples' must set the bridge name sp-samples")


def _swap_volume(c: dict[str, Any], svc: str, entry: str, prefix: str = "vpn-config") -> None:
    vols = c["services"][svc]["volumes"]
    vols[:] = [v for v in vols if not v.startswith(prefix)] + [entry]


def test_vpn_config_mounted_by_another_service_is_refused(good: dict[str, Any]) -> None:
    def mutate(c: dict[str, Any]) -> None:
        c["services"]["ingest"]["volumes"].append("vpn-config:/vpn-config:ro")

    assert _has(_with(good, mutate), "service 'ingest' must not mount vpn-config")


def test_vpn_config_must_be_read_only_in_vpn(good: dict[str, Any]) -> None:
    problems = _with(good, lambda c: _swap_volume(c, "vpn", "vpn-config:/vpn-config"))
    assert _has(problems, "service 'vpn' must mount vpn-config read-only")


def test_vpn_config_must_be_writable_in_api(good: dict[str, Any]) -> None:
    problems = _with(good, lambda c: _swap_volume(c, "api", "vpn-config:/vpn-config:ro"))
    assert _has(problems, "service 'api' must mount vpn-config read-write")


def test_api_docker_socket_is_refused(good: dict[str, Any]) -> None:
    def mutate(c: dict[str, Any]) -> None:
        c["services"]["api"]["volumes"].append("/var/run/docker.sock:/var/run/docker.sock")

    assert _has(_with(good, mutate), "service 'api' must not mount the docker socket")


def test_api_net_admin_is_refused(good: dict[str, Any]) -> None:
    problems = _with(good, lambda c: c["services"]["api"].update({"cap_add": ["NET_ADMIN"]}))
    assert _has(problems, "service 'api' must not have NET_ADMIN")


def test_api_on_an_extra_network_is_refused(good: dict[str, Any]) -> None:
    problems = _with(good, lambda c: c["services"]["api"]["networks"].append("vpn-uplink"))
    assert _has(problems, "service 'api' must be on exactly backend and dashboard")


def test_api_must_stay_read_only(good: dict[str, Any]) -> None:
    problems = _with(good, lambda c: c["services"]["api"].update({"read_only": False}))
    assert _has(problems, "service 'api' must be read_only")


def test_vpn_entrypoint_script_must_be_read_only(good: dict[str, Any]) -> None:
    problems = _with(
        good,
        lambda c: _swap_volume(c, "vpn", "./vpn/entrypoint.sh:/vpn/entrypoint.sh", "./vpn/entry"),
    )
    assert _has(problems, "must mount /vpn/entrypoint.sh read-only")


def test_real_vpn_entrypoint_is_clean() -> None:
    assert check_vpn_entrypoint((ROOT / "vpn" / "entrypoint.sh").read_text()) == []


@pytest.mark.parametrize(
    "line",
    ["source /vpn-config/wg.env", ". /vpn-config/wg.env", 'eval "$(cat x)"', "x=1; . ./f"],
)
def test_vpn_entrypoint_sourcing_is_refused(line: str) -> None:
    assert check_vpn_entrypoint(f"#!/bin/sh\n{line}\n")


def test_vpn_entrypoint_comments_may_mention_source() -> None:
    assert check_vpn_entrypoint("# never source the file\necho ok\n") == []


def test_sensor_without_replicas_switch_is_refused(good: dict[str, Any]) -> None:
    problems = _with(good, lambda c: c["services"]["sensor-ssh"].pop("deploy"))
    assert _has(problems, "service 'sensor-ssh' deploy must be exactly")


def test_sensor_with_extra_deploy_key_is_refused(good: dict[str, Any]) -> None:
    problems = _with(
        good, lambda c: c["services"]["sensor-web"]["deploy"].update({"resources": {}})
    )
    assert _has(problems, "service 'sensor-web' deploy must be exactly")


def test_replicas_on_a_non_sensor_is_refused(good: dict[str, Any]) -> None:
    problems = _with(good, lambda c: c["services"]["api"].update({"deploy": {"replicas": 2}}))
    assert _has(problems, "service 'api' must not use deploy.replicas")


def test_latest_tag_is_refused(good: dict[str, Any]) -> None:
    problems = _with(good, lambda c: c["services"]["db"].update({"image": "postgres:latest"}))
    assert _has(problems, "service 'db' image must carry an explicit non-latest tag")


def test_untagged_image_is_refused(good: dict[str, Any]) -> None:
    problems = _with(good, lambda c: c["services"]["db"].update({"image": "postgres"}))
    assert _has(problems, "service 'db' image must carry an explicit non-latest tag")


def test_built_service_with_foreign_image_name_is_refused(good: dict[str, Any]) -> None:
    problems = _with(good, lambda c: c["services"]["api"].update({"image": "example.org/api:1"}))
    assert _has(problems, "service 'api' image must use")


def test_vpn_health_script_must_be_read_only(good: dict[str, Any]) -> None:
    def mutate(c: dict[str, Any]) -> None:
        vols = c["services"]["vpn"]["volumes"]
        vols[:] = [v.removesuffix(":ro") if "health.sh" in v else v for v in vols]

    assert _has(_with(good, mutate), "/vpn/health.sh read-only")


def test_vpn_healthcheck_must_use_the_script(good: dict[str, Any]) -> None:
    def mutate(c: dict[str, Any]) -> None:
        c["services"]["vpn"]["healthcheck"]["test"] = ["CMD", "true"]

    assert _has(_with(good, mutate), "healthcheck must run /vpn/health.sh")

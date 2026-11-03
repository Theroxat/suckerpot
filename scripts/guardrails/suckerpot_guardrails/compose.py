"""Loads compose files (with overlays) and checks the egress and isolation invariants of M21.

The checks read the YAML as written: no variable is interpolated and profiles are ignored, so a
service that only exists under a profile is checked like any other.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml

Compose = dict[str, Any]

# Networks that may have a route to the internet or accept inbound traffic, with the
# bridge name and the options that make them safe.
EXTERNAL_NETWORKS: dict[str, dict[str, str]] = {
    "ingress": {
        "name": "sp-ingress",
        "com.docker.network.bridge.enable_ip_masquerade": "false",
        "com.docker.network.bridge.enable_icc": "false",
    },
    "dashboard": {
        "name": "sp-dashboard",
        "com.docker.network.bridge.enable_ip_masquerade": "false",
    },
    "vpn-uplink": {
        "name": "sp-vpn",
        "com.docker.network.bridge.enable_icc": "false",
    },
    # M32: the uplink of hubproxy (participant mode without a VPN), its only member.
    "hub-uplink": {
        "name": "sp-hubgate",
        "com.docker.network.bridge.enable_icc": "false",
    },
}
ADMIN_SSH_PORT = "22222"
PROXY_ENV = {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class _Override(list[Any]):
    """A sequence tagged ``!override``: replaces the base value instead of extending it."""


class _OverrideMap(dict[Any, Any]):
    """A mapping tagged ``!override``: replaces the base mapping instead of merging into it."""


class _Reset:
    """A value tagged ``!reset``: removes the key."""


class _Loader(yaml.SafeLoader):
    pass


def _override(loader: yaml.SafeLoader, node: yaml.Node) -> Any:
    if isinstance(node, yaml.SequenceNode):
        return _Override(loader.construct_sequence(node, deep=True))
    if isinstance(node, yaml.MappingNode):
        return _OverrideMap(loader.construct_mapping(node, deep=True))
    return loader.construct_scalar(node)  # type: ignore[arg-type]


def _reset(loader: yaml.SafeLoader, node: yaml.Node) -> Any:
    return _Reset()


_Loader.add_constructor("!override", _override)
_Loader.add_constructor("!reset", _reset)


def _merge(base: Any, over: Any) -> Any:
    if isinstance(over, _Override):
        return list(over)
    if isinstance(over, _OverrideMap):
        return dict(over)
    if isinstance(base, dict) and isinstance(over, dict):
        out = dict(base)
        for key, value in over.items():
            if isinstance(value, _Reset):
                out.pop(key, None)
            elif key in out:
                out[key] = _merge(out[key], value)
            else:
                out[key] = _merge(None, value)
        return out
    if isinstance(base, list) and isinstance(over, list):
        return [*base, *over]
    if isinstance(over, dict):
        return {k: _merge(None, v) for k, v in over.items() if not isinstance(v, _Reset)}
    return over


def load_compose(paths: Iterable[Path]) -> Compose:
    """Loads the files in order and merges them the way ``docker compose -f a -f b`` does."""
    merged: Compose = {}
    for path in paths:
        data = yaml.load(path.read_text(encoding="utf-8"), Loader=_Loader)  # noqa: S506
        merged = _merge(merged, data or {})
    return merged


def _service_networks(service: Mapping[str, Any]) -> set[str]:
    nets = service.get("networks") or []
    return set(nets) if not isinstance(nets, Mapping) else set(nets.keys())


def _env(service: Mapping[str, Any]) -> dict[str, str]:
    env = service.get("environment") or {}
    if isinstance(env, Mapping):
        return {str(k): "" if v is None else str(v) for k, v in env.items()}
    out: dict[str, str] = {}
    for item in env:
        key, _, value = str(item).partition("=")
        out[key] = value
    return out


def _mounts(service: Mapping[str, Any], volume: str) -> list[bool]:
    """For each mount of the named volume, whether it is read-only."""
    found: list[bool] = []
    for item in service.get("volumes") or []:
        if isinstance(item, Mapping):
            if item.get("source") == volume:
                found.append(bool(item.get("read_only", False)))
            continue
        parts = str(item).split(":")
        if parts[0] == volume:
            found.append(len(parts) > 2 and "ro" in parts[2].split(","))
    return found


def _mount_targets(service: Mapping[str, Any]) -> list[tuple[str, bool]]:
    """(container path, read-only) for every volume entry of a service."""
    found: list[tuple[str, bool]] = []
    for item in service.get("volumes") or []:
        if isinstance(item, Mapping):
            found.append((str(item.get("target")), bool(item.get("read_only", False))))
            continue
        parts = str(item).split(":")
        if len(parts) > 1:
            found.append((parts[1], len(parts) > 2 and "ro" in parts[2].split(",")))
    return found


def check_compose(compose: Compose) -> list[str]:
    """Returns one message per violation (an empty list means the file is acceptable)."""
    problems: list[str] = []
    services: dict[str, Any] = compose.get("services") or {}
    networks: dict[str, Any] = compose.get("networks") or {}

    # 1. Only three networks may leave "internal" mode, each with its safe options.
    if "egress" in networks:
        problems.append("network 'egress' must not exist (outbound goes through the vpn proxy)")
    for net, cfg in networks.items():
        cfg = cfg or {}
        if net in EXTERNAL_NETWORKS:
            if cfg.get("internal"):
                continue  # stricter than required (used by test overlays)
            expected = EXTERNAL_NETWORKS[net]
            if cfg.get("name") != expected["name"]:
                problems.append(f"network '{net}' must be named {expected['name']}")
            opts = cfg.get("driver_opts") or {}
            if opts.get("com.docker.network.bridge.name") != expected["name"]:
                problems.append(f"network '{net}' must set the bridge name {expected['name']}")
            for key, value in expected.items():
                if key != "name" and str(opts.get(key)) != value:
                    problems.append(f"network '{net}' must set {key}={value}")
        elif cfg.get("internal") is not True:
            problems.append(f"network '{net}' must be internal: true")

    # Bridges that hold a proxy or sample traffic are named, so the host firewall can match them.
    for net, bridge in (
        ("egress-proxy", "sp-egress"),
        ("samples", "sp-samples"),
        ("hub-proxy", "sp-hubproxy"),
    ):
        opts = (networks.get(net) or {}).get("driver_opts") or {}
        if net in networks and opts.get("com.docker.network.bridge.name") != bridge:
            problems.append(f"network '{net}' must set the bridge name {bridge}")

    # 2. Exact membership.
    members: dict[str, set[str]] = {n: set() for n in networks}
    for name, svc in services.items():
        for net in _service_networks(svc):
            if net not in networks:
                problems.append(f"service '{name}' uses undefined network '{net}'")
            members.setdefault(net, set()).add(name)
    sensors = {n for n in services if n.startswith("sensor-")}
    expected_members = {
        "ingress": sensors,
        "dashboard": {"api"},
        "vpn-uplink": {"vpn"},
        "egress-proxy": {"vpn", "ingest", "collector"},
        "hub-uplink": {"hubproxy"},
    }
    for net, want in expected_members.items():
        if net in networks and members.get(net, set()) != want:
            problems.append(
                f"network '{net}' members must be exactly {sorted(want)}, "
                f"found {sorted(members.get(net, set()))}"
            )
    for net in ("egress-proxy", "vpn-uplink", "hub-uplink", "hub-proxy"):
        if net not in networks:
            problems.append(f"network '{net}' is missing")
    # hub-proxy: hubproxy and ingest only (never a sensor, the api or the vpn side).
    extra = members.get("hub-proxy", set()) - {"hubproxy", "ingest"}
    if extra:
        problems.append(
            f"network 'hub-proxy' members must be hubproxy and ingest only: {sorted(extra)}"
        )

    # 3. Egress clients sit on internal networks only and cannot resolve external names.
    for name in ("ingest", "collector", "analyzer"):
        svc = services.get(name)
        if svc is None:
            problems.append(f"service '{name}' is missing")
            continue
        for net in _service_networks(svc):
            if net in EXTERNAL_NETWORKS or (networks.get(net) or {}).get("internal") is not True:
                problems.append(f"service '{name}' is on non-internal network '{net}'")
        if list(svc.get("dns") or []) != ["127.0.0.1"]:
            problems.append(f"service '{name}' must set dns: [\"127.0.0.1\"]")

    # 4. The vpn container.
    vpn = services.get("vpn")
    if vpn is None:
        problems.append("service 'vpn' is missing")
    else:
        if _service_networks(vpn) != {"vpn-uplink", "egress-proxy"}:
            problems.append("service 'vpn' must be on exactly vpn-uplink and egress-proxy")
        if list(vpn.get("cap_add") or []) != ["NET_ADMIN"]:
            problems.append("service 'vpn' cap_add must be exactly [NET_ADMIN]")
        if "ALL" not in (vpn.get("cap_drop") or []):
            problems.append("service 'vpn' must set cap_drop: [ALL]")
        devices = [str(d).split(":")[0] for d in vpn.get("devices") or []]
        if devices != ["/dev/net/tun"]:
            problems.append("service 'vpn' devices must be exactly /dev/net/tun")
        if "no-new-privileges:true" not in (vpn.get("security_opt") or []):
            problems.append("service 'vpn' must set no-new-privileges:true")
        if vpn.get("ports"):
            problems.append("service 'vpn' must not publish ports")
        if vpn.get("privileged"):
            problems.append("service 'vpn' must not be privileged")
        if not re.search(r"@sha256:[0-9a-f]{64}$", str(vpn.get("image", ""))):
            problems.append("service 'vpn' image must be pinned by sha256 digest")
        if vpn.get("read_only") is not True:
            problems.append("service 'vpn' must be read_only")
        if _env(vpn).get("FIREWALL_OUTBOUND_SUBNETS"):
            problems.append("service 'vpn' must not set FIREWALL_OUTBOUND_SUBNETS")

    # 5, 6. Nobody else gets privileges, host namespaces or published ports.
    for name, svc in services.items():
        if name != "vpn":
            for key in ("cap_add", "devices", "privileged", "pid", "ipc", "network_mode"):
                if svc.get(key):
                    problems.append(f"service '{name}' must not set {key}")
        if svc.get("ports") and not (name.startswith("sensor-") or name == "api"):
            problems.append(f"service '{name}' must not publish ports")
        proxy_vars = sorted(k for k in _env(svc) if k.lower() in PROXY_ENV)
        if proxy_vars:
            problems.append(f"service '{name}' must not set {', '.join(proxy_vars)}")

    # 7. Quarantine: collector read-write, analyzer and api read-only, nobody else.
    for name, svc in services.items():
        mounts = _mounts(svc, "quarantine")
        if not mounts:
            if name in ("collector", "analyzer"):
                problems.append(f"service '{name}' must mount quarantine")
            continue
        if name == "collector":
            continue
        if name not in ("analyzer", "api"):
            problems.append(f"service '{name}' must not mount quarantine")
        elif not all(mounts):
            problems.append(f"service '{name}' must mount quarantine read-only")

    # 8. Uploaded VPN settings (M23): api read-write, vpn read-only, nobody else. The api gets no
    # privilege and no route out, and the vpn entrypoint script is mounted read-only.
    for name, svc in services.items():
        mounts = _mounts(svc, "vpn-config")
        if name == "api":
            if not mounts or any(mounts):
                problems.append("service 'api' must mount vpn-config read-write")
        elif name == "vpn":
            if not mounts or not all(mounts):
                problems.append("service 'vpn' must mount vpn-config read-only")
        elif mounts:
            problems.append(f"service '{name}' must not mount vpn-config")
    api = services.get("api")
    if api is not None:
        if _service_networks(api) != {"backend", "dashboard"}:
            problems.append("service 'api' must be on exactly backend and dashboard")
        if any("docker.sock" in str(v) for v in api.get("volumes") or []):
            problems.append("service 'api' must not mount the docker socket")
        if api.get("read_only") is not True:
            problems.append("service 'api' must be read_only")
        if "ALL" not in (api.get("cap_drop") or []):
            problems.append("service 'api' must set cap_drop: [ALL]")
        if "NET_ADMIN" in (api.get("cap_add") or []):
            problems.append("service 'api' must not have NET_ADMIN")
    if vpn is not None:
        entry = list(vpn.get("entrypoint") or [])
        if entry[-1:] != ["/vpn/entrypoint.sh"]:
            problems.append("service 'vpn' must run /vpn/entrypoint.sh")
        script_mounts = [
            read_only for target, read_only in _mount_targets(vpn) if target == "/vpn/entrypoint.sh"
        ]
        script_ro = all(script_mounts)
        if len(script_mounts) != 1 or not script_ro:
            problems.append("service 'vpn' must mount /vpn/entrypoint.sh read-only")

    problems += _check_hubproxy(services)
    problems += _check_ports(services)
    problems += _check_sensor_switches(services)
    problems += _check_images(services)
    if vpn is not None:
        health = [
            read_only for target, read_only in _mount_targets(vpn) if target == "/vpn/health.sh"
        ]
        if len(health) != 1 or not all(health):
            problems.append("service 'vpn' must mount /vpn/health.sh read-only")
        test = list((vpn.get("healthcheck") or {}).get("test") or [])
        if test != ["CMD", "/bin/sh", "/vpn/health.sh"]:
            problems.append("service 'vpn' healthcheck must run /vpn/health.sh")
    return problems


def _check_hubproxy(services: Mapping[str, Any]) -> list[str]:
    """M32: hubproxy is the only other route out. Profile ``direct``, never with ``vpn``."""
    problems: list[str] = []
    for name in ("vpn", "collector", "analyzer"):
        svc = services.get(name)
        if svc is not None and list(svc.get("profiles") or []) != ["egress"]:
            problems.append(f"service '{name}' profiles must be exactly [egress]")
    # No service may belong to both route-out profiles.
    for name, svc in services.items():
        if {"egress", "direct"} <= set(svc.get("profiles") or []):
            problems.append(f"service '{name}' must not be in both profiles egress and direct")
    hub = services.get("hubproxy")
    if hub is None:
        problems.append("service 'hubproxy' is missing")
        return problems
    if list(hub.get("profiles") or []) != ["direct"]:
        problems.append("service 'hubproxy' profiles must be exactly [direct]")
    vpn = services.get("vpn") or {}
    if "hubproxy" in _depends(vpn) or "vpn" in _depends(hub):
        problems.append("services 'vpn' and 'hubproxy' must not depend on each other")
    if _service_networks(hub) != {"hub-uplink", "hub-proxy"}:
        problems.append("service 'hubproxy' must be on exactly hub-uplink and hub-proxy")
    for key in ("ports", "cap_add", "devices", "volumes", "privileged", "network_mode"):
        if hub.get(key):
            problems.append(f"service 'hubproxy' must not set {key}")
    if hub.get("read_only") is not True:
        problems.append("service 'hubproxy' must be read_only")
    if "ALL" not in (hub.get("cap_drop") or []):
        problems.append("service 'hubproxy' must set cap_drop: [ALL]")
    if "no-new-privileges:true" not in (hub.get("security_opt") or []):
        problems.append("service 'hubproxy' must set no-new-privileges:true")
    user = str(hub.get("user", "0")).split(":")[0]
    if not user.isdigit() or int(user) == 0:
        problems.append("service 'hubproxy' must run as a non-root user")
    for key in ("mem_limit", "memswap_limit", "cpus", "pids_limit"):
        if not hub.get(key):
            problems.append(f"service 'hubproxy' must set {key}")
    if hub.get("dns"):
        problems.append("service 'hubproxy' needs Docker's resolver (no dns override)")
    return problems


def _depends(service: Mapping[str, Any]) -> set[str]:
    deps = service.get("depends_on") or []
    return set(deps) if not isinstance(deps, Mapping) else set(deps.keys())


def _host_port(entry: Any) -> str:
    """The host-side part of a ports entry, as written (``${X:-22}`` stays whole)."""
    if isinstance(entry, Mapping):
        return str(entry.get("published", ""))
    # Split on colons that are not part of a ${VAR:-default} expression.
    parts = re.split(r":(?![-?+])", str(entry))
    return parts[-2] if len(parts) >= 2 else parts[0]


def _default_port(host: str) -> str:
    match = re.fullmatch(r"\$\{[A-Z0-9_]+:-(\d+)\}", host)
    return match.group(1) if match else host


def _check_ports(services: Mapping[str, Any]) -> list[str]:
    """M32: nobody publishes the admin SSH port; the dashboard never uses a sensor port."""
    problems: list[str] = []
    sensor_ports = {
        _default_port(_host_port(p))
        for n, s in services.items()
        if n.startswith("sensor-")
        for p in s.get("ports") or []
    }
    for name, svc in services.items():
        for entry in svc.get("ports") or []:
            host = _host_port(entry)
            if _default_port(host) == ADMIN_SSH_PORT:
                problems.append(f"service '{name}' must not publish port {ADMIN_SSH_PORT}")
            if name == "api" and (_default_port(host) in sensor_ports or "_HOST_PORT" in host):
                problems.append("service 'api' must not publish a sensor port")
    return problems


def _check_sensor_switches(services: Mapping[str, Any]) -> list[str]:
    """M28: a sensor is switched on or off by deploy.replicas and nothing else."""
    problems: list[str] = []
    for name, svc in services.items():
        deploy = svc.get("deploy")
        if not name.startswith("sensor-"):
            if deploy and "replicas" in deploy:
                problems.append(f"service '{name}' must not use deploy.replicas")
            continue
        want = {"replicas": "${SENSOR_" + name.removeprefix("sensor-").upper() + ":-1}"}
        if deploy != want:
            problems.append(f"service '{name}' deploy must be exactly {want}")
    return problems


def _check_images(services: Mapping[str, Any]) -> list[str]:
    """M28: built services are tagged from the release prefix and version, never ``latest``."""
    problems: list[str] = []
    for name, svc in services.items():
        image = str(svc.get("image", ""))
        if re.search(r":latest($|[@\s])", image) or (image and ":" not in image.split("/")[-1]):
            problems.append(f"service '{name}' image must carry an explicit non-latest tag")
        if svc.get("build") is not None and not (
            (image.startswith("${SUCKERPOT_IMAGE_PREFIX") and ":${SUCKERPOT_VERSION" in image)
            # A test overlay names images after its throwaway project, never the release prefix.
            or (image.startswith("local/${COMPOSE_PROJECT_NAME:?}-") and image.endswith(":test"))
        ):
            problems.append(
                f"service '{name}' image must use ${{SUCKERPOT_IMAGE_PREFIX...}} and "
                "${SUCKERPOT_VERSION...}"
            )
    return problems


def check_vpn_entrypoint(script: str) -> list[str]:
    """The vpn entrypoint must read wg.env with fixed patterns, never source or eval it."""
    problems: list[str] = []
    code = "\n".join(line for line in script.splitlines() if not line.lstrip().startswith("#"))
    if re.search(r"(^|[;&|(]\s*|\s)(source|eval)\s", code, re.M):
        problems.append("vpn entrypoint must not use source or eval")
    if re.search(r"(^|[;&|(]\s*)\.\s+\S", code, re.M):
        problems.append("vpn entrypoint must not dot-source a file")
    return problems


def find_hash_named_files(root: Path) -> list[str]:
    """Paths under ``root`` whose file name is a 64-hex string (a quarantined sample)."""
    skip = {".git", "node_modules", ".venv", "dist", "__pycache__"}
    found: list[str] = []
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in skip]
        found += [str(Path(current, f).relative_to(root)) for f in files if HEX64.match(f)]
    return found


def active_services(compose: Compose, profiles: Iterable[str]) -> set[str]:
    """Services compose would start for the given ``COMPOSE_PROFILES`` (no ``--profile`` flag)."""
    wanted = set(profiles)
    active: set[str] = set()
    for name, svc in (compose.get("services") or {}).items():
        service_profiles = set(svc.get("profiles") or [])
        if not service_profiles or service_profiles & wanted:
            active.add(name)
    return active


def check_participant(compose: Compose, profiles: Iterable[str]) -> list[str]:
    """M32: the participant rendering (base + lowmem + participant overlay) for one profile set.

    ``profiles`` is ``["direct"]`` (no VPN) or ``["egress"]`` (with a VPN). Returns violations.
    """
    wanted = set(profiles)
    problems = check_compose(compose)
    services: dict[str, Any] = compose.get("services") or {}
    networks: dict[str, Any] = compose.get("networks") or {}
    active = active_services(compose, wanted)
    sensors = {n for n in active if n.startswith("sensor-")}
    if wanted not in ({"direct"}, {"egress"}):
        problems.append(
            f"participant profiles must be exactly direct or egress, got {sorted(wanted)}"
        )
    if {"vpn", "hubproxy"} <= active:
        problems.append("vpn and hubproxy must never run together")
    want = {"redis", "db", "migrate", "backup", "ingest"} | sensors
    want |= {"hubproxy"} if wanted == {"direct"} else {"vpn", "collector", "analyzer"}
    if active != want:
        problems.append(
            f"participant active services must be {sorted(want)}, "
            f"extra {sorted(active - want)}, missing {sorted(want - active)}"
        )
    if "api" in active:
        problems.append("participant mode must not start the api")
    for name in sorted(active):
        svc = services[name]
        if name in ("hubproxy", "vpn"):
            continue
        for net in _service_networks(svc):
            if name.startswith("sensor-") and net == "ingress":
                continue
            if (networks.get(net) or {}).get("internal") is not True:
                problems.append(f"participant service '{name}' is on non-internal network '{net}'")
        if svc.get("ports") and not name.startswith("sensor-"):
            problems.append(f"participant service '{name}' must not publish ports")
    # Sensors never share a network with hubproxy.
    hub_nets = _service_networks(services.get("hubproxy") or {})
    for name in sensors:
        if _service_networks(services[name]) & hub_nets:
            problems.append(f"sensor '{name}' shares a network with hubproxy")
    return problems


ALLOWED_OVERLAY_KEYS: dict[str, set[str]] = {
    "api": {"profiles"},
    "vpn": {"depends_on"},
    "ingest": {"networks"},
    "backup": {"mem_limit", "memswap_limit"},
}


def check_participant_overlay(base: Compose, overlay: Compose) -> list[str]:
    """M32: the overlay changes only profiles, depends_on, ingest networks and backup limits."""
    problems: list[str] = []
    extra_top = set(overlay) - {"services"}
    if extra_top:
        problems.append(f"participant overlay may only set services, found {sorted(extra_top)}")
    base_services: dict[str, Any] = base.get("services") or {}
    for name, svc in (overlay.get("services") or {}).items():
        allowed = ALLOWED_OVERLAY_KEYS.get(name)
        if allowed is None or name not in base_services:
            problems.append(f"participant overlay must not touch service '{name}'")
            continue
        svc = svc or {}
        if set(svc) - allowed:
            problems.append(f"participant overlay: '{name}' may only set {sorted(allowed)}")
        if name == "api" and list(svc.get("profiles") or []) != ["dashboard"]:
            problems.append("participant overlay: api profiles must be exactly [dashboard]")
        if name == "ingest":
            added = _service_networks(svc) - _service_networks(base_services[name])
            if added != {"hub-proxy"}:
                problems.append("participant overlay: ingest may only add the hub-proxy network")
        if name == "backup":
            for key in ("mem_limit", "memswap_limit"):
                limit = base_services[name].get(key) or base_services[name]["mem_limit"]
                if key in svc and _mem_bytes(str(svc[key])) > _mem_bytes(str(limit)):
                    problems.append(f"participant overlay must not raise backup {key}")
    return problems


def _mem_bytes(value: str) -> int:
    match = re.fullmatch(r"(\d+)([mg])", value)
    if match is None:
        return 1 << 62
    return int(match.group(1)) * (1024**2 if match.group(2) == "m" else 1024**3)


def check_hubproxy_allow(value: str, defaults: str) -> list[str]:
    """M32: ``HUBPROXY_ALLOW`` holds at most two ``<name>:443`` entries naming default hosts."""
    problems: list[str] = []
    hosts = {
        m.group(1)
        for m in re.finditer(r"^NETWORK_(?:HUB|FEED)_URL=https://([a-z0-9.-]+)", defaults, re.M)
    }
    entries = [e for e in value.split(",") if e.strip()]
    if not 1 <= len(entries) <= 2:
        problems.append("HUBPROXY_ALLOW must hold one or two entries")
    for entry in entries:
        host, _, port = entry.strip().rpartition(":")
        if port != "443" or not host:
            problems.append(f"HUBPROXY_ALLOW entry '{entry}' must be <name>:443")
        elif host not in hosts:
            problems.append(
                f"HUBPROXY_ALLOW host '{host}' is not a host of config/network-defaults.env"
            )
    return problems


def profile_view(compose: Compose, profiles: Iterable[str]) -> dict[str, Any]:
    """What compose would create for a profile set: active services as written, the networks and
    volumes they use, and nothing else. Used to prove that an install does not change."""
    services: dict[str, Any] = compose.get("services") or {}
    active = active_services(compose, profiles)
    used_networks: set[str] = set()
    for name in active:
        used_networks |= _service_networks(services[name])
    return {
        "services": {n: services[n] for n in sorted(active)},
        "networks": {
            n: (compose.get("networks") or {}).get(n) or {} for n in sorted(used_networks)
        },
    }

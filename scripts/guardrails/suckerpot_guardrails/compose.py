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
}
PROXY_ENV = {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class _Override(list[Any]):
    """A sequence tagged ``!override``: replaces the base value instead of extending it."""


class _Reset:
    """A value tagged ``!reset``: removes the key."""


class _Loader(yaml.SafeLoader):
    pass


def _override(loader: yaml.SafeLoader, node: yaml.Node) -> Any:
    if isinstance(node, yaml.SequenceNode):
        return _Override(loader.construct_sequence(node, deep=True))
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    return loader.construct_scalar(node)  # type: ignore[arg-type]


def _reset(loader: yaml.SafeLoader, node: yaml.Node) -> Any:
    return _Reset()


_Loader.add_constructor("!override", _override)
_Loader.add_constructor("!reset", _reset)


def _merge(base: Any, over: Any) -> Any:
    if isinstance(over, _Override):
        return list(over)
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
    for net, bridge in (("egress-proxy", "sp-egress"), ("samples", "sp-samples")):
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
    }
    for net, want in expected_members.items():
        if net in networks and members.get(net, set()) != want:
            problems.append(
                f"network '{net}' members must be exactly {sorted(want)}, "
                f"found {sorted(members.get(net, set()))}"
            )
    for net in ("egress-proxy", "vpn-uplink"):
        if net not in networks:
            problems.append(f"network '{net}' is missing")

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
    return problems


def find_hash_named_files(root: Path) -> list[str]:
    """Paths under ``root`` whose file name is a 64-hex string (a quarantined sample)."""
    skip = {".git", "node_modules", ".venv", "dist", "__pycache__"}
    found: list[str] = []
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in skip]
        found += [str(Path(current, f).relative_to(root)) for f in files if HEX64.match(f)]
    return found

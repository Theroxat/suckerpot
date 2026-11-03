"""Guardrails for the "behind a tunnel" deployment mode (docker-compose.tunnel.yml, Caddyfile.tunnel).

The tunnel Caddyfile must stay a copy of the main one apart from the allowed differences, only it
may trust a proxy header, and nothing in tunnel mode may publish a port or keep a direct route out.
"""

from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path
from typing import Any

import yaml

HUB = Path(__file__).resolve().parents[1]
MAIN = HUB / "Caddyfile"
TUNNEL = HUB / "Caddyfile.tunnel"


class _Loader(yaml.SafeLoader):
    pass


def _tag(loader: yaml.SafeLoader, tag_suffix: str, node: yaml.Node) -> Any:
    """Read ``!override`` and ``!reset`` as the plain value they wrap, marked by a tuple."""
    if isinstance(node, yaml.SequenceNode):
        value: Any = loader.construct_sequence(node, deep=True)
    elif isinstance(node, yaml.MappingNode):
        value = loader.construct_mapping(node, deep=True)
    else:
        value = loader.construct_scalar(node)  # type: ignore[arg-type]
    return (tag_suffix, value)


_Loader.add_multi_constructor("!", _tag)


def _overlay() -> dict[str, Any]:
    doc = yaml.load((HUB / "docker-compose.tunnel.yml").read_text(), Loader=_Loader)  # noqa: S506
    assert isinstance(doc, dict)
    return doc


def _base() -> dict[str, Any]:
    doc = yaml.safe_load((HUB / "docker-compose.yml").read_text())
    assert isinstance(doc, dict)
    return doc


def _code(path: Path) -> str:
    return "\n".join(
        line for line in path.read_text().splitlines() if not line.strip().startswith("#")
    )


# --- the two Caddyfiles ---


def _normalise_tunnel(text: str) -> str:
    """Undo the allowed differences, so what is left must equal the main Caddyfile."""
    out = text
    out = out.replace("\tauto_https off\n", "")
    out = out.replace("\t\ttrusted_proxies static private_ranges\n", "")
    out = out.replace("\t\tclient_ip_headers Cf-Connecting-Ip\n", "")
    out = re.sub(r"http://(\{\$HUB_[A-Z_]+\}):8080 \{", r"\1 {", out)
    return re.sub(
        r"reverse_proxy hub-api:8080 \{\n\s*header_up X-Forwarded-For \{client_ip\}\n\s*\}",
        "reverse_proxy hub-api:8080",
        out,
    )


def test_tunnel_caddyfile_is_the_main_one_apart_from_the_allowed_differences() -> None:
    assert _normalise_tunnel(_code(TUNNEL)) == _code(MAIN).replace(
        "# Caddy replaces any client-supplied forwarding header with the real peer address.\n", ""
    )


def test_tunnel_sites_are_plain_http_on_8080() -> None:
    code = _code(TUNNEL)
    assert "http://{$HUB_DOMAIN}:8080 {" in code
    assert "http://{$HUB_FEEDS_DOMAIN}:8080 {" in code
    assert "auto_https off" in code


def test_trust_settings_exist_only_in_the_tunnel_caddyfile() -> None:
    main, tunnel = _code(MAIN), _code(TUNNEL)
    for needle in ("trusted_proxies", "client_ip_headers", "Cf-Connecting-Ip", "header_up"):
        assert needle not in main, needle
    assert "trusted_proxies static private_ranges" in tunnel
    assert "client_ip_headers Cf-Connecting-Ip" in tunnel


def test_every_tunnel_reverse_proxy_sets_the_forwarded_for_header() -> None:
    code = _code(TUNNEL)
    proxies = re.findall(
        r"reverse_proxy hub-api:8080 \{\n\s*header_up X-Forwarded-For \{client_ip\}\n\s*\}", code
    )
    assert len(proxies) == code.count("reverse_proxy") == 2


def test_tunnel_caddyfile_logs_nowhere() -> None:
    code = _code(TUNNEL)
    blocks = re.findall(r"\blog\s*\{([^}]*)\}", code)
    assert len(blocks) == 3  # global, hub site, feeds site
    assert all(b.strip() == "output discard" for b in blocks)
    assert len(re.findall(r"\blog\b", code)) == len(blocks)


def test_tunnel_caddyfile_carries_the_delist_page_hashes() -> None:
    page = (HUB / "static" / "delist.html").read_text()
    caddy = TUNNEL.read_text()
    for tag in ("script", "style"):
        match = re.search(rf"<{tag}>(.*?)</{tag}>", page, flags=re.S)
        assert match is not None
        digest = base64.b64encode(hashlib.sha256(match.group(1).encode()).digest()).decode()
        assert f"sha256-{digest}" in caddy, f"update the {tag} hash in Caddyfile.tunnel"


# --- the compose overlay ---


def test_only_caddy_publishes_a_port_in_tunnel_mode() -> None:
    base, overlay = _base()["services"], _overlay()["services"]
    merged_ports = {n: s.get("ports") for n, s in base.items() if s.get("ports")}
    # The base file publishes only Caddy's 80 and 443; the overlay replaces them.
    assert set(merged_ports) == {"caddy"}
    assert [n for n, s in overlay.items() if "ports" in s] == ["caddy"]
    kind, ports = overlay["caddy"]["ports"]
    assert kind == "override" and len(ports) == 1
    assert ports[0].endswith(":8080") and ports[0].startswith("${HUB_BIND:?")
    assert "${HUB_HTTP_PORT:?" in ports[0]


def test_caddy_needs_no_sysctl_in_tunnel_mode() -> None:
    caddy = _overlay()["services"]["caddy"]
    assert "cap_add" not in caddy  # the binary needs NET_BIND_SERVICE to execute at all
    assert caddy["sysctls"] == ("reset", [])
    assert "8080" in " ".join(caddy["healthcheck"]["test"])
    mounts = caddy["volumes"]
    assert "./Caddyfile.tunnel:/etc/caddy/Caddyfile:ro" in mounts


def test_no_service_other_than_the_worker_and_admin_gets_a_new_network() -> None:
    overlay = _overlay()["services"]
    assert {n for n, s in overlay.items() if "networks" in s} == {"hub-worker", "hub-admin"}


def test_egress_clients_have_no_direct_route_out() -> None:
    doc = _overlay()
    base_nets = _base()["networks"]
    for name in ("hub-worker", "hub-admin"):
        kind, nets = doc["services"][name]["networks"]
        assert kind == "override" and sorted(nets) == ["egress", "hub-internal"]
        assert "hub-out" not in nets
        # Every network but the external proxy network is internal.
        assert base_nets["hub-internal"] == {"internal": True}
    egress = doc["networks"]["egress"]
    assert egress["external"] is True
    assert egress["name"].startswith("${HUB_EGRESS_NETWORK:?")


def test_the_only_non_internal_networks_are_hub_public_and_the_external_one() -> None:
    nets = _base()["networks"]
    open_nets = {n for n, v in nets.items() if not v.get("internal")}
    assert open_nets == {"hub-public", "hub-out"}
    users: dict[str, set[str]] = {n: set() for n in open_nets}
    overlay = _overlay()["services"]
    for name, svc in _base()["services"].items():
        nets_of = overlay.get(name, {}).get("networks", svc.get("networks", []))
        if isinstance(nets_of, tuple):
            nets_of = nets_of[1]
        for n in nets_of:
            if n in users:
                users[n].add(name)
    assert users == {"hub-public": {"caddy"}, "hub-out": set()}


def test_proxy_environment_is_set_for_egress_clients() -> None:
    for name in ("hub-worker", "hub-admin"):
        env = _overlay()["services"][name]["environment"]
        assert env["HTTPS_PROXY"].startswith("${HUB_EGRESS_PROXY:?")
        assert env["HTTP_PROXY"] == env["HTTPS_PROXY"]
        assert env["NO_PROXY"] == "hub-db,localhost,127.0.0.1"


def test_httpx_clients_honour_the_proxy_environment() -> None:
    """Every outbound client reads HTTPS_PROXY: none disables trust_env or sets its own route."""
    clients = 0
    for path in (HUB / "hub").rglob("*.py"):
        src = path.read_text()
        if "httpx" not in src:
            continue
        clients += src.count("httpx.AsyncClient(") + src.count("httpx.Client(")
        for bad in ("trust_env", "transport=", "proxy=", "proxies=", "mounts="):
            assert bad not in src, (path.name, bad)
    assert clients >= 2


def test_overlay_and_example_name_the_new_variables() -> None:
    example = (HUB / ".env.example").read_text()
    for var in ("HUB_BIND", "HUB_HTTP_PORT", "HUB_EGRESS_NETWORK", "HUB_EGRESS_PROXY"):
        assert re.search(rf"^#{var}=", example, flags=re.M), var
    assert "http://user:change-me@vpn:8888" in example


def test_secrets_directory_is_ignored() -> None:
    lines = (HUB / ".gitignore").read_text().split()
    assert "secrets/" in lines

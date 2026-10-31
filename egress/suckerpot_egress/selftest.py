"""Live self-test, run inside a container: ``python -m suckerpot_egress.selftest``.

Prints one ``PASS`` / ``FAIL`` line per check and exits non-zero on any FAIL. It never prints an
address from the VPN: only whether the exit address is inside the allow-list.

Flags (default: ``--direct --gate``):
  --direct             direct TCP/UDP/DNS probes must all fail (no route out except the proxy)
  --no-connect H:P     a direct TCP connection to H:P must fail (repeatable)
  --gate               run the gate check; it must be open (or the reason given by --expect)
  --expect REASON      the gate reason that counts as a PASS (default: ok)
  --refuse H:P         CONNECT through the proxy to H:P must be refused (repeatable)
  --echo-fails         an echo through the proxy must fail
"""

from __future__ import annotations

import argparse
import asyncio
import socket
import sys

import httpx

from suckerpot_egress.gate import EgressGate
from suckerpot_egress.settings import EgressSettings
from suckerpot_egress.tunnel import TunnelError, connect_via_proxy

PROBE_TARGETS = ("1.1.1.1", "9.9.9.9")
DNS_NAME = "example.com"
PROBE_TIMEOUT_S = 3.0


def _line(ok: bool, name: str, detail: str = "") -> bool:
    print(f"{'PASS' if ok else 'FAIL'} {name}" + (f" ({detail})" if detail else ""))
    return ok


def tcp_fails(host: str, port: int) -> bool:
    try:
        socket.create_connection((host, port), timeout=PROBE_TIMEOUT_S).close()
    except OSError:
        return True
    return False


def udp_dns_unanswered(server: str) -> bool:
    query = (
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(PROBE_TIMEOUT_S)
        try:
            s.sendto(query, (server, 53))
            s.recvfrom(512)
        except OSError:
            return True
    return False


def resolve_fails(name: str) -> bool:
    try:
        socket.getaddrinfo(name, 443)
    except OSError:
        return True
    return False


def _split_target(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    return host, int(port)


def run_direct(extra: list[str]) -> list[bool]:
    out = [_line(tcp_fails(h, 443), f"direct tcp {h}:443 fails") for h in PROBE_TARGETS]
    out.append(
        _line(udp_dns_unanswered(PROBE_TARGETS[0]), f"udp dns {PROBE_TARGETS[0]} unanswered")
    )
    out.append(_line(resolve_fails(DNS_NAME), f"getaddrinfo {DNS_NAME} fails"))
    for target in extra:
        host, port = _split_target(target)
        out.append(_line(tcp_fails(host, port), f"direct tcp {target} fails"))
    return out


async def run_gate(gate: EgressGate, expect: str) -> bool:
    status = await gate.check()
    detail = f"reason={status.reason}"
    if status.open and gate.settings.allowed_cidrs:
        detail += ", in allow-list: yes"
    elif status.reason == "ip_not_allowed":
        detail += ", in allow-list: no"
    return _line(status.reason == expect, "gate check", detail)


def refused(settings: EgressSettings, target: str) -> bool:
    host, port = _split_target(target)
    try:
        connect_via_proxy(settings, host, port, timeout=PROBE_TIMEOUT_S, validate=False).close()
    except (TunnelError, OSError):
        return True
    return False


async def echo_fails(settings: EgressSettings) -> bool:
    url = settings.echo_urls[0]
    proxy = httpx.Proxy(settings.proxy_url, auth=(settings.proxy_user, settings.proxy_password))
    try:
        async with httpx.AsyncClient(proxy=proxy, trust_env=False, timeout=5.0) as client:
            await client.get(url)
    except httpx.HTTPError:
        return True
    return False


async def main_async(args: argparse.Namespace) -> int:
    settings = EgressSettings.from_env()
    results: list[bool] = []
    if args.direct or args.no_connect:
        results += run_direct(args.no_connect)
    gate = EgressGate(settings)
    try:
        if args.gate:
            results.append(await run_gate(gate, args.expect))
        for target in args.refuse:
            results.append(_line(refused(settings, target), f"proxy refuses CONNECT {target}"))
        if args.echo_fails:
            results.append(_line(await echo_fails(settings), "echo through the proxy fails"))
    finally:
        await gate.aclose()
    return 0 if all(results) else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="suckerpot_egress.selftest")
    p.add_argument("--direct", action="store_true")
    p.add_argument("--no-connect", action="append", default=[], metavar="HOST:PORT")
    p.add_argument("--gate", action="store_true")
    p.add_argument("--expect", default="ok")
    p.add_argument("--refuse", action="append", default=[], metavar="HOST:PORT")
    p.add_argument("--echo-fails", action="store_true")
    args = p.parse_args(argv)
    if not (args.direct or args.no_connect or args.gate or args.refuse or args.echo_fails):
        args.direct = args.gate = True
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())

"""Shared fixtures of the feed tests and the golden-vector generator.

Regenerate the vectors with ``python -m tests.test_feeds_common`` from ``netproto/`` (only when
the spec changes; review the diff). The keys below are fixed test keys, never used anywhere else.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from suckerpot_netproto.feeds import (
    RenderContext,
    Rendered,
    build_index,
    index_list,
    index_other,
    minisign,
    render_index,
    render_list,
)

VECTORS = Path(__file__).parent / "feed_vectors"
GOLDEN = VECTORS / "golden"
SECRET = minisign.SecretKey(bytes(range(64, 96)), bytes(range(1, 9)))
SECRET2 = minisign.SecretKey(bytes(range(96, 128)), bytes(range(11, 19)))
GEN = datetime(2026, 11, 1, 13, 0, 0, tzinfo=UTC)
UNTIL = datetime(2026, 11, 4, 13, 0, 0, tzinfo=UTC)
SERIAL = 4812
SIGN_TS = 1_793_538_000


def ctx(list_id: str, **kw: Any) -> RenderContext:
    base: dict[str, Any] = {
        "list_id": list_id,
        "serial": SERIAL,
        "generated_at": GEN,
        "valid_until": UNTIL,
        "allow_documentation": True,
    }
    base.update(kw)
    return RenderContext(**base)


def entry(value: str, family: int | str, **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "value": value,
        "family": family,
        "tier": "standard",
        "categories": ["payload-host"],
        "first_seen": "2026-10-26",
        "last_seen": "2026-10-31",
        "expires": "2026-11-14",
    }
    base.update(kw)
    return base


OUTBOUND: list[dict[str, Any]] = [
    entry("203.0.113.50", 4, categories=["c2"], families=["mirai"], ports=[23, 2323],
          first_seen="2026-10-28", last_seen="2026-10-30", expires="2026-11-29"),
    entry("2001:db8::50", 6, categories=["c2"], families=["gafgyt"], ports=[443],
          reported=True),
    entry("198.51.100.9", 4, tier="high", tags=["mirai"], families=["mirai"], reported=True),
    entry("192.0.2.77", 4, categories=["malware-drop", "payload-host"], tags=["cve-2024-3721"]),
]  # fmt: skip
INBOUND: list[dict[str, Any]] = [
    entry("198.51.100.200", 4, tier="high", categories=["brute-force", "command-exec"],
          services=["telnet", "ssh"], tags=["mirai", "recon"]),
    entry("2001:db8:1::7", 6, categories=["exploit"], services=["web"], tags=["php2shell"]),
    entry("192.0.2.14", 4, categories=["login-success"], services=["ssh"]),
]  # fmt: skip
DOMAINS: list[dict[str, Any]] = [
    entry("dl.example.net", "dns", families=["xmrig"], tags=["crypto-miner"]),
    entry("cnc.example.org", "dns", tier="high", categories=["c2"], families=["mirai"],
          ports=[23]),
]  # fmt: skip

SETS: dict[str, list[dict[str, Any]]] = {
    "outbound": OUTBOUND,
    "inbound": INBOUND,
    "outbound-domains": DOMAINS,
}


def render_all() -> dict[str, Rendered]:
    return {name: render_list(ctx(name), entries) for name, entries in SETS.items()}


def build_signed_index(
    rendered: dict[str, Rendered] | None = None,
    *,
    serial: int = SERIAL,
    valid_until: datetime = UNTIL,
    secret: minisign.SecretKey = SECRET,
) -> tuple[bytes, str, dict[str, bytes], dict[str, str]]:
    """(index bytes, index signature, file bytes, file signatures)."""
    rendered = rendered or render_all()
    files: dict[str, bytes] = {}
    lists = []
    for r in rendered.values():
        files.update(r.files)
        lists.append(index_list(r, dict.fromkeys(r.files, GEN)))
    other = [index_other("stats.json", b'{"members":0}\n')]
    files["stats.json"] = b'{"members":0}\n'
    index = build_index(
        serial=serial,
        generated_at=GEN,
        valid_until=valid_until,
        key_id=secret.public.key_id_hex,
        lists=lists,
        other=other,
    )
    raw = render_index(index)
    sig = minisign.sign_feed_file(raw, "index.json", serial, secret, timestamp=SIGN_TS)
    sigs = {
        name: minisign.sign_feed_file(data, name, serial, secret, timestamp=SIGN_TS)
        for name, data in files.items()
    }
    return raw, sig, files, sigs


def main() -> None:  # pragma: no cover - generator
    GOLDEN.mkdir(parents=True, exist_ok=True)
    raw, sig, files, sigs = build_signed_index()
    out = {"index.json": raw, "index.json.minisig": sig.encode(), **files}
    for name in ("outbound.txt", "inbound.json", "outbound-domains.txt"):
        out[f"{name}.minisig"] = sigs[name].encode()
    for name, data in out.items():
        (GOLDEN / name).write_bytes(data)
    keys = {
        "_comment": "Fixed test keys, never used anywhere else. Signatures are deterministic.",
        "secret_seed_hex": SECRET.seed.hex(),
        "key_id_bytes_hex": SECRET.key_id.hex(),
        "key_id": SECRET.public.key_id_hex,
        "public_key": SECRET.public.encoded,
        "serial": SERIAL,
        "sign_timestamp": SIGN_TS,
        "secret_key_file": minisign.serialize_secret_key(SECRET),
    }
    (VECTORS / "keys.json").write_text(json.dumps(keys, indent=2) + "\n")
    print(f"wrote {len(out)} golden files", file=sys.stderr)


if __name__ == "__main__":
    main()

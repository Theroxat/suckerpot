"""Per-deployment fake identity, derived from a random secret kept under the data directory.

The secret is generated once (mode 0600) and everything a client can learn about the "server"
(patch version, run id, replication id, kernel build, uptime at start, memory baseline, the
handful of cached keys) is derived from it with HMAC, so two deployments never look alike and
nothing can be predicted from public data.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import logging
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("redis_sensor.identity")

SECRET_FILE = "profile_secret"  # noqa: S105 - a file name, not a secret
DEFAULT_SERIES = "7.2"
PATCHES = (4, 5, 6, 7, 8, 9)
KERNELS = ("6.8.0-31-generic", "6.8.0-35-generic", "6.8.0-45-generic", "6.8.0-48-generic")


def write_private(path: Path, data: bytes) -> None:
    """Atomically write ``data`` with mode 0600."""
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    tmp.replace(path)


def load_or_create_secret(directory: str | Path) -> str:
    root = Path(directory)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = root / SECRET_FILE
    try:
        value = path.read_text().strip()
    except OSError:
        value = ""
    if len(value) < 32:
        value = secrets.token_hex(32)
        write_private(path, (value + "\n").encode())
        log.warning("generated new profile secret in %s (persist the data volume)", root)
    return value


def valid_version(text: str) -> bool:
    parts = text.split(".")
    return len(parts) in (2, 3) and all(p.isdigit() and len(p) <= 3 for p in parts)


@dataclass(frozen=True)
class Profile:
    version: str
    run_id: str
    replid: str
    build_id: str
    kernel: str
    uptime_offset: int  # seconds the "server" was up before this process started
    base_memory: int  # bytes
    rss_extra: int
    local_ip: str
    saved_ago: int  # seconds since the last "RDB save" at process start
    keys: tuple[tuple[bytes, bytes], ...]


def _digest(secret: str, label: str) -> bytes:
    return hmac.new(secret.encode(), label.encode(), hashlib.sha256).digest()


def _hex(secret: str, label: str, n: int) -> str:
    out = ""
    counter = 0
    while len(out) < n:
        out += _digest(secret, f"{label}/{counter}").hex()
        counter += 1
    return out[:n]


def _num(secret: str, label: str, low: int, high: int) -> int:
    return low + int.from_bytes(_digest(secret, label)[:8], "big") % (high - low + 1)


def derive_profile(secret: str, version: str = "") -> Profile:
    """Build the profile. ``version`` is a series (``7.2``) or a full version (``7.2.5``)."""
    version = version.strip()
    if not valid_version(version):
        version = DEFAULT_SERIES
    if version.count(".") == 1:
        version = f"{version}.{PATCHES[_num(secret, 'patch', 0, len(PATCHES) - 1)]}"
    keys: list[tuple[bytes, bytes]] = []
    pool = (
        (
            "session:" + _hex(secret, "k1", 12),
            '{"uid":%d,"role":"user"}' % _num(secret, "u1", 100, 999),
        ),
        ("cache:homepage", "<html><body>cached</body></html>"),
        ("user:%d:visits" % _num(secret, "u2", 1000, 1999), str(_num(secret, "v2", 3, 400))),
        ("queue:email:last", "job-" + _hex(secret, "k4", 8)),
        ("rate:api:%d" % _num(secret, "u3", 10, 99), str(_num(secret, "v3", 1, 60))),
    )
    count = _num(secret, "nkeys", 3, len(pool))
    for key, value in pool[:count]:
        keys.append((key.encode(), value.encode()))
    return Profile(
        version=version,
        run_id=_hex(secret, "run", 40),
        replid=_hex(secret, "replid", 40),
        build_id=_hex(secret, "build", 16),
        kernel=KERNELS[_num(secret, "kernel", 0, len(KERNELS) - 1)],
        uptime_offset=_num(secret, "uptime", 2 * 86400, 70 * 86400),
        base_memory=_num(secret, "mem", 880_000, 1_450_000),
        rss_extra=_num(secret, "rss", 7_500_000, 11_500_000),
        local_ip="10.%d.%d.%d"
        % (_num(secret, "ip1", 0, 30), _num(secret, "ip2", 0, 250), _num(secret, "ip3", 2, 250)),
        saved_ago=_num(secret, "saved", 40, 3000),
        keys=tuple(keys),
    )


def load_profile(directory: str | Path, version: str = "") -> Profile:
    return derive_profile(load_or_create_secret(directory), version)

"""Per-deployment fake host identity.

The daemon ID, kernel build, hardware, container and image IDs and creation dates come from a
random secret generated once and stored in ``<data_dir>/profile.json`` (mode 0600). Nothing
here is taken from public data and the secret is never shown to clients.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import random
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("docker_sensor.profile")

_KERNELS = ["6.8.0-45-generic", "6.8.0-48-generic", "6.8.0-50-generic", "6.8.0-51-generic"]
_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


@dataclass(frozen=True)
class FakeContainer:
    id: str
    name: str
    image: str
    image_id: str
    command: str
    created: int
    ports: tuple[tuple[int, int], ...]  # (private, public) TCP ports; public 0 = not published
    ip: str


@dataclass(frozen=True)
class Profile:
    secret: bytes
    created: float
    daemon_id: str
    kernel: str
    cpus: int
    mem_bytes: int
    boot_ts: float
    net_prefix: str
    containers: tuple[FakeContainer, ...]
    images: tuple[tuple[str, str, int, int], ...]  # (repo:tag, id, size, created)

    def derive(self, label: str, length: int = 64) -> str:
        digest = hmac.new(self.secret, label.encode(), hashlib.sha256).hexdigest()
        return digest[:length]

    def rng(self, label: str) -> random.Random:
        digest = hmac.new(self.secret, label.encode(), hashlib.sha256).digest()
        return random.Random(int.from_bytes(digest[:16], "big"))  # noqa: S311 - content only


_IMAGES = [
    ("nginx:1.27", 192_000_000, "nginx -g 'daemon off;'", [(80, 8080)]),
    ("postgres:16", 432_000_000, "docker-entrypoint.sh postgres", [(5432, 0)]),
    ("redis:7.4", 117_000_000, "docker-entrypoint.sh redis-server", [(6379, 0)]),
    ("grafana/grafana:11.2.0", 466_000_000, "/run.sh", [(3000, 3000)]),
]
# Images a typical host already has (bots create from these without pulling), then a few
# application images of which a per-deployment subset is present.
_BASE_IMAGES = [
    ("alpine:latest", 8_400_000),
    ("ubuntu:latest", 78_100_000),
    ("ubuntu:22.04", 77_900_000),
    ("busybox:latest", 4_300_000),
    ("debian:bookworm", 117_000_000),
    ("nginx:latest", 192_000_000),
]
_APP_IMAGES = [
    ("node:20-alpine", 135_000_000),
    ("golang:1.23-alpine", 252_000_000),
    ("mysql:8.0", 573_000_000),
    ("traefik:v3.1", 183_000_000),
    ("portainer/portainer-ce:2.21.0", 290_000_000),
    ("mariadb:11", 405_000_000),
]
_NAMES = {
    "nginx:1.27": "edge-proxy",
    "postgres:16": "app-db",
    "redis:7.4": "app-cache",
    "grafana/grafana:11.2.0": "metrics",
}


def build_profile(secret: bytes, created: float) -> Profile:
    base = Profile(secret, created, "", "", 0, 0, 0.0, "", (), ())
    rng = base.rng("layout")
    daemon = ":".join("".join(rng.choice(_B32) for _ in range(4)) for _ in range(12))
    prefix = f"172.{rng.choice([17, 18])}.0"
    boot = created - rng.randrange(3, 60) * 86400 - rng.randrange(0, 86400)
    images = []
    containers = []
    ip_last = 2
    for i, (ref, size, cmd, ports) in enumerate(_IMAGES):
        image_id = "sha256:" + base.derive(f"image-{i}")
        img_created = int(created - rng.randrange(20, 120) * 86400)
        images.append((ref, image_id, size, img_created))
        if i < 3 or rng.random() < 0.5:
            containers.append(
                FakeContainer(
                    id=base.derive(f"container-{i}"),
                    name=_NAMES[ref],
                    image=ref,
                    image_id=image_id,
                    command=cmd,
                    created=int(boot + rng.randrange(60, 7200)),
                    ports=tuple(ports),
                    ip=f"{prefix}.{ip_last}",
                )
            )
            ip_last += 1
    extra_rng = base.rng("extra-images")
    extra = _BASE_IMAGES + extra_rng.sample(_APP_IMAGES, extra_rng.choice([1, 2, 3]))
    for j, (ref, size) in enumerate(extra):
        jitter = extra_rng.randrange(0, 2_000_000)
        images.append(
            (
                ref,
                "sha256:" + base.derive(f"extra-image-{j}"),
                size + jitter,
                int(created - extra_rng.randrange(10, 200) * 86400),
            )
        )
    return Profile(
        secret=secret,
        created=created,
        daemon_id=daemon,
        kernel=rng.choice(_KERNELS),
        cpus=rng.choice([4, 4, 8]),
        mem_bytes=rng.choice([8, 16, 16, 32]) * 1024**3 - rng.randrange(0, 600) * 1024**2,
        boot_ts=boot,
        net_prefix=prefix,
        containers=tuple(containers),
        images=tuple(images),
    )


def load_or_create_profile(data_dir: str) -> Profile:
    """Read the profile from ``data_dir`` or create it. Falls back to an ephemeral secret."""
    path = Path(data_dir) / "profile.json"
    try:
        doc = json.loads(path.read_text())
        secret = bytes.fromhex(doc["secret"])
        created = float(doc["created"])
        if len(secret) >= 16:
            return build_profile(secret, created)
    except (OSError, ValueError, KeyError, TypeError):
        pass
    secret = secrets.token_bytes(32)
    created = float(int(time.time()))
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps({"secret": secret.hex(), "created": created}))
        os.replace(tmp, path)
    except OSError:
        log.warning("cannot persist the profile in %s; identity will change on restart", data_dir)
    return build_profile(secret, created)

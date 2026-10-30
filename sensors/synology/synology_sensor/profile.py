"""Per-deployment fake NAS identity.

The host name, model and serial come from a random secret generated once and stored in
``<data_dir>/profile.json`` (mode 0600). Nothing here is taken from public data and the secret
is never shown to clients.
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

log = logging.getLogger("synology_sensor.profile")

# (model shown by DSM, host name pool). Host names are what an owner would plausibly pick.
_MODELS = ["DS220+", "DS418", "DS918+", "DS920+", "DS923+", "DS720+", "DS1621+", "RS820+"]
_NAMES = ["DiskStation", "NAS01", "nas", "SynologyNAS", "Storage", "FileServer", "Diskstation1"]


@dataclass(frozen=True)
class Profile:
    secret: bytes
    created: float
    hostname: str
    model: str
    serial: str

    def rng(self, label: str) -> random.Random:
        digest = hmac.new(self.secret, label.encode(), hashlib.sha256).digest()
        return random.Random(int.from_bytes(digest[:16], "big"))  # noqa: S311 - content only


def build_profile(secret: bytes, created: float) -> Profile:
    base = Profile(secret, created, "", "", "")
    rng = base.rng("layout")
    model = rng.choice(_MODELS)
    # Models are sometimes used as the host name (DS920plus), otherwise a friendly name.
    hostname = (
        model.replace("+", "plus")
        if rng.random() < 0.4
        else rng.choice(_NAMES) + (str(rng.randrange(2, 9)) if rng.random() < 0.2 else "")
    )
    serial = "{}{}{}{:06d}".format(
        rng.choice(["19", "20", "21", "22"]),
        rng.choice(["0", "1", "2"]) + rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ"),
        rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ") + rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ"),
        rng.randrange(0, 999999),
    )
    return Profile(secret, created, hostname, model, serial)


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

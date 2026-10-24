"""The per-deployment secret that seeds the fake device identity.

Generated once, mode 0600. It is deliberately random and not derived from anything an outsider
can observe, otherwise the fake MAC, address and uptime could be predicted and the sensor
recognised.
"""

from __future__ import annotations

import logging
import os
import secrets
from pathlib import Path

log = logging.getLogger("telnet_sensor.secret")
SECRET_NAME = "profile_secret"  # noqa: S105 - a file name


def load_or_create_secret(data_dir: str) -> str:
    directory = Path(data_dir)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / SECRET_NAME
    try:
        value = path.read_text().strip()
    except FileNotFoundError:
        value = ""
    if len(value) >= 32:
        return value
    value = secrets.token_hex(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(value + "\n")
    os.chmod(path, 0o600)
    log.warning("generated a new profile secret in %s; keep this directory on a volume", directory)
    return value

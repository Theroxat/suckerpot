"""Clustering keys: the fingerprints that tie sessions of one campaign together.

Pure functions, no I/O and no regular expressions; every input is attacker-controlled and
bounded here. A key is ``(kind, value)`` with ``value`` at most 128 characters.

* ``script``        sha256 of the normalised command sequence (two or more commands);
* ``exploit``       sha256 of method + normalised path + body shape of a payload-tagged request;
* ``credlist``      sha256 of the first 32 sorted ``user:password`` pairs of a brute-force run;
* ``payload_host``  a host that served a download (set from the indicators);
* ``hash``          a file hash seen in the session (from the indicators);
* ``family``        the malware family a threat-intel source named (from the indicators).
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence

from ingest.normalize import fingerprint, normalize_commands, normalize_text, normalize_token

Key = tuple[str, str]

KINDS = ("script", "payload_host", "hash", "family", "exploit", "credlist")
MIN_SCRIPT_COMMANDS = 2
MIN_CREDLIST_ATTEMPTS = 20
CREDLIST_PAIRS = 32
MAX_KEYS_PER_SESSION = 16
#: How many keys of each kind one session may carry: a session cannot bridge more than this.
KEY_CAPS = {"script": 1, "exploit": 3, "credlist": 1, "hash": 4, "payload_host": 4, "family": 4}
MAX_VALUE = 128
#: Tags of a request or statement that carries a payload: only these get an ``exploit`` key.
PAYLOAD_TAGS = ("php2shell", "sql-rce", "container-escape", "redis-rogue-master")
#: Hosts that serve legitimate software. A download from one of them says nothing about a campaign.
BENIGN_HOST_SUFFIXES = (
    "github.com", "githubusercontent.com", "ubuntu.com", "debian.org", "pypi.org",
    "pythonhosted.org", "npmjs.org", "golang.org", "kernel.org", "fedoraproject.org",
    "centos.org", "alpinelinux.org", "docker.com", "docker.io", "microsoft.com",
    "windowsupdate.com", "google.com", "googleapis.com", "cloudflare.com", "amazonaws.com",
    "gnu.org", "sourceforge.net", "apache.org", "mozilla.org",
)  # fmt: skip


def _sha(parts: Iterable[str]) -> str:
    return hashlib.sha256("\n".join(parts).encode("utf-8", "replace")).hexdigest()


def is_benign_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == s or host.endswith("." + s) for s in BENIGN_HOST_SUFFIXES)


def script_key(commands: Sequence[str]) -> Key | None:
    """The fingerprint of what the session typed, if it typed enough to mean something."""
    normalized = normalize_commands(commands)
    if len(normalized) < MIN_SCRIPT_COMMANDS:
        return None
    return ("script", fingerprint(normalized))


def _body_shape(body: str) -> str:
    """The shape of a request body: field names for a form, the opening bracket for JSON."""
    body = body[:512].strip()
    if not body:
        return "empty"
    if body[0] in "{[":
        return "json"
    if "=" in body:
        names = sorted({pair.split("=", 1)[0] for pair in body.split("&") if "=" in pair})
        return "form:" + ",".join(n[:32] for n in names[:16])
    return "raw:" + str(len(body).bit_length())


def _path_shape(path: str) -> str:
    path = path[:512]
    base, _, query = path.partition("?")
    segments = [normalize_token(seg) for seg in base.lower().split("/")]
    names = sorted({pair.split("=", 1)[0] for pair in query.split("&") if pair})
    shape = "/".join(segments)
    return shape + ("?" + ",".join(n[:32] for n in names[:16]) if names else "")


def exploit_key(kind: str, method: str, path: str, body: str) -> Key:
    """Same exploit, other target: the path and body are normalised before hashing.

    ``kind`` is the event type; a statement (no path) is hashed through the command normaliser.
    """
    if path:
        shape = f"{_path_shape(path)}|{_body_shape(body)}"
    else:
        shape = "|".join(normalize_text(body)) or _body_shape(body)
    return ("exploit", _sha([kind, method.upper()[:16], shape]))


def credlist_key(pairs: Iterable[tuple[str, str]]) -> Key | None:
    """A credential list, whatever order it was tried in: the first 32 sorted distinct pairs
    (all of them when there are fewer, but at least 20)."""
    distinct = sorted({f"{u[:64]}:{p[:64]}" for u, p in pairs})
    if len(distinct) < MIN_CREDLIST_ATTEMPTS:
        return None
    return ("credlist", _sha(distinct[:CREDLIST_PAIRS]))


def clamp(key: Key) -> Key | None:
    kind, value = key
    value = value.strip().lower()[:MAX_VALUE]
    return (kind, value) if kind in KINDS and value else None


def cap_keys(keys: Iterable[Key]) -> set[Key]:
    """Clamp every key and keep at most ``KEY_CAPS[kind]`` per kind (deterministic)."""
    kept: dict[str, list[Key]] = {}
    for key in sorted(k for k in (clamp(k) for k in keys) if k):
        bucket = kept.setdefault(key[0], [])
        if len(bucket) < KEY_CAPS[key[0]]:
            bucket.append(key)
    return {k for bucket in kept.values() for k in bucket}

"""Pure helpers that look at what an attacker asked the daemon to do.

Nothing here runs or evaluates anything: strings are searched with ``str`` methods only (no
regular expressions) and JSON is parsed after size and nesting checks.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

MINER_WORDS = (
    "xmrig", "kinsing", "kdevtmpfsi", "c3pool", "monero", "minerd", "cpuminer", "cryptonight",
    "nanopool", "supportxmr", "minexmr", "moneroocean", "stratum+", "xmr-stak", "xmr.",
    "kthreaddi", "ethminer", "nicehash", "hashvault", "2miners",
)  # fmt: skip
# Bind sources that give the container the host's files.
SENSITIVE_SOURCES = (
    "/etc", "/root", "/proc", "/sys", "/home", "/var/run/docker.sock", "/run/docker.sock",
    "/var/lib/docker", "/boot", "/dev", "/var/spool/cron", "/usr", "/bin", "/lib",
)  # fmt: skip
_URL_SCHEMES = ("http://", "https://", "ftp://", "tftp://")
_URL_STOP = frozenset(" \t\r\n\"'`;|<>()\\{}$^")
_URL_TRIM = ".,;:)]}'\""
_TOOLS = ("wget", "curl", "tftp", "ftpget", "fetch", "aria2c", "busybox")
MAX_URL = 2048
MAX_URLS = 8


def depth_steps(raw: bytes, max_depth: int, step: int = 8192) -> Iterator[bool | None]:
    """Nesting check in slices: yields None between slices, then the verdict (True = ok).

    The fast path is two C-level counts: a document with at most ``max_depth`` brackets in
    total cannot be deeper. Only then a linear scan that skips strings is needed; callers that
    must not hog the event loop drive the generator and yield between slices.
    """
    if raw.count(b"[") + raw.count(b"{") <= max_depth:
        yield True
        return
    depth = 0
    in_str = False
    esc = False
    for off in range(0, len(raw), step):
        for byte in raw[off : off + step]:
            if in_str:
                if esc:
                    esc = False
                elif byte == 0x5C:
                    esc = True
                elif byte == 0x22:
                    in_str = False
            elif byte == 0x22:
                in_str = True
            elif byte in (0x5B, 0x7B):
                depth += 1
                if depth > max_depth:
                    yield False
                    return
            elif byte in (0x5D, 0x7D):
                depth -= 1
        yield None
    yield True


def depth_ok(raw: bytes, max_depth: int) -> bool:
    """True if JSON text ``raw`` nests at most ``max_depth`` levels."""
    verdict: bool | None = None
    for verdict in depth_steps(raw, max_depth):
        if verdict is not None:
            break
    return bool(verdict)


def bounded_json(
    raw: bytes, *, max_bytes: int, max_depth: int, depth_checked: bool | None = None
) -> Any | None:
    """Parse ``raw`` as JSON after checking size and depth first. None if not acceptable.

    ``depth_checked`` carries a verdict the caller already computed (cooperatively, in slices).
    """
    if not raw or len(raw) > max_bytes:
        return None
    if not (depth_ok(raw, max_depth) if depth_checked is None else depth_checked):
        return None
    try:
        return json.loads(raw)
    except (ValueError, RecursionError, UnicodeDecodeError):
        return None


MAX_MATCHES = 64  # scheme matches examined per call (empty ones included): keeps the scan linear


def find_urls(text: str, limit: int = MAX_URLS) -> list[str]:
    """Extract URLs (http, https, ftp, tftp) without regular expressions.

    Work is bounded: every scheme match counts (also "http:// " with nothing behind it), at most
    ``MAX_MATCHES`` are examined, and each scheme is searched forward only once.
    """
    low = text.lower()
    out: list[str] = []
    i = 0
    nxt: dict[str, int] = {}  # next known position of each scheme (-1: none left)
    for _ in range(MAX_MATCHES):
        if len(out) >= limit:
            break
        best = -1
        scheme = ""
        for s in _URL_SCHEMES:
            pos = nxt.get(s, -2)
            if pos != -1 and pos < i:
                pos = low.find(s, i)
            nxt[s] = pos
            if pos != -1 and (best == -1 or pos < best):
                best, scheme = pos, s
        if best == -1:
            break
        end = best + len(scheme)
        stop = min(len(text), best + MAX_URL)
        while end < stop and text[end] not in _URL_STOP:
            if text[end] == "&" and text[end + 1 : end + 2] == "&":  # shell "&&", not a query
                break
            end += 1
        url = text[best:end].rstrip(_URL_TRIM)
        if len(url) > len(scheme):
            out.append(url)
        i = max(end, best + len(scheme))
    return out


def detect_tool(text: str) -> str:
    low = text.lower()
    for tool in _TOOLS:
        if tool in low:
            return tool
    return "unknown"


def is_miner(*parts: str) -> bool:
    low = " ".join(parts).lower()
    return any(word in low for word in MINER_WORDS)


def as_str_list(value: Any, *, max_items: int = 64, max_chars: int = 4096) -> list[str]:
    """A JSON value that should be a list of strings (or one string), bounded in count and bytes."""
    if isinstance(value, str):
        return [value[:max_chars]]
    if not isinstance(value, list):
        return []
    out: list[str] = []
    total = 0
    for item in value[:max_items]:
        if not isinstance(item, str | int | float):
            continue
        text = str(item)
        room = max_chars - total
        if room <= 0:
            break
        out.append(text[:room])
        total += len(text)
    return out


def join_command(parts: list[str], limit: int = 4000) -> str:
    out: list[str] = []
    size = 0
    for p in parts:
        if size + len(p) + 1 > limit:
            out.append(p[: max(0, limit - size)])
            break
        out.append(p)
        size += len(p) + 1
    return " ".join(out)


def _bind_source(bind: str) -> str:
    return bind.split(":", 1)[0]


def _is_host_path(src: str) -> bool:
    if src == "/" or src.startswith("/host"):
        return True
    return any(src == s or src.startswith(s + "/") for s in SENSITIVE_SOURCES)


@dataclass
class ContainerSpec:
    """What a ``containers/create`` body asks for, reduced to bounded values."""

    image: str = ""
    cmd: list[str] = field(default_factory=list)
    entrypoint: list[str] = field(default_factory=list)
    env: list[str] = field(default_factory=list)
    binds: list[str] = field(default_factory=list)
    privileged: bool = False
    pid_mode: str = ""
    network_mode: str = ""
    cap_add: list[str] = field(default_factory=list)
    user: str = ""
    tty: bool = False
    auto_remove: bool = False
    hostname: str = ""
    flags: set[str] = field(default_factory=set)

    @property
    def input(self) -> str:
        return join_command(self.entrypoint + self.cmd)

    def compact(self) -> ContainerSpec:
        """A small copy for the per-IP state: what ``docker ps`` / inspect / exec need."""
        return ContainerSpec(
            image=self.image[:256],
            cmd=cap_list(self.cmd, 8, 512),
            entrypoint=cap_list(self.entrypoint, 4, 256),
            env=cap_list(self.env, 4, 512),
            binds=cap_list(self.binds, 8, 1024),
            privileged=self.privileged,
            pid_mode=self.pid_mode[:32],
            network_mode=self.network_mode[:64],
            cap_add=cap_list(self.cap_add, 8, 128),
            user=self.user[:64],
            tty=self.tty,
            auto_remove=self.auto_remove,
            hostname=self.hostname[:64],
            flags=set(),
        )

    def size(self) -> int:
        """Approximate bytes held (strings plus a fixed overhead per field)."""
        parts = [self.image, self.pid_mode, self.network_mode, self.user, self.hostname]
        for lst in (self.cmd, self.entrypoint, self.env, self.binds, self.cap_add):
            parts.extend(lst)
        return sum(len(x) + 56 for x in parts) + 600

    def summary(self) -> dict[str, Any]:
        """The parts of the spec worth keeping in an event, within a fixed byte budget."""
        return {
            "image": self.image[:256],
            "cmd": cap_list(self.cmd, 16, 1500),
            "entrypoint": cap_list(self.entrypoint, 8, 500),
            "env": cap_list(self.env, 16, 2000),
            "binds": cap_list(self.binds, 16, 1000),
            "privileged": self.privileged,
            "pid_mode": self.pid_mode[:32],
            "network_mode": self.network_mode[:64],
            "cap_add": cap_list(self.cap_add, 16, 300),
            "user": self.user[:64],
            "tty": self.tty,
        }


def cap_list(items: list[str], max_items: int, max_chars: int) -> list[str]:
    """First items of a list within a total character budget (no build-then-cut)."""
    out: list[str] = []
    left = max_chars
    for item in items[:max_items]:
        if left <= 0:
            break
        out.append(item[:left])
        left -= len(item)
    return out


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def parse_container_spec(obj: Any) -> ContainerSpec:
    """Read the interesting fields of a create body. Unknown shapes give an empty spec."""
    body = _as_dict(obj)
    host = _as_dict(body.get("HostConfig"))
    spec = ContainerSpec()
    image = body.get("Image")
    spec.image = image[:256] if isinstance(image, str) else ""
    spec.cmd = as_str_list(body.get("Cmd"))
    spec.entrypoint = as_str_list(body.get("Entrypoint"))
    spec.env = as_str_list(body.get("Env"), max_items=64, max_chars=8192)
    spec.binds = as_str_list(host.get("Binds"), max_items=32, max_chars=4096)
    mounts = host.get("Mounts")
    if isinstance(mounts, list):
        for m in mounts[:16]:
            src = _as_dict(m).get("Source")
            if isinstance(src, str):
                spec.binds.append(src[:512])
    spec.privileged = host.get("Privileged") is True
    spec.auto_remove = host.get("AutoRemove") is True
    pid = host.get("PidMode")
    spec.pid_mode = pid[:32] if isinstance(pid, str) else ""
    net = host.get("NetworkMode")
    spec.network_mode = net[:64] if isinstance(net, str) else ""
    spec.cap_add = as_str_list(host.get("CapAdd"), max_items=32, max_chars=512)
    user = body.get("User")
    spec.user = user[:64] if isinstance(user, str) else ""
    spec.tty = body.get("Tty") is True
    hn = body.get("Hostname")
    spec.hostname = hn[:64] if isinstance(hn, str) else ""

    flags = spec.flags
    flags.add("container_create")
    if spec.privileged:
        flags.add("privileged")
    if any(_is_host_path(_bind_source(b)) or b.startswith("/:") for b in spec.binds):
        flags.add("host_mount")
    if any("docker.sock" in b for b in spec.binds):
        flags.add("docker_sock_mount")
    if spec.pid_mode == "host":
        flags.add("pid_host")
    if spec.network_mode == "host":
        flags.add("net_host")
    if spec.cap_add:
        flags.add("cap_add")
    if spec.image:
        flags.add("image:" + spec.image[:128])
    if is_miner(spec.image, spec.input, " ".join(spec.env)):
        flags.add("miner")
    return spec


def spec_urls(spec: ContainerSpec) -> list[str]:
    """URLs in the command line and environment (deduplicated, bounded)."""
    seen: list[str] = []
    for text in (spec.input, "\n".join(spec.env)):
        for url in find_urls(text):
            if url not in seen and len(seen) < MAX_URLS:
                seen.append(url)
    return seen


def canned_output(cmd: list[str]) -> str:
    """Output for a few trivial commands. The command is looked at, never run."""
    if not cmd:
        return ""
    words = cmd
    # sh -c "<inner>" / bash -c "<inner>": look at the inner string when it is plain.
    if (
        len(words) >= 3
        and words[0].rsplit("/", 1)[-1] in ("sh", "bash", "ash")
        and words[1] == "-c"
    ):
        inner = words[2]
        if any(c in inner for c in ";|&$`<>()\\\n"):
            return ""
        words = inner.split()
        if not words:
            return ""
    name = words[0].rsplit("/", 1)[-1]
    args = words[1:]
    if name == "id" and not args:
        return "uid=0(root) gid=0(root) groups=0(root)\n"
    if name == "whoami":
        return "root\n"
    if name == "pwd":
        return "/\n"
    if name == "uname":
        return {"-m": "x86_64\n", "-s": "Linux\n"}.get(" ".join(args), "")
    if name == "echo":
        text = " ".join(args)[:1024]
        return text + "\n"
    return ""

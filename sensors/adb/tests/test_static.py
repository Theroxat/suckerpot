"""Static guard: the package must never contain code-execution or process-spawning primitives."""

from __future__ import annotations

import ast
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent / "adb_sensor"
BANNED_CALLS = {"eval", "exec", "compile", "__import__", "breakpoint", "input"}
BANNED_MODULES = {
    "subprocess",
    "pickle",
    "cPickle",
    "marshal",
    "shelve",
    "ctypes",
    "pty",
    "code",
    "codeop",
    "multiprocessing",
    "runpy",
    "importlib",
    "dill",
    "cloudpickle",
    "shlex_exec",
}
BANNED_OS = {
    "system",
    "popen",
    "execv",
    "execve",
    "execl",
    "execle",
    "execlp",
    "execvp",
    "execvpe",
    "spawnl",
    "spawnv",
    "spawnlp",
    "spawnvp",
    "fork",
    "forkpty",
    "posix_spawn",
    "startfile",
}


def _violations(root: Path = PKG) -> list[str]:
    found: list[str] = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            where = f"{path.relative_to(root)}:{getattr(node, 'lineno', 0)}"
            if isinstance(node, ast.Import):
                found += [
                    f"{where} import {a.name}"
                    for a in node.names
                    if a.name.split(".")[0] in BANNED_MODULES
                ]
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0] in BANNED_MODULES:
                    found.append(f"{where} from {node.module}")
                if node.module == "os":
                    found += [
                        f"{where} from os import {a.name}"
                        for a in node.names
                        if a.name in BANNED_OS
                    ]
            elif isinstance(node, ast.Call):
                fn = node.func
                if isinstance(fn, ast.Name) and fn.id in BANNED_CALLS:
                    found.append(f"{where} {fn.id}()")
                if isinstance(fn, ast.Attribute) and fn.attr in BANNED_OS | {"eval", "exec"}:
                    found.append(f"{where} .{fn.attr}()")
    return found


def test_no_code_execution_primitives() -> None:
    assert _violations() == []


def test_guard_detects_violations(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_text(
        "import subprocess\nimport os\nos.system('x')\neval('1')\ncompile('1', '', 'eval')\n"
    )
    assert len(_violations(tmp_path)) == 4


def test_no_write_outside_data_path() -> None:
    """The only file writes are the profile secret in secret.py (reads of /sys cgroup files
    use Path.read_text, which is allowed)."""
    offenders = []
    for path in sorted(PKG.rglob("*.py")):
        if path.name == "secret.py":
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id == "open":
                offenders.append(f"{path.name}:{node.lineno} open()")
            if isinstance(fn, ast.Attribute):
                if fn.attr in ("write_text", "write_bytes", "fdopen", "mkdir", "touch"):
                    offenders.append(f"{path.name}:{node.lineno} .{fn.attr}()")
                if fn.attr == "open" and isinstance(fn.value, ast.Name) and fn.value.id == "os":
                    offenders.append(f"{path.name}:{node.lineno} os.open()")
    assert offenders == []


def test_no_network_clients() -> None:
    """The sensor only accepts connections: no outbound connect, no HTTP client, no DNS."""
    banned = {"open_connection", "create_connection", "connect", "urlopen", "getaddrinfo"}
    banned_imports = {"requests", "httpx", "aiohttp", "urllib3", "ftplib", "smtplib", "telnetlib"}
    found = []
    for path in sorted(PKG.rglob("*.py")):
        if path.name == "healthcheck.py":
            continue  # connects to 127.0.0.1 only, from the container healthcheck
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in banned:
                    found.append(f"{path.name}:{node.lineno} {node.func.attr}")
            if isinstance(node, ast.Import):
                found += [
                    f"{path.name} import {a.name}" for a in node.names if a.name in banned_imports
                ]
            if (
                isinstance(node, ast.ImportFrom)
                and (node.module or "").split(".")[0] in banned_imports
            ):
                found.append(f"{path.name} from {node.module}")
    assert found == []

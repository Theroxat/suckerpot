"""Static guard: the package must never contain code-execution or process-spawning primitives."""

from __future__ import annotations

import ast
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent / "mysql_sensor"
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
    """The only file writes are the identity files (secret, keys, certificates) in identity.py."""
    offenders = []
    for path in sorted(PKG.rglob("*.py")):
        if path.name == "identity.py":
            continue
        text = path.read_text()
        if path.name == "memguard.py":  # reads /sys/fs/cgroup and /proc files, read-only
            assert "write_" not in text and "'w'" not in text and '"w"' not in text
            continue
        for marker in ("write_text(", "write_bytes(", "os.open(", "os.fdopen(", "open("):
            if marker in text:
                offenders.append(f"{path.name}: {marker}")
    assert offenders == []


def test_no_network_clients() -> None:
    """The sensor never initiates connections (no fetching, no callbacks)."""
    offenders = []
    for path in sorted(PKG.rglob("*.py")):
        if path.name == "healthcheck.py":  # connects to 127.0.0.1 only
            continue
        text = path.read_text()
        for marker in (
            "open_connection(",
            "create_connection(",
            "urllib",
            "http.client",
            "requests",
        ):
            if marker in text:
                offenders.append(f"{path.name}: {marker}")
    assert offenders == []


def test_no_giveaways_in_package() -> None:
    for path in sorted(PKG.rglob("*.py")):
        text = path.read_text().lower()
        assert "honeypot" not in text, path
        assert "suckerpot" not in text.replace("suckerpot_common", ""), path


def test_responder_has_no_dynamic_attribute_dispatch() -> None:
    """Attacker-derived names must never reach getattr/setattr/globals lookups."""
    offenders = []
    for path in sorted(PKG.rglob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in {"getattr", "setattr", "globals", "locals", "vars"}:
                    offenders.append(f"{path.name}:{node.lineno} {node.func.id}")
    assert offenders == []


def test_no_regular_expressions() -> None:
    """Attacker input is parsed by hand: the re module is not used at all."""
    for path in sorted(PKG.rglob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(a.name != "re" for a in node.names), path
            if isinstance(node, ast.ImportFrom):
                assert node.module != "re", path

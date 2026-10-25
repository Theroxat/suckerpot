"""Static guard: the package must never contain code-execution or process-spawning primitives."""

from __future__ import annotations

import ast
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent / "sip_sensor"
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
    "re",
    "fnmatch",
    "glob",
    "lupa",
    "lua",
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


def test_no_code_execution_or_regex_primitives() -> None:
    assert _violations() == []


def test_guard_detects_violations(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_text(
        "import subprocess\nimport os\nimport re\nos.system('x')\neval('1')\ncompile('1', '', 'eval')\n"
    )
    assert len(_violations(tmp_path)) == 5


def test_no_write_outside_data_path() -> None:
    """The only file writes are the profile secret in identity.py."""
    offenders = []
    for path in sorted(PKG.rglob("*.py")):
        if path.name in ("identity.py", "memguard.py"):  # memguard only reads cgroup files
            continue
        text = path.read_text()
        for marker in ("write_text(", "write_bytes(", "os.open(", "os.fdopen(", "open("):
            if marker in text:
                offenders.append(f"{path.name}: {marker}")
    assert offenders == []


def test_no_network_clients() -> None:
    """The sensor never initiates connections: no outbound sockets, no DNS, no HTTP."""
    offenders = []
    for path in sorted(PKG.rglob("*.py")):
        if path.name == "healthcheck.py":  # talks to 127.0.0.1 only
            continue
        text = path.read_text()
        for marker in (
            "open_connection(",
            "create_connection(",
            "remote_addr",
            "urllib",
            "http.client",
            "import requests",
            ".connect(",
            "sock_connect",
            "getaddrinfo",
            "gethostbyname",
            "socket.socket(",
        ):
            if marker in text:
                offenders.append(f"{path.name}: {marker}")
    assert offenders == []


def test_replies_only_go_back_to_the_sender() -> None:
    """Exactly one ``sendto`` in the package, answering the address the datagram came from."""
    hits = []
    for path in sorted(PKG.rglob("*.py")):
        if path.name == "healthcheck.py":
            continue
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if "sendto(" in line:
                hits.append((path.name, lineno, line.strip()))
    assert len(hits) == 1, hits
    assert hits[0][0] == "server.py" and hits[0][2].endswith(
        "sendto(reply, addr)  # type: ignore[arg-type]"
    )


def _string_literals(tree: ast.AST) -> list[str]:
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                docstrings.add(id(body[0].value))
    return [
        n.value.lower()
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings
    ]


def test_no_giveaways_in_package() -> None:
    for path in sorted(PKG.rglob("*.py")):
        assert "honeypot" not in path.read_text().lower(), path
        for text in _string_literals(ast.parse(path.read_text())):
            assert "suckerpot" not in text.replace("suckerpot_common", ""), (path, text)
            assert "honeypot" not in text, (path, text)

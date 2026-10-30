"""Static guard: no code execution, no process spawning, no regexes, no writes outside /data."""

from __future__ import annotations

import ast
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent / "synology_sensor"
BANNED_CALLS = {"eval", "exec", "compile", "__import__", "breakpoint", "input"}
BANNED_MODULES = {
    "subprocess", "pickle", "cPickle", "marshal", "shelve", "ctypes", "pty", "code", "codeop",
    "multiprocessing", "runpy", "importlib", "dill", "cloudpickle", "yaml",
    "re", "fnmatch", "glob",  # no regular expressions on attacker input (ReDoS)
}  # fmt: skip
BANNED_OS = {
    "system", "popen", "execv", "execve", "execl", "execle", "execlp", "execvp", "execvpe",
    "spawnl", "spawnv", "spawnlp", "spawnvp", "fork", "forkpty", "posix_spawn", "startfile",
}  # fmt: skip
WRITERS = {"profile.py", "tls.py"}  # the only module allowed to create files, below data_dir
WRITE_ATTRS = {"write_text", "write_bytes", "mkdir", "touch", "rename", "unlink"}


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


def test_no_code_execution_or_regex() -> None:
    assert _violations() == []


def test_guard_detects_violations(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_text(
        "import subprocess\nimport os\nimport re\nos.system('x')\neval('1')\ncompile('1', '', 'eval')\n"
    )
    assert len(_violations(tmp_path)) == 5


def test_only_profile_and_tls_write_files() -> None:
    offenders = []
    for path in sorted(PKG.rglob("*.py")):
        if path.name in WRITERS:
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Call):
                fn = node.func
                name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
                if name in WRITE_ATTRS | {"fdopen"} or (
                    name == "open" and isinstance(fn, ast.Name)
                ):
                    offenders.append(f"{path.name}:{node.lineno} {name}")
                if (
                    name == "open"
                    and isinstance(fn, ast.Attribute)
                    and getattr(fn.value, "id", "") == "os"
                ):
                    offenders.append(f"{path.name}:{node.lineno} os.open")
    assert offenders == []


def test_writers_stay_below_data_dir() -> None:
    for name in WRITERS:
        text = (PKG / name).read_text()
        assert "data_dir" in text and "/tmp" not in text and "/etc" not in text


def test_no_network_clients_in_package() -> None:
    """The sensor never fetches anything: no outbound HTTP libraries or connect calls."""
    banned = {"urllib.request", "http.client", "requests", "httpx", "aiohttp", "ftplib", "smtplib"}
    hits = []
    for path in sorted(PKG.rglob("*.py")):
        if path.name == "healthcheck.py":  # connects to 127.0.0.1 only
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            mods: list[str] = []
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods = [node.module]
            hits += [f"{path.name} {m}" for m in mods if m in banned]
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in ("create_connection", "open_connection", "connect", "urlopen"):
                    hits.append(f"{path.name}:{node.lineno} {node.func.attr}")
    assert hits == []


def test_no_giveaway_words_in_package() -> None:
    """Nothing a client can see names the project or the framework."""
    for path in sorted(PKG.rglob("*.py")):
        text = path.read_text().lower().replace("suckerpot_common", "")
        for word in ("honeypot", "suckerpot", "starlette", "uvicorn"):
            assert word not in text, f"{path.name} mentions {word}"

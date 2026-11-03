"""The proxy source must stay minimal: no process spawning, no dynamic code, no file writes."""

from __future__ import annotations

import ast
import pathlib

SRC = pathlib.Path(__file__).resolve().parent.parent / "hubproxy"
FORBIDDEN_IMPORTS = {"subprocess", "pickle", "marshal", "ctypes", "shutil", "tempfile", "ssl"}
FORBIDDEN_NAME_CALLS = {"eval", "exec", "compile", "__import__", "open"}
FORBIDDEN_ATTR_CALLS = {"system", "popen", "write_text", "write_bytes", "mkdir", "unlink"}
THIRD_PARTY_OK = {"hubproxy"}


def _trees() -> list[tuple[str, ast.AST]]:
    return [(p.name, ast.parse(p.read_text())) for p in sorted(SRC.glob("*.py"))]


def test_no_forbidden_imports_or_calls() -> None:
    problems: list[str] = []
    for name, tree in _trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                problems += [
                    f"{name}: import {a.name}"
                    for a in node.names
                    if a.name.split(".")[0] in FORBIDDEN_IMPORTS
                ]
            elif (
                isinstance(node, ast.ImportFrom)
                and (node.module or "").split(".")[0] in FORBIDDEN_IMPORTS
            ):
                problems.append(f"{name}: from {node.module}")
            elif isinstance(node, ast.Call):
                fn = node.func
                if isinstance(fn, ast.Name) and fn.id in FORBIDDEN_NAME_CALLS:
                    problems.append(f"{name}: call {fn.id}")
                elif isinstance(fn, ast.Attribute) and fn.attr in FORBIDDEN_ATTR_CALLS:
                    problems.append(f"{name}: call {fn.attr}")
    assert not problems, problems


def test_standard_library_only() -> None:
    import sys

    stdlib = sys.stdlib_module_names
    bad: list[str] = []
    for name, tree in _trees():
        for node in ast.walk(tree):
            mods: list[str] = []
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                mods = [node.module]
            bad += [f"{name}: {m}" for m in mods if m.split(".")[0] not in stdlib | THIRD_PARTY_OK]
    assert not bad, bad


def test_logging_never_formats_peer_information() -> None:
    for name, tree in _trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in {
                "get_extra_info",
                "getpeername",
                "peername",
            }:
                raise AssertionError(f"{name}: peer information is read")

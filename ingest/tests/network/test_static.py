"""Static guarantees of the network package (N2, N3), by AST walk. Comments are free."""

from __future__ import annotations

import ast
import re
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[2] / "ingest" / "network"
FILES = sorted(PACKAGE.glob("*.py"))
FORBIDDEN_CALLS = {
    "AsyncClient",
    "Client",
    "get",
    "post",
    "request",
    "urlopen",
    "create_connection",
}
FORBIDDEN_MODULES = {"socket", "urllib.request", "aiohttp", "requests", "urllib3", "http.client"}
READ_ONLY_SQL = ("builder.py", "source.py")


def calls(tree: ast.AST) -> list[str]:
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            base = node.func.value
            if (
                isinstance(base, ast.Name)
                and base.id in {"httpx", "socket", "requests"}
                and node.func.attr in FORBIDDEN_CALLS
            ):
                out.append(f"{base.id}.{node.func.attr}")
    return out


def test_the_package_exists() -> None:
    assert {p.name for p in FILES} >= {"builder.py", "client.py", "worker.py", "source.py"}


def test_no_raw_network_client() -> None:
    for path in FILES:
        tree = ast.parse(path.read_text())
        assert calls(tree) == [], path.name
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not {a.name for a in node.names} & FORBIDDEN_MODULES, path.name
            if isinstance(node, ast.ImportFrom):
                assert (node.module or "") not in FORBIDDEN_MODULES, path.name


def test_the_only_client_factory_is_make_client() -> None:
    src = (PACKAGE / "client.py").read_text()
    assert "make_client(" in src
    assert "follow_redirects=False" in src


def test_every_other_module_uses_the_hub_client_only() -> None:
    for path in FILES:
        if path.name == "client.py":
            continue
        assert "make_client" not in path.read_text(), path.name


def _strings(tree: ast.AST) -> list[str]:
    return [
        n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
    ]


def test_the_builder_and_its_source_never_touch_events_or_their_data() -> None:
    for name in READ_ONLY_SQL:
        tree = ast.parse((PACKAGE / name).read_text())
        for text in (t for t in _strings(tree) if "SELECT" in t.upper()):
            assert not re.search(r"\b(FROM|JOIN)\s+events\b", text, re.IGNORECASE), name
            assert not re.search(r"\bdata\b\s*(->|#>|\?)", text), name
            assert not re.search(r"\b(password|username|credential|command_text)\w*\b", text), name
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                assert node.attr not in {"data", "password", "username"}, name
            if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
                assert node.slice.value not in {"data", "password", "username"}, name


def test_the_batch_has_no_credential_field() -> None:
    from suckerpot_netproto import models

    for model in (models.SourceObs, models.PayloadObs, models.C2Obs, models.FileObs):
        assert not {"password", "username", "credentials", "command"} & set(model.model_fields)


def test_the_demo_fragment_is_the_only_event_read_and_takes_the_demo_flag_alone() -> None:
    tree = ast.parse((PACKAGE / "demo.py").read_text())
    text = " ".join(_strings(tree))
    assert len(re.findall(r"\bFROM events\b", text)) == 1
    assert re.findall(r"\be\.data\b[^']*'(\w+)'", text) == ["demo"]
    assert not re.search(r"\b(password|username|credential|command_text)\w*\b", text)
    for path in FILES:  # nobody else reads events
        if path.name not in {"demo.py", *READ_ONLY_SQL}:
            for node in _strings(ast.parse(path.read_text())):
                assert not re.search(r"\b(FROM|JOIN)\s+events\b", node, re.IGNORECASE), path.name

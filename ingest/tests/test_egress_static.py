"""No code in the ingest package may open a network connection by itself (M21, invariant I3).

Everything outbound goes through ``ingest.egress`` (the VPN proxy, with the gate). The scan is an
AST walk over the package source: calls and imports only, so comments and docstrings are free to
mention these names. Clients built in ``tests/`` are exempt.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parent.parent / "ingest"

FORBIDDEN_CALLS = {
    "httpx.AsyncClient",
    "httpx.Client",
    "httpx.get",
    "httpx.post",
    "httpx.request",
    "httpx.stream",
    "socket.create_connection",
    "socket.socket",
    "socket.getaddrinfo",
    "socket.gethostbyname",
    "smtplib.SMTP",
    "smtplib.SMTP_SSL",
    "urllib.request.urlopen",
    "asyncio.open_connection",
}
FORBIDDEN_ATTRS = {"getaddrinfo", "create_connection", "open_connection", "sock_connect"}
FORBIDDEN_MODULES = {"urllib.request", "aiohttp", "requests", "urllib3", "http.client"}

# (relative path, dotted call) pairs that are allowed. Empty: even the SMTP adapter in
# alerts/send.py only uses suckerpot_egress.TunnelSMTP.
ALLOW: set[tuple[str, str]] = set()


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _aliases(tree: ast.AST) -> dict[str, str]:
    """Local name to the dotted module path it stands for (``import httpx as h``, ``from m import n``)."""
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                out[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                out[a.asname or a.name] = f"{node.module}.{a.name}"
    return out


def _resolved(node: ast.AST, aliases: dict[str, str]) -> str:
    name = _dotted(node)
    head, _, rest = name.partition(".")
    if head in aliases:
        return aliases[head] + ("." + rest if rest else "")
    return name


def scan_source(source: str, rel: str = "<memory>") -> list[str]:
    problems: list[str] = []
    tree = ast.parse(source)
    aliases = _aliases(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _resolved(node.func, aliases)
            attr = name.rsplit(".", 1)[-1]
            if (name in FORBIDDEN_CALLS or attr in FORBIDDEN_ATTRS) and (rel, name) not in ALLOW:
                problems.append(f"{rel}:{node.lineno}: call to {name}")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in FORBIDDEN_MODULES or alias.name.split(".")[0] in FORBIDDEN_MODULES:
                    problems.append(f"{rel}:{node.lineno}: import {alias.name}")
        elif isinstance(node, ast.ImportFrom) and node.module:
            mod = node.module
            if mod in FORBIDDEN_MODULES or mod.split(".")[0] in FORBIDDEN_MODULES:
                problems.append(f"{rel}:{node.lineno}: import from {mod}")
            if mod == "smtplib" and any(a.name in ("SMTP", "SMTP_SSL") for a in node.names):
                problems.append(f"{rel}:{node.lineno}: smtplib client imported")
    return problems


def test_package_opens_no_connection_of_its_own() -> None:
    problems: list[str] = []
    files = sorted(PACKAGE.rglob("*.py"))
    assert files, "the scan found no source: wrong path"
    for path in files:
        problems += scan_source(path.read_text(), str(path.relative_to(PACKAGE)))
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize(
    "snippet",
    [
        "import httpx\nc = httpx.AsyncClient(timeout=3)\n",
        "import httpx\nc = httpx.Client()\n",
        "import socket\ns = socket.create_connection(('x', 1))\n",
        "import socket\ns = socket.socket()\n",
        "import smtplib\ns = smtplib.SMTP('h')\n",
        "from smtplib import SMTP_SSL\n",
        "import urllib.request\n",
        "import aiohttp\n",
        "import requests\n",
        "from httpx import AsyncClient\nc = AsyncClient()\n",
        "import httpx as h\nc = h.AsyncClient()\n",
        "from httpx import AsyncClient as C\nc = C()\n",
        "from socket import create_connection\ns = create_connection(('x', 1))\n",
        "from socket import socket as S\ns = S()\n",
        "import asyncio as a\nasync def f():\n    await a.open_connection('h', 1)\n",
        "from asyncio import open_connection\nasync def f():\n    await open_connection('h', 1)\n",
        "async def f(loop, s):\n    await loop.sock_connect(s, ('h', 1))\n",
        "import asyncio\nasync def f(loop):\n    await loop.getaddrinfo('h', 1)\n",
    ],
)
def test_scanner_catches_planted_clients(snippet: str) -> None:
    assert scan_source(snippet), snippet


def test_scanner_ignores_comments_annotations_and_the_factory() -> None:
    ok = (
        "# httpx.AsyncClient( is not allowed here\n"
        "import httpx\n"
        "from ingest.egress import make_client\n"
        "def f(c: httpx.AsyncClient | None = None) -> None:\n"
        "    '''socket.socket() in a docstring'''\n"
        "    c = c or make_client(httpx.Timeout(1.0))\n"
    )
    assert scan_source(ok) == []

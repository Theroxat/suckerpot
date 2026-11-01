"""The package has no mail sending, no network client, and names the project only in terms.py."""

from __future__ import annotations

import ast
import re
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent / "suckerpot_reporting"
BANNED_IMPORTS = {
    "smtplib",
    "socket",
    "ssl",
    "http",
    "httpx",
    "requests",
    "urllib",
    "urllib3",
    "aiohttp",
    "ftplib",
    "poplib",
    "imaplib",
    "telnetlib",
    "subprocess",
    "asyncio",
}
BANNED_PREFIXES = ("email.mime", "email.message")  # building and sending paths
DENY_MODULE = "terms.py"
PROJECT = re.compile(
    r"suckerpot|self[\s_-]?hostr|sucker[\s_-]?pot|honey[\s_-]?pot|honeynet", re.IGNORECASE
)


def violations(source: str) -> list[str]:
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names = [node.module]
        for name in names:
            if name == "urllib.parse":
                continue  # string handling only
            if name.split(".")[0] in BANNED_IMPORTS or name.startswith(BANNED_PREFIXES):
                found.append(f"import {name}")
    return found


def project_terms(source: str) -> list[str]:
    cleaned = re.sub(r"suckerpot[_-]reporting", "", source, flags=re.IGNORECASE)
    return PROJECT.findall(cleaned)


def test_no_sending_or_network_imports() -> None:
    for path in PKG.glob("*.py"):
        assert violations(path.read_text()) == [], path.name


def test_scanner_catches_planted_imports() -> None:
    assert violations("import smtplib") == ["import smtplib"]
    assert violations("from email.mime.text import MIMEText") == ["import email.mime.text"]
    assert violations("import httpx as h") == ["import httpx"]
    assert violations("from urllib.request import urlopen") == ["import urllib.request"]
    assert violations("import json\nimport email.parser") == []


def test_project_terms_only_in_the_deny_module() -> None:
    for path in PKG.glob("*.py"):
        hits = project_terms(path.read_text())
        if path.name == DENY_MODULE:
            assert hits
        else:
            assert hits == [], path.name
    assert (
        project_terms("the SuckerPot app")
        and project_terms("the Selfhostr app")
        and project_terms("a honeypot")
    )


def test_typed_package() -> None:
    assert (PKG / "py.typed").exists()

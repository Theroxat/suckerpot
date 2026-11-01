"""The abuse package prepares text and files. It never sends mail, never opens a connection of
its own (``test_egress_static`` covers clients) and never carries the project's name on the wire."""

import ast
from pathlib import Path

from ingest.abuse import rdap

PACKAGE = Path(__file__).resolve().parent.parent / "ingest" / "abuse"
FORBIDDEN_MODULES = {"smtplib", "email.mime", "email.message", "aiosmtplib", "socket", "ssl"}
WIRE_TERMS = ("suckerpot", "honeypot", "sucker pot")


def imports(source: str) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


def test_package_has_sources() -> None:
    assert list(PACKAGE.glob("*.py"))


def test_no_mail_or_raw_socket_imports() -> None:
    bad = [
        f"{p.name}: {m}"
        for p in PACKAGE.glob("*.py")
        for m in imports(p.read_text())
        if m in FORBIDDEN_MODULES or m.split(".")[0] in {"smtplib", "aiosmtplib", "socket"}
    ]
    assert not bad, bad


def test_scanner_catches_a_planted_import() -> None:
    assert imports("import smtplib\nfrom email.mime.text import MIMEText\n") >= {
        "smtplib", "email.mime.text"
    }  # fmt: skip


def test_user_agent_and_request_headers_do_not_name_the_project() -> None:
    assert not any(t in rdap.USER_AGENT.lower() for t in WIRE_TERMS)
    assert not any(t in rdap.ACCEPT.lower() for t in WIRE_TERMS)


def test_no_url_in_the_package_names_the_project() -> None:
    for path in PACKAGE.glob("*.py"):
        for line in path.read_text().splitlines():
            if "https://" in line:
                assert not any(t in line.lower() for t in WIRE_TERMS), path.name

"""The replies package can read mail and set one flag, nothing else (M26, O2 and O3).

An AST walk over ``ingest/replies``: a future change that deletes, appends, expunges, answers
mail or follows a link fails here. ``SafeMailbox`` is the only code that talks IMAP.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parent.parent / "ingest" / "replies"

# IMAP methods (and look-alikes) that change or remove mail, or rights, folders and flags.
FORBIDDEN_METHODS = {
    "expunge",
    "delete",
    "rename",
    "setacl",
    "deleteacl",
    "store",
    "copy",
    "create",
    "subscribe",
    "unsubscribe",
    "setquota",
    "sendmail",
    "send_message",
}
FORBIDDEN_IMPORTS = {
    "smtplib",
    "ingest.reportmail",
    "httpx",
    "imaplib",
    "poplib",
    "webbrowser",
    "subprocess",
    "urllib",
    "requests",
}
FORBIDDEN_BUILTINS = {"eval", "exec", "compile"}  # bare calls; ``re.compile`` is fine
FORBIDDEN_OS = {"system", "popen"}
FORBIDDEN_STRINGS = ("\\deleted", "expunge")


def _functions(tree: ast.AST) -> dict[ast.AST, str]:
    """Each node mapped to the name of the function that holds it."""
    owner: dict[ast.AST, str] = {}
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
            for child in ast.walk(fn):
                owner[child] = fn.name
    return owner


def scan(source: str, rel: str) -> list[str]:
    tree = ast.parse(source)
    owner = _functions(tree)
    problems: list[str] = []
    for node in ast.walk(tree):
        where = f"{rel}:{getattr(node, 'lineno', 0)}"
        if isinstance(node, ast.Import | ast.ImportFrom):
            names = (
                [a.name for a in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
            )
            for name in names:
                head = name.split(".")[0]
                if name in FORBIDDEN_IMPORTS or head in FORBIDDEN_IMPORTS:
                    problems.append(f"{where}: import {name}")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            low = node.value.lower()
            if any(bad in low for bad in FORBIDDEN_STRINGS):
                problems.append(f"{where}: string constant names a removal command")
        elif isinstance(node, ast.Call):
            func = node.func
            attr = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if attr in FORBIDDEN_METHODS:
                problems.append(f"{where}: call to .{attr}()")
            if attr == "append" and isinstance(func, ast.Attribute):
                if "imap" in ast.unparse(func.value).lower():
                    problems.append(f"{where}: IMAP append")
            if (isinstance(func, ast.Name) and attr in FORBIDDEN_BUILTINS) or (
                isinstance(func, ast.Attribute) and attr in FORBIDDEN_OS
            ):
                problems.append(f"{where}: call to {attr}()")
            if attr == "get_payload" and rel != "parse.py":
                if any(k.arg == "decode" for k in node.keywords):
                    problems.append(f"{where}: get_payload(decode=...) outside parse.py")
            if attr == "uid" and isinstance(func, ast.Attribute):
                # The one place a UID command is sent.
                if rel != "imap.py" or owner.get(node) != "_uid":
                    problems.append(f"{where}: UID command outside SafeMailbox._uid")
            if attr == "_uid" and node.args and isinstance(node.args[0], ast.Constant):
                verb = node.args[0].value
                if verb == "STORE" and owner.get(node) != "mark_seen":
                    problems.append(f"{where}: STORE outside mark_seen")
                if verb not in ("SEARCH", "FETCH", "STORE", "MOVE"):
                    problems.append(f"{where}: unknown UID command {verb!r}")
    return problems


def test_the_package_cannot_change_mail_beyond_seen_and_move() -> None:
    files = sorted(PACKAGE.glob("*.py"))
    assert {f.name for f in files} >= {"imap.py", "parse.py", "worker.py"}, "wrong path"
    problems: list[str] = []
    for path in files:
        problems += scan(path.read_text(), path.name)
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize(
    "snippet",
    [
        "def f(c):\n    c.expunge()\n",
        "def f(c):\n    c.delete('x')\n",
        "def f(c):\n    c.rename('a', 'b')\n",
        "def f(c):\n    c.store('1', '+FLAGS', '(x)')\n",
        "def f(c):\n    c.setacl('x', 'y', 'z')\n",
        "def f(self):\n    self._imap.append('INBOX', None, None, b'x')\n",
        "def f(c):\n    c.uid('FETCH', '1')\n",
        "X = '(\\\\Deleted)'\n",
        "X = 'EXPUNGE'\n",
        "import smtplib\n",
        "import imaplib\n",
        "from ingest.reportmail import sender\n",
        "import httpx\n",
        "import webbrowser\n",
        "import subprocess\n",
        "def f(p):\n    return p.get_payload(decode=True)\n",
        "def f(self):\n    self._uid('STORE', '1', '+FLAGS', '(x)')\n",
        "def f(self):\n    self._uid('COPY', '1', 'x')\n",
        "def f(x):\n    eval(x)\n",
    ],
)
def test_the_scanner_catches_planted_code(snippet: str) -> None:
    assert scan(snippet, "worker.py"), snippet


def test_the_scanner_accepts_the_allowed_shapes() -> None:
    ok = (
        "class B:\n"
        "    def _uid(self, command, *args):\n"
        "        return self._imap.uid(command, *args)\n"
        "    def mark_seen(self, uid):\n"
        "        self._uid('STORE', str(uid), '+FLAGS.SILENT', '(\\\\Seen)')\n"
        "    def other(self):\n"
        "        items = []\n"
        "        items.append(1)\n"
    )
    assert scan(ok, "imap.py") == []
    assert scan("def f(p):\n    return p.get_payload(decode=True)\n", "parse.py") == []

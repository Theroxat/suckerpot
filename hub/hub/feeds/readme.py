"""The public README.txt of the feed site, filled from ``static/README.txt.tmpl``.

Three placeholders: the feed public key, the feed host name and the delisting mailbox. The
template and ``delist.html`` ship with the hub (``hub/static``); they are published into the feeds
volume with the other files so that they are signed and listed in ``index.json``.
"""

from __future__ import annotations

from pathlib import Path

from ..config import Settings

_HERE = Path(__file__).resolve()
STATIC_DIRS = (_HERE.parents[2] / "static", Path("/app/static"))
NO_MAILBOX = "(no mailbox is configured: use the form)"


def static_dir() -> Path:
    for candidate in STATIC_DIRS:
        if (candidate / "README.txt.tmpl").is_file():
            return candidate
    raise FileNotFoundError("hub static files not found")


def render_readme(s: Settings, public_key: str, *, directory: Path | None = None) -> bytes:
    template = ((directory or static_dir()) / "README.txt.tmpl").read_text(encoding="utf-8")
    text = (
        template.replace("@FEED_PUBLIC_KEY@", public_key)
        .replace("@FEEDS_DOMAIN@", s.feeds_domain)
        .replace("@DELIST_MAILBOX@", s.delist_mailbox or NO_MAILBOX)
    )
    return text.encode("utf-8")


def delist_page(*, directory: Path | None = None) -> bytes:
    return ((directory or static_dir()) / "delist.html").read_bytes()

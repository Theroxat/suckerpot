"""Logging with a scrubbing filter (invariant H1: no client address, no key in any log).

The app never logs request data on purpose. The filter is a second line of defence: it rewrites
any record that contains an IPv4 or IPv6 literal, a node key or a long hex string.
"""

from __future__ import annotations

import logging
import re
import sys

_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_IPV6 = re.compile(r"(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Za-z:])")
_B64_KEY = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])")
_HEX = re.compile(r"\b[0-9a-fA-F]{32,}\b")


def scrub(text: str) -> str:
    text = _HEX.sub("[hex]", text)
    text = _B64_KEY.sub("[key]", text)
    text = _IPV4.sub("[addr]", text)
    return _IPV6.sub("[addr]", text)


class PrivacyFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except (TypeError, ValueError):
            message = str(record.msg)
        record.msg = scrub(message)
        record.args = None
        if record.exc_info:  # tracebacks may carry values; keep the type only
            record.msg = (
                f"{record.msg} [{record.exc_info[0].__name__ if record.exc_info[0] else 'error'}]"
            )
            record.exc_info = None
            record.exc_text = None
        return True


SERVER_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access", "uvicorn.asgi")


def configure(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    handler.addFilter(PrivacyFilter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    # uvicorn installs its own handlers (and does not propagate): scrub those as well, so a
    # traceback printed by the server can never carry a client address.
    for name in SERVER_LOGGERS:
        server = logging.getLogger(name)
        if not server.handlers:
            server.addHandler(handler)
        for h in server.handlers:
            if not any(isinstance(f, PrivacyFilter) for f in h.filters):
                h.addFilter(PrivacyFilter())
    # Access logs are off at the server; make sure nothing re-enables them.
    logging.getLogger("uvicorn.access").disabled = True
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

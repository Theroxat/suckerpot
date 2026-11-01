"""The name a mail client announces itself with (``EHLO``) and the domain of Message-IDs.

It must never be the container's host name: it is the domain of the sender address. One helper so
the alerts and the abuse reports follow the same rule.
"""

from __future__ import annotations

import re
from email.utils import parseaddr

_DOMAIN = re.compile(
    r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$"
)

FALLBACK = "localhost"


def sender_domain(address: str, *, fallback: str = FALLBACK) -> str:
    """The domain of ``address`` (``Name <user@domain>`` is accepted), or ``fallback``."""
    domain = parseaddr(address)[1].rpartition("@")[2].strip().lower()
    return domain if _DOMAIN.match(domain) else fallback

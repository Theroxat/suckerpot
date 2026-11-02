"""Mail domains shared by many unrelated people (M26).

A reply from ``someone@gmail.com`` says nothing about the organisation we wrote to, even when the
abuse contact is a free mailbox. For these domains trust is given to an exact address only, and
the domain alone never makes a mail relevant, matched or verified. Lower-case, no leading dot.
"""

from __future__ import annotations

from typing import Final

SHARED_MAIL_DOMAINS: Final = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "msn.com",
        "yahoo.com",
        "yahoo.co.uk",
        "yahoo.fr",
        "yahoo.de",
        "ymail.com",
        "aol.com",
        "icloud.com",
        "me.com",
        "mac.com",
        "proton.me",
        "protonmail.com",
        "pm.me",
        "tutanota.com",
        "tuta.io",
        "gmx.com",
        "gmx.net",
        "gmx.de",
        "gmx.ch",
        "web.de",
        "mail.com",
        "mail.ru",
        "yandex.com",
        "yandex.ru",
        "qq.com",
        "163.com",
        "126.com",
        "sina.com",
        "naver.com",
        "daum.net",
        "bluewin.ch",
        "orange.fr",
        "free.fr",
        "wanadoo.fr",
        "laposte.net",
        "libero.it",
        "t-online.de",
        "seznam.cz",
        "zoho.com",
        "fastmail.com",
        "hushmail.com",
        "inbox.com",
        "rediffmail.com",
        "comcast.net",
        "verizon.net",
        "att.net",
        "sbcglobal.net",
        "btinternet.com",
    }
)


def is_shared_domain(domain: str | None) -> bool:
    """True for a free or shared mail domain (the domain itself or any subdomain of it)."""
    d = (domain or "").lower().strip(".")
    return d in SHARED_MAIL_DOMAINS or any(d.endswith("." + s) for s in SHARED_MAIL_DOMAINS)

"""Alerts never carry the monitored system's own address (M25 security fix).

Alert text is built from attacker-controlled facts, and it leaves through a webhook or an e-mail
(both through the VPN). Before anything is sent:

1. values that match the owner's own terms are MASKED in the message (``[own address]`` for an
   address, ``[own term]`` for a name), whatever notation the attacker used;
2. the masked message is rendered, and the complete serialized payload is checked again: the
   body of a webhook, every header and part of an e-mail. A residual leak refuses the send with
   ``guard_failed:<codes>``;
3. no fresh, confirmed self address (``no_self_address``) or an unreadable deny set
   (``self_terms_unavailable``) means nothing is sent at all.

Only the address codes are enforced on the final payload. The dashboard link in an alert is the
owner's own and goes to the owner's own channel, so names and paths are masked in the facts but
are not a reason to refuse.
"""

from __future__ import annotations

import re
from typing import Any, Final

from suckerpot_reporting import GuardContext, SelfTerms
from suckerpot_reporting.guard import scan_text
from suckerpot_reporting.normalize import candidates

ADDRESS_MASK: Final = "[own address]"
TERM_MASK: Final = "[own term]"
ADDRESS_CODES: Final = frozenset({"self_address", "vpn_address"})
_CTX: Final = GuardContext(allow_documentation=True)


def leaks(terms: SelfTerms, text: str) -> tuple[str, ...]:
    """Address codes found in ``text`` in any notation (the guard's own scan)."""
    counts: dict[str, int] = {}
    scan_text(text, terms, _CTX, counts)
    return tuple(sorted(ADDRESS_CODES & counts.keys()))


def _own_candidate(terms: SelfTerms, text: str) -> list[tuple[int, int]]:
    spans = [
        (c.start, c.end)
        for c in candidates(text)
        if any(terms.is_self(a) is not None for a in c.embedded())
    ]
    spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    return spans


def _name_patterns(terms: SelfTerms) -> list[re.Pattern[str]]:
    sep = r"(?:[.\-_]|\sdot\s)"
    out = [
        re.compile(
            rf"(?<![a-z0-9]){sep.join(re.escape(x) for x in t.labels)}(?![a-z0-9])", re.IGNORECASE
        )
        for t in terms.names
        if t.labels
    ]
    out += [re.compile(re.escape(p), re.IGNORECASE) for p in terms.texts if p]
    return out


def mask_text(terms: SelfTerms, text: str) -> str:
    """``text`` with the owner's addresses and names replaced. If a notation survives the
    replacement (encoded forms), the whole value is replaced."""
    out: list[str] = []
    pos = 0
    for start, end in _own_candidate(terms, text):
        if start < pos:
            continue
        out += [text[pos:start], ADDRESS_MASK]
        pos = end
    out.append(text[pos:])
    masked = "".join(out)
    for pattern in _name_patterns(terms):
        masked = pattern.sub(TERM_MASK, masked)
    return ADDRESS_MASK if leaks(terms, masked) else masked


def mask_message(terms: SelfTerms, value: Any) -> Any:
    """The alert message (nested dicts, lists and strings) with every string masked."""
    if isinstance(value, str):
        return mask_text(terms, value)
    if isinstance(value, dict):
        return {k: mask_message(terms, v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [mask_message(terms, v) for v in value]
    return value

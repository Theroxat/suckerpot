"""Early reveals for link verification (design M32 section 8.3, N17).

Every cycle the hub is asked which blinded links of this node wait for a clear value. A value is
sent through ``/v1/reveals`` only when all of these hold:

* ``NETWORK_VERIFY_REVEALS`` is on and, in participant mode, the consent lists ``verify_reveals``;
* the hub lists the hash (nothing else is ever revealed early);
* this node holds the clear value (a download link of a real session, as for M29 reveals);
* the value passes the identity guard, and the node knows its own address (fail closed).
"""

from __future__ import annotations

from collections.abc import Callable

from suckerpot_reporting import SelfTerms

from . import participant
from .client import HubClient
from .config import NetworkSettings
from .store import Store
from .sync import clear_by_blind, guarded_reveal_items

KIND = "url"


def enabled(settings: NetworkSettings, consent: participant.Consent | None) -> bool:
    """Whether this node may answer the hub's early-reveal list at all."""
    if not settings.verify_reveals:
        return False
    return not settings.participant or (consent is not None and consent.has("verify_reveals"))


async def answer(
    hub: HubClient,
    store: Store,
    terms: SelfTerms | None,
    settings: NetworkSettings,
    consent: participant.Consent | None,
    *,
    allow_documentation: bool = False,
    on_sent: Callable[[int], None] | None = None,
) -> int:
    """Reveal the held values the hub asked for. Returns how many were sent."""
    if not enabled(settings, consent):
        return 0
    if terms is None or not terms.has_self_address:
        return 0  # without a known own address the guard cannot vouch for anything
    asked = await hub.verify_reveals()
    wanted = {r.value_b for r in asked.items if r.kind == KIND}
    if not wanted:
        return 0
    held = clear_by_blind(KIND, await store.reveal_values(KIND))
    known = {(KIND, value_b): clear for value_b, clear in held.items() if value_b in wanted}
    items = guarded_reveal_items(known, terms, allow_documentation=allow_documentation)
    if not items:
        return 0
    await hub.reveals(items)
    if on_sent is not None:
        on_sent(len(items))
    return len(items)

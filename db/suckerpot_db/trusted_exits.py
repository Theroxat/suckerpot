"""Read the VPN exit ranges the owner trusted (M23), for the egress gate of ingest and collector.

The gate calls the returned provider at most once a minute and keeps its last good answer when
it raises, so this module does not catch anything.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Awaitable, Callable, Sequence

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from suckerpot_db.models import EgressTrustedExitRow

type Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def trusted_exit_provider(
    factory: async_sessionmaker[AsyncSession],
) -> Callable[[], Awaitable[Sequence[Network]]]:
    """A provider for ``EgressGate(extra_cidrs=...)`` reading ``egress_trusted_exits``."""

    async def provider() -> Sequence[Network]:
        async with factory() as db:
            rows = (await db.scalars(select(EgressTrustedExitRow.cidr))).all()
        return [ipaddress.ip_network(str(r), strict=False) for r in rows]

    return provider


# Rows that act in the abuse deny set (migration 0019): typed by the owner, declared by our own
# sensors, or learned and confirmed by the owner. Freshness does not matter here: an old
# address of ours is still ours.
ACTIVE_SELF_NETWORKS_SQL = (
    "SELECT value FROM report_self_terms WHERE kind IN ('address', 'cidr') "
    "AND (source IN ('manual', 'sensor') OR (source = 'learned' AND confirmed))"
)


def _network(value: str) -> Network | None:
    value = value.strip().strip("[]")
    try:
        if "/" in value:
            return ipaddress.ip_network(value, strict=False)
        return ipaddress.ip_network(ipaddress.ip_address(value))
    except ValueError:
        return None


async def load_self_networks(db: AsyncSession) -> list[Network]:
    """The honeypot's own addresses and networks (``report_self_terms``), as networks."""
    values = (await db.scalars(text(ACTIVE_SELF_NETWORKS_SQL))).all()
    return [n for n in (_network(str(v)) for v in values) if n is not None]


def self_networks_provider(
    factory: async_sessionmaker[AsyncSession],
) -> Callable[[], Awaitable[Sequence[Network]]]:
    """A provider for ``EgressGate(self_networks=...)``."""

    async def provider() -> Sequence[Network]:
        async with factory() as db:
            return await load_self_networks(db)

    return provider

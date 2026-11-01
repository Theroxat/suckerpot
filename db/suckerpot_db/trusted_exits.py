"""Read the VPN exit ranges the owner trusted (M23), for the egress gate of ingest and collector.

The gate calls the returned provider at most once a minute and keeps its last good answer when
it raises, so this module does not catch anything.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Awaitable, Callable, Sequence

from sqlalchemy import select
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

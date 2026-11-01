"""Built-in never-list entries, inserted at worker start (existing rows are left alone).

Public resolvers, very large CDN and SaaS domains and update servers: attackers abuse them as
payload hosts or forge sightings from them, and reporting them would only harm the hub's standing.
The operator adds more with ``python -m hub.admin never add``.
"""

from __future__ import annotations

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from .models import NeverList

SEED: tuple[tuple[str, str, str], ...] = (
    ("8.8.8.8", "ip", "public resolver"),
    ("8.8.4.4", "ip", "public resolver"),
    ("2001:4860:4860::8888", "ip", "public resolver"),
    ("2001:4860:4860::8844", "ip", "public resolver"),
    ("1.1.1.1", "ip", "public resolver"),
    ("1.0.0.1", "ip", "public resolver"),
    ("2606:4700:4700::1111", "ip", "public resolver"),
    ("2606:4700:4700::1001", "ip", "public resolver"),
    ("9.9.9.9", "ip", "public resolver"),
    ("149.112.112.112", "ip", "public resolver"),
    ("208.67.222.222", "ip", "public resolver"),
    ("208.67.220.220", "ip", "public resolver"),
    ("94.140.14.14", "ip", "public resolver"),
    ("94.140.15.15", "ip", "public resolver"),
    ("cloudflare.com", "domain", "large cdn"),
    ("cloudflare-dns.com", "domain", "public resolver"),
    ("github.com", "domain", "large saas"),
    ("githubusercontent.com", "domain", "large saas"),
    ("gitlab.com", "domain", "large saas"),
    ("amazonaws.com", "domain", "large cloud"),
    ("cloudfront.net", "domain", "large cdn"),
    ("googleusercontent.com", "domain", "large saas"),
    ("googleapis.com", "domain", "large saas"),
    ("google.com", "domain", "large saas"),
    ("microsoft.com", "domain", "large saas"),
    ("windowsupdate.com", "domain", "update server"),
    ("azureedge.net", "domain", "large cdn"),
    ("akamaihd.net", "domain", "large cdn"),
    ("fastly.net", "domain", "large cdn"),
    ("ubuntu.com", "domain", "update server"),
    ("debian.org", "domain", "update server"),
    ("pypi.org", "domain", "package registry"),
    ("npmjs.org", "domain", "package registry"),
    ("docker.io", "domain", "package registry"),
)


async def ensure_seed(session: AsyncSession) -> None:
    stmt = (
        pg_insert(NeverList)
        .values([{"value": v, "kind": k, "note": n} for v, k, n in SEED])
        .on_conflict_do_nothing()
    )
    await session.execute(stmt)
    await session.commit()

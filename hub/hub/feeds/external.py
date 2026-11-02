"""CDN front-end and Tor exit ranges, kept in ``feed_auto_ranges`` (design M30 sections 5.3, 7.4).

The feed job refuses to run without fresh ranges (``ranges_stale``), so this module fails closed
in every direction: a download that is too large, slow, redirected, malformed, too small or
suddenly much smaller than the copy in the database changes nothing, and the last good copy stays.

Only the hosts of ``hub/data/ranges.yaml`` are contacted: https, the default port, no redirect,
no credentials, a generic client identity and no query string. This is hub traffic about public
infrastructure; no node data is involved. Sources that cannot be refreshed are retried after
``RETRY_AFTER`` and the failure is logged by code only.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import yaml
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings

log = logging.getLogger("hub.feeds.external")

RANGES_FILE = Path(__file__).resolve().parent.parent / "data" / "ranges.yaml"
TIMEOUT = httpx.Timeout(10.0, connect=5.0)
TOTAL_TIMEOUT_S = 30.0
RETRY_AFTER = timedelta(hours=6)
MIN_PREFIX_V4 = 8
MIN_PREFIX_V6 = 16
SHRINK_CHECK_FROM = 20  # below this many stored prefixes the shrink check is skipped
MAX_PREFIXES = 100_000
TRY_KEY = "ranges_try:"
IPNet = ipaddress.IPv4Network | ipaddress.IPv6Network


class RangesError(Exception):
    """A refused fetch. The message is a short code, never a value."""


@dataclass(frozen=True)
class JsonPath:
    path: str
    key: str | None = None
    where: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Source:
    name: str
    urls: tuple[str, ...]
    format: str
    every_hours: int
    max_bytes: int
    min_count: int
    json_paths: tuple[JsonPath, ...] = ()

    @property
    def hosts(self) -> frozenset[str]:
        return frozenset(urlsplit(u).hostname or "" for u in self.urls)


def _source(raw: dict[str, Any]) -> Source:
    name = str(raw["name"])
    if name != "tor" and not name.startswith("cdn:"):
        raise ValueError("source names are 'tor' or 'cdn:<name>'")
    urls = tuple(str(u) for u in raw["urls"])
    for url in urls:
        parts = urlsplit(url)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.username
            or parts.password
            or parts.port
            or parts.query
            or parts.fragment
        ):
            raise ValueError("range URLs must be plain https URLs")
    fmt = str(raw["format"])
    if fmt not in {"lines", "json"}:
        raise ValueError("format must be lines or json")
    paths = tuple(
        JsonPath(
            str(p["path"]),
            str(p["key"]) if p.get("key") else None,
            tuple((str(k), str(v)) for k, v in (p.get("where") or {}).items()),
        )
        for p in raw.get("json") or []
    )
    if fmt == "json" and not paths:
        raise ValueError("json sources need a json: section")
    return Source(
        name=name,
        urls=urls,
        format=fmt,
        every_hours=int(raw["every_hours"]),
        max_bytes=int(raw["max_bytes"]),
        min_count=int(raw["min_count"]),
        json_paths=paths,
    )


def load_sources(path: Path = RANGES_FILE) -> list[Source]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    return [_source(raw) for raw in doc["sources"]]


# --- parsing ------------------------------------------------------------------------------------


def _network(raw: str) -> IPNet:
    try:
        net = ipaddress.ip_network(raw.strip(), strict=False)
    except ValueError as exc:
        raise RangesError("bad_prefix") from exc
    if net.prefixlen < (MIN_PREFIX_V4 if net.version == 4 else MIN_PREFIX_V6):
        raise RangesError("prefix_too_wide")
    return net


def _json_values(src: Source, body: bytes) -> list[str]:
    try:
        doc = json.loads(body)
    except ValueError as exc:
        raise RangesError("bad_json") from exc
    if not isinstance(doc, dict):
        raise RangesError("bad_json")
    out: list[str] = []
    for spec in src.json_paths:
        items = doc.get(spec.path)
        if not isinstance(items, list):
            raise RangesError("bad_json")
        for item in items:
            if spec.key is None:
                value: Any = item
            elif isinstance(item, dict):
                if any(str(item.get(k)) != v for k, v in spec.where):
                    continue
                value = item.get(spec.key)
            else:
                raise RangesError("bad_json")
            if not isinstance(value, str):
                raise RangesError("bad_json")
            out.append(value)
    return out


def parse_prefixes(src: Source, bodies: list[bytes]) -> list[str]:
    """Canonical, de-duplicated, sorted prefixes of a source. Raises ``RangesError``."""
    nets: set[IPNet] = set()
    for body in bodies:
        if src.format == "json":
            values = _json_values(src, body)
        else:
            try:
                lines = body.decode("utf-8").splitlines()
            except UnicodeDecodeError as exc:
                raise RangesError("bad_encoding") from exc
            values = [ln.split("#", 1)[0].strip() for ln in lines]
        for value in values:
            if value:
                nets.add(_network(value))
        if len(nets) > MAX_PREFIXES:
            raise RangesError("too_many")
    if len(nets) < src.min_count:
        raise RangesError("too_few")
    return sorted(str(n) for n in nets)


# --- download -----------------------------------------------------------------------------------


async def _download(client: httpx.AsyncClient, url: str, cap: int) -> bytes:
    async with asyncio.timeout(TOTAL_TIMEOUT_S):
        async with client.stream(
            "GET",
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible)", "Accept": "*/*"},
            follow_redirects=False,
        ) as resp:
            if resp.status_code != 200:
                raise RangesError("http_status")
            declared = resp.headers.get("content-length", "")
            if declared.isdigit() and int(declared) > cap:
                raise RangesError("too_large")
            chunks: list[bytes] = []
            size = 0
            async for chunk in resp.aiter_bytes():
                size += len(chunk)
                if size > cap:
                    raise RangesError("too_large")
                chunks.append(chunk)
    return b"".join(chunks)


async def fetch_source(client: httpx.AsyncClient, src: Source) -> list[str]:
    try:
        bodies = [await _download(client, url, src.max_bytes) for url in src.urls]
    except RangesError:
        raise
    except (httpx.HTTPError, TimeoutError, OSError) as exc:
        raise RangesError("network") from exc
    return parse_prefixes(src, bodies)


# --- storage and schedule ---------------------------------------------------------------------


async def _stored(session: AsyncSession, name: str) -> tuple[int, date | None]:
    row = (
        await session.execute(
            text("SELECT count(*), max(fetched_day) FROM feed_auto_ranges WHERE source = :s"),
            {"s": name},
        )
    ).one()
    return int(row[0]), row[1]


async def _get_try(session: AsyncSession, name: str) -> datetime | None:
    row = (
        await session.execute(
            text("SELECT value FROM worker_state WHERE key = :k"), {"k": TRY_KEY + name}
        )
    ).first()
    return datetime.fromisoformat(str(row[0])) if row else None


async def _set_try(session: AsyncSession, name: str, when: datetime) -> None:
    await session.execute(
        text(
            "INSERT INTO worker_state (key, value) VALUES (:k, :v) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
        ),
        {"k": TRY_KEY + name, "v": when.isoformat()},
    )


async def _replace(session: AsyncSession, name: str, prefixes: list[str], today: date) -> None:
    """Swap the stored copy of one source in a single transaction."""
    await session.execute(text("DELETE FROM feed_auto_ranges WHERE source = :s"), {"s": name})
    await session.execute(
        text("INSERT INTO feed_auto_ranges (source, prefix, fetched_day) VALUES (:s, :p, :d)"),
        [{"s": name, "p": p, "d": today} for p in prefixes],
    )


def _due(src: Source, fetched: date | None, now: datetime) -> bool:
    """Copies are dated by day, so the schedule is in whole days (at least one)."""
    if fetched is None:
        return True
    return (now.date() - fetched).days >= max(1, -(-src.every_hours // 24))


async def refresh(
    session: AsyncSession,
    s: Settings,
    now: datetime,
    *,
    client: httpx.AsyncClient | None = None,
    sources: list[Source] | None = None,
    force: bool = False,
) -> dict[str, str]:
    """Refresh every source that is due. Returns ``{name: outcome}``; never raises on a source.

    Outcomes: ``updated:<n>``, ``fresh``, ``backoff`` or ``failed:<code>``. With
    ``HUB_EXTERNAL_RANGES_ENABLED=false`` or the feeds ``off`` nothing is contacted.
    """
    if not s.external_ranges_enabled or s.feed_mode == "off":
        return {}
    todo = sources if sources is not None else load_sources()
    own = client is None
    http = client or httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False)
    out: dict[str, str] = {}
    try:
        for src in todo:
            count, fetched = await _stored(session, src.name)
            if not force:
                if not _due(src, fetched, now):
                    out[src.name] = "fresh"
                    continue
                tried = await _get_try(session, src.name)
                if tried is not None and now - tried < RETRY_AFTER:
                    out[src.name] = "backoff"
                    continue
            try:
                prefixes = await fetch_source(http, src)
                if count >= SHRINK_CHECK_FROM and len(prefixes) * 2 < count:
                    raise RangesError("shrunk")
            except RangesError as exc:
                code = str(exc)
            else:
                await _replace(session, src.name, prefixes, now.date())
                await session.commit()
                out[src.name] = f"updated:{len(prefixes)}"
                continue
            await session.rollback()
            await _set_try(session, src.name, now)
            await session.commit()
            log.warning("ranges source %s kept its last copy: %s", src.name, code)
            out[src.name] = f"failed:{code}"
    finally:
        if own:
            await http.aclose()
    return out

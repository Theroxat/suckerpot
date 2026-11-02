"""Feed and downloader privacy (design M30 invariants F2, F5, F7, F8).

No member pseudonym, node id, fingerprint, country, node count per entry, target id or precise
sighting time may appear in a feed file, and no new table keeps a client address.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import CIDR, INET, MACADDR

from hub import models
from hub.feeds import filter as feed_filter
from hub.feeds import job

from .conftest import Env
from .seed import TODAY, add_nodes, observe
from .test_feeds_select import SSH_FIELDS, add_ranges, confirm, feed_settings, run_job

HUB = Path(__file__).resolve().parent.parent
T0 = datetime(2026, 11, 1, 0, 30, tzinfo=UTC)
TIMESTAMP = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d")
FEED_TABLES = (
    "feed_entries",
    "feed_runs",
    "feed_daily",
    "feed_allow",
    "feed_auto_ranges",
    "payload_links",
    "target_hosts",
    "delist_challenges",
    "delist_requests",
)
ENTRY_KEYS = {
    "value", "family", "tier", "categories", "services", "tags", "families", "ports",
    "first_seen", "last_seen", "expires", "reported",
}  # fmt: skip


def published_files(root: Path) -> list[Path]:
    return [p for p in root.iterdir() if p.is_file() and not p.name.endswith(".gz")]


# --- static ------------------------------------------------------------------------------------


def test_no_inet_columns_in_the_feed_tables() -> None:
    bad = [
        f"{t.name}.{c.name}"
        for t in models.Base.metadata.sorted_tables
        for c in t.columns
        if isinstance(c.type, INET | CIDR | MACADDR)
    ]
    assert bad == []
    migration = (HUB / "migrations" / "versions" / "h0005_feeds.py").read_text()
    assert not re.search(r"\b(inet|cidr|macaddr)\b", migration, flags=re.I)


def test_feed_tables_reference_no_node() -> None:
    forbidden = {"node_id", "pubkey", "pseudonym", "fingerprint", "country", "ip", "client"}
    for name in FEED_TABLES:
        table = models.Base.metadata.tables[name]
        assert forbidden.isdisjoint(c.name for c in table.columns), name
        assert all(
            fk.column.table.name not in {"nodes", "observations", "batches"}
            for fk in table.foreign_keys
        ), name


def test_delisting_stores_days_not_times() -> None:
    table = models.Base.metadata.tables["delist_requests"]
    assert str(table.c.created_day.type) == "DATE" and str(table.c.decided_day.type) == "DATE"


def test_feed_code_only_talks_to_the_database_and_the_disk() -> None:
    """The generator makes no outbound call: only the range fetcher (external.py) may."""
    for path in (HUB / "hub" / "feeds").glob("*.py"):
        if path.name == "external.py":
            continue
        source = path.read_text()
        imports = re.findall(r"^\s*(?:import|from)\s+([\w.]+)", source, flags=re.M)
        assert not {"httpx", "requests", "urllib", "aiohttp", "socket"} & set(imports), path.name


def test_feeds_site_logs_nothing() -> None:
    caddy = (HUB / "Caddyfile").read_text()
    match = re.search(r"\{\$HUB_FEEDS_DOMAIN[^{]*\{(.*)", caddy, flags=re.S)
    if match is None:
        pytest.skip("the feeds site is added to the Caddyfile by the compose task")
    block = match.group(1)
    assert "output discard" in block and not re.search(r"output\s+(file|stdout|stderr)", block)


def test_external_fetcher_only_contacts_listed_hosts() -> None:
    fetcher = HUB / "hub" / "feeds" / "external.py"
    ranges = HUB / "hub" / "data" / "ranges.yaml"
    if not fetcher.exists() or not ranges.exists():
        pytest.skip("the range fetcher is added by the compose task")
    source = fetcher.read_text()
    urls = set(re.findall(r"https?://([A-Za-z0-9.-]+)", source))
    allowed = set(re.findall(r"https?://([A-Za-z0-9.-]+)", ranges.read_text()))
    assert urls <= allowed


# --- what a feed file may say ----------------------------------------------------------------------


@pytest.mark.integration
async def test_no_member_or_target_detail_reaches_any_feed_file(
    env: Env, feed_dir: Path, key_file: Path
) -> None:
    s = feed_settings(feed_dir, key_file)
    await add_ranges(env)
    ids = await add_nodes(env.worker, 10, countries=["CH", "DE", "FR", "US", "NL"] * 2)
    async with env.worker() as ses:
        for i, node in enumerate(ids):
            await ses.execute(
                text("UPDATE nodes SET pseudonym = :p, show_country = true WHERE id = :i"),
                {"p": f"quiet-otter-{i}", "i": node},
            )
        await ses.commit()
    day1, day2 = TODAY - timedelta(days=1), TODAY - timedelta(days=2)
    await observe(env.worker, ids, "ip", "192.0.2.90", [day1, day2], **SSH_FIELDS)
    await observe(
        env.worker,
        ids[:2],
        "payload_ip",
        "198.51.100.9",
        [day1, day2],
        activity=["download"],
        families=["mirai"],
        fetched=True,
        services=[],
        tags=[],
    )
    await observe(
        env.worker,
        ids[2:],
        "payload_ip",
        "198.51.100.9",
        [day1, day2],
        activity=["download"],
        families=["mirai"],
        services=[],
        tags=[],
    )
    await confirm(env, s)
    await run_job(env, s, T0)
    res = await run_job(env, s, T0 + timedelta(hours=7))
    assert res.state == "published"
    async with env.worker() as ses:
        secrets: set[str] = set()
        for r in await ses.execute(text("SELECT id, pubkey, pseudonym FROM nodes")):
            secrets |= {str(r.id), bytes(r.pubkey).hex(), r.pseudonym}
        secrets |= {str(r[0]) for r in await ses.execute(text("SELECT id FROM targets"))}
    files = published_files(feed_dir)
    assert len(files) > 20
    for path in files:
        body = path.read_text()
        for secret in secrets:
            assert secret not in body, f"{path.name} leaks {secret}"
        for token in (re.escape(c) for c in ("CH", "DE", "FR", "US", "NL")):
            assert not re.search(rf'"country"|country_code|\b{token}\b(?=,|")', body), path.name
        assert "node_count" not in body and '"nodes"' not in body and "pseudonym" not in body


@pytest.mark.integration
async def test_entries_carry_dates_but_no_time_and_no_counts(
    env: Env, feed_dir: Path, key_file: Path
) -> None:
    s = feed_settings(feed_dir, key_file)
    await add_ranges(env)
    ids = await add_nodes(env.worker, 5)
    await observe(
        env.worker, ids, "ip", "192.0.2.91", [TODAY - timedelta(days=1)] * 1, **SSH_FIELDS
    )
    await observe(env.worker, ids, "ip", "192.0.2.91", [TODAY - timedelta(days=2)], **SSH_FIELDS)
    await confirm(env, s)
    await run_job(env, s, T0)
    await run_job(env, s, T0 + timedelta(hours=7))
    doc: dict[str, Any] = json.loads((feed_dir / "inbound.json").read_text())
    assert doc["entries"], "the entry should be listed"
    for item in doc["entries"]:
        assert set(item) <= ENTRY_KEYS
        assert not TIMESTAMP.search(json.dumps(item))
    # The only timestamps in a list file are the header ones.
    stripped = {k: v for k, v in doc.items() if k not in ("generated_at", "valid_until", "entries")}
    assert not TIMESTAMP.search(json.dumps(stripped))
    csv = (feed_dir / "inbound.csv").read_text()
    assert not TIMESTAMP.search(csv)
    for name in ("stats.json", "removed.json"):
        body = (feed_dir / name).read_text()
        assert "192.0.2.91" not in body or name == "removed.json"
    stats = json.loads((feed_dir / "stats.json").read_text())
    assert "entries" in stats["lists"][0] and not any("value" in item for item in stats["lists"])


@pytest.mark.integration
async def test_delisted_and_excluded_values_are_counted_never_listed(
    env: Env, feed_dir: Path, key_file: Path
) -> None:
    s = feed_settings(feed_dir, key_file)
    await add_ranges(env)
    ids = await add_nodes(env.worker, 5)
    for v in ("192.0.2.92", "192.0.2.93"):
        await observe(
            env.worker,
            ids,
            "ip",
            v,
            [TODAY - timedelta(days=1), TODAY - timedelta(days=2)],
            **SSH_FIELDS,
        )
    await confirm(env, s)
    await run_job(env, s, T0)
    await run_job(env, s, T0 + timedelta(hours=7))
    async with env.worker() as ses:
        await ses.execute(
            text(
                "INSERT INTO feed_allow VALUES ('192.0.2.92', 'ip', 'false_positive', NULL, :d, NULL, 'delist')"
            ),
            {"d": TODAY},
        )
        await ses.execute(
            text(
                "INSERT INTO feed_allow VALUES ('192.0.2.93', 'ip', 'owner_request', NULL, :d, NULL, 'admin')"
            ),
            {"d": TODAY},
        )
        await ses.commit()
    res = await run_job(env, s, T0 + timedelta(hours=8))
    assert res.state == "published"
    assert (feed_dir / "inbound.txt").read_text() == ""
    removed = (feed_dir / "removed.json").read_text()
    assert "192.0.2.92" not in removed and "192.0.2.93" not in removed
    stats = json.loads((feed_dir / "stats.json").read_text())
    assert stats["exclusions"]["allow_list"] == 2
    today = [d for d in stats["daily"] if d["list"] == "inbound"][-1]
    assert today["removed"]["delisted"] == 1 and today["removed"]["excluded"] == 1


def test_exclusion_module_has_no_client_address_handling() -> None:
    assert not hasattr(feed_filter, "client") and not hasattr(job, "request")

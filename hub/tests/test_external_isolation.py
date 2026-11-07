"""Isolation of the external tier (design M36 invariants X1 to X3, acceptance 2 to 5).

External data never enters targets, consensus, reports, submissions or the five network lists, and
network data never changes what the external tier publishes. Static checks read the source;
integration checks run both jobs against a throwaway PostgreSQL.
"""

from __future__ import annotations

import ast
import random
import re
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text

from hub import models
from hub.external_feed import job as ejob

from .conftest import Env
from .seed import add_nodes, observe
from .test_external_select import (
    NOW,
    ext_settings,
    external_dir,
    published_txt,
    run_ext,
    seed,
)
from .test_feeds_select import IP, SSH_FIELDS, add_ranges, confirm, feed_settings, run_job
from .test_feeds_select import D as DAYS

HUB = Path(__file__).resolve().parent.parent
PKG = HUB / "hub" / "external_feed"
SOURCES = sorted(PKG.glob("*.py"))
EXTERNAL_TABLES = {"external_entries", "external_feed_state"}
# Everything the external code may read or write in SQL (X1): its own tables and the key/value
# bookkeeping table. The exclusions are loaded by hub.feeds.filter (never_list, feed_allow,
# delist_requests, feed_auto_ranges), not here.
ALLOWED_SQL_TABLES = EXTERNAL_TABLES | {"worker_state", "hub_audit"}
NODE_SIDE = {
    "observations", "targets", "target_contributors", "reveals", "batches", "nodes",
    "takedown_votes", "payload_links", "target_hosts", "feed_entries", "feed_runs", "feed_daily",
    "reports", "recipient_log", "abusech_submissions", "verify_tasks", "verify_attestations",
    "node_roles", "node_stats_weekly", "network_daily", "network_summary",
}  # fmt: skip


def code_only(path: Path) -> str:
    """The source without comments and docstrings (they may talk about what is never done)."""
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                body[0].value.value = ""
    return ast.unparse(tree)


def imported_modules(path: Path) -> set[str]:
    out: set[str] = set()
    pkg = ".".join(path.relative_to(HUB).with_suffix("").parts[:-1])
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            out.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parts = pkg.split(".")[: len(pkg.split(".")) - node.level + 1]
                base = ".".join([*parts, base] if base else parts)
            out.add(base)
            out.update(f"{base}.{a.name}" for a in node.names)
    return out


# --- static ------------------------------------------------------------------------------------


def test_the_external_job_never_names_a_node_side_table() -> None:
    assert SOURCES, "external_feed package not found"
    for path in SOURCES:
        code = code_only(path)
        for table in NODE_SIDE:
            assert not re.search(rf"\b{table}\b", code), (path.name, table)


def sql_strings(path: Path) -> list[str]:
    return [
        n.value
        for n in ast.walk(ast.parse(path.read_text()))
        if isinstance(n, ast.Constant)
        and isinstance(n.value, str)
        and re.match(r"\s*(SELECT|INSERT|UPDATE|DELETE)\b", n.value)
    ]


def test_external_sql_touches_only_its_own_tables() -> None:
    seen = 0
    for path in SOURCES:
        for sql in sql_strings(path):
            seen += 1
            found = set(re.findall(r"\b(?:FROM|INTO|UPDATE|JOIN)\s+([a-z_]+)", sql))
            assert found <= ALLOWED_SQL_TABLES, (path.name, found - ALLOWED_SQL_TABLES)
    assert seen >= 8  # the check is not vacuous


def test_the_external_package_imports_nothing_that_reads_node_data() -> None:
    banned = (
        "hub.consensus", "hub.abusech", "hub.reports", "hub.verify", "hub.reputation",
        "hub.stats", "hub.external", "hub.feeds.job", "hub.feeds.select", "hub.feeds.lifecycle",
        "hub.feeds.stats", "hub.routes", "hub.main", "hub.worker", "hub.admin",
    )  # fmt: skip
    for path in SOURCES:
        for mod in imported_modules(path):
            assert not any(mod == b or mod.startswith(b + ".") for b in banned), (path.name, mod)


def test_nothing_that_decides_on_node_data_imports_the_external_package() -> None:
    allowed = {"worker.py", "admin.py", "config.py"}
    for path in (HUB / "hub").rglob("*.py"):
        if PKG in path.parents or (path.name in allowed and path.parent == HUB / "hub"):
            continue
        for mod in imported_modules(path):
            assert "external_feed" not in mod, (str(path.relative_to(HUB)), mod)


def test_the_five_lists_and_the_main_publisher_do_not_know_the_external_tables() -> None:
    for name in ("feeds/job.py", "feeds/select.py", "feeds/lifecycle.py", "consensus.py",
                 "abusech.py", "verify.py", "reputation.py"):  # fmt: skip
        source = (HUB / "hub" / name).read_text()
        assert "external_entries" not in source and "external_feed_state" not in source, name
    for path in (HUB / "hub" / "reports").glob("*.py"):
        assert "external_entries" not in path.read_text(), path.name


def test_external_tables_reference_no_node_and_hold_no_client_address() -> None:
    forbidden = {"node_id", "pubkey", "pseudonym", "fingerprint", "country", "ip", "client", "day"}
    for name in EXTERNAL_TABLES:
        table = models.Base.metadata.tables[name]
        assert forbidden.isdisjoint(c.name for c in table.columns), name
        assert not list(table.foreign_keys), name
    migration = (HUB / "migrations" / "versions" / "h0011_external.py").read_text()
    assert not re.search(r"\b(inet|cidr|macaddr|node_id)\b", migration, flags=re.I)


def test_the_api_role_cannot_touch_the_external_tables() -> None:
    from hub import roles

    assert not any("external" in g for g in roles.API_GRANTS)
    assert "external_entries" in roles.WORKER_TABLES


def test_the_main_index_validator_still_refuses_an_external_list_id() -> None:
    from suckerpot_netproto.feeds.models import LIST_IDS

    assert "external-outbound" not in LIST_IDS


# --- X3 and the property test (database) ---------------------------------------------------------


def snapshot(root: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in sorted(root.iterdir()) if p.is_file()}


async def reset_network(env: Env) -> None:
    async with env.worker() as ses:
        for table in (
            "target_contributors", "observations", "targets", "payload_links", "target_hosts",
            "feed_entries", "feed_runs", "feed_daily", "takedown_votes", "hub_audit",
        ):  # fmt: skip
            await ses.execute(text(f"DELETE FROM {table}"))
        await ses.execute(text("DELETE FROM worker_state WHERE key LIKE 'feed_%'"))
        await ses.commit()


async def drive_main(env: Env, s: Any) -> None:
    """Network data, consensus, then the main feed job to a published listing."""
    ids = await add_nodes(env.worker, 5)
    await observe(env.worker, ids, "ip", IP, DAYS[:2], **SSH_FIELDS)
    await confirm(env, s)
    await run_job(env, s)
    res = await run_job(env, s, NOW + timedelta(hours=7))
    assert res.state == "published"


@pytest.mark.integration
async def test_the_main_feed_is_byte_identical_with_the_external_tier_on_or_off(
    env: Env, tmp_path: Path, key_file: Path
) -> None:
    await add_ranges(env)
    off_dir, on_dir = tmp_path / "off", tmp_path / "on"
    off = feed_settings(off_dir, key_file, external_feed_mode="off")
    await drive_main(env, off)
    expected = snapshot(off_dir)
    assert "index.json" in expected and not (off_dir / "external").exists()

    await reset_network(env)
    on = feed_settings(on_dir, key_file, external_feed_mode="publish")
    await seed(env, ["203.0.113.45", "198.51.100.9"])
    assert (await run_ext(env, on)).state == "published"
    await drive_main(env, on)
    assert (await run_ext(env, on, NOW + timedelta(hours=8))).state in ("published", "unchanged")
    assert external_dir(on_dir).is_dir()
    assert snapshot(on_dir) == expected  # same five lists, same index, same signatures


@pytest.mark.integration
async def test_network_data_never_changes_what_the_external_tier_publishes(
    env: Env, tmp_path: Path, key_file: Path
) -> None:
    await add_ranges(env)
    external_values = ["203.0.113.45", "198.51.100.9", "2001:db8::45"]
    await seed(env, external_values)

    async def external_files(name: str) -> dict[str, bytes]:
        async with env.worker() as ses:
            await ses.execute(
                text("DELETE FROM worker_state WHERE key = :k"), {"k": ejob.SERIAL_KEY}
            )
            await ses.commit()
        s = ext_settings(tmp_path / name, key_file)
        assert (await run_ext(env, s)).state == "published"
        return snapshot(external_dir(tmp_path / name))

    baseline = await external_files("baseline")
    rng = random.Random(36)  # noqa: S311
    pool = [f"203.0.113.{i}" for i in range(1, 60)] + [f"198.51.100.{i}" for i in range(1, 60)]
    for round_no in range(4):
        await reset_network(env)
        ids = await add_nodes(env.worker, rng.randint(2, 8))
        values = rng.sample(pool, 12) + external_values[: rng.randint(0, 3)]
        for v in values:
            kind = rng.choice(["ip", "c2_ip", "payload_ip"])
            picked = ids[: rng.randint(1, len(ids))]
            await observe(env.worker, picked, kind, v, DAYS[: rng.randint(1, 3)], **SSH_FIELDS)
        s = feed_settings(tmp_path / f"main{round_no}", key_file)
        await confirm(env, s)
        await run_job(env, s)
        await run_job(env, s, NOW + timedelta(hours=7))
        assert await external_files(f"round{round_no}") == baseline


@pytest.mark.integration
async def test_external_values_never_enter_network_tables_or_the_five_lists(
    env: Env, tmp_path: Path, key_file: Path
) -> None:
    await add_ranges(env)
    await seed(env, ["203.0.113.45", "198.51.100.9"])
    s = ext_settings(tmp_path / "feeds", key_file)
    assert (await run_ext(env, s)).state == "published"
    ids = await add_nodes(env.worker, 5)
    await observe(env.worker, ids, "ip", IP, DAYS[:2], **SSH_FIELDS)
    await confirm(env, s)
    await run_job(env, s)
    await run_job(env, s, NOW + timedelta(hours=7))
    await run_ext(env, s, NOW + timedelta(hours=8))
    async with env.worker() as ses:
        for table, where in (
            ("targets", "coalesce(value_b, value, '')"),
            ("feed_entries", "value"),
            ("observations", "value"),
            ("abusech_submissions", "indicator"),
        ):
            hit = (
                await ses.execute(
                    text(
                        f"SELECT count(*) FROM {table} WHERE {where} IN ('203.0.113.45', '198.51.100.9')"
                    )
                )
            ).scalar_one()
            assert hit == 0, table
        assert (await ses.execute(text("SELECT count(*) FROM reports"))).scalar_one() == 0
    root = tmp_path / "feeds"
    for p in root.iterdir():
        if p.is_file() and not p.name.endswith(".gz"):
            blob = p.read_bytes()
            assert b"203.0.113.45" not in blob and b"198.51.100.9" not in blob, p.name
    assert published_txt(root) == ["198.51.100.9", "203.0.113.45"]

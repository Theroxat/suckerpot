"""Publication (design M30 section 6.6 and the change breaker, section 5.6)."""

from __future__ import annotations

import gzip
import os
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from suckerpot_netproto.feeds import FeedEntry, minisign, verify_file_against_index, verify_index
from suckerpot_netproto.feeds.models import LIST_IDS

from hub.config import Settings
from hub.feeds import job, publish

from .conftest import Env
from .seed import TODAY, add_nodes, observe
from .test_feeds_select import (
    SSH_FIELDS,
    add_ranges,
    confirm,
    entries,
    feed_settings,
    is_there,
    read,
    run_job,
)

T0 = datetime(2026, 11, 1, 0, 30, tzinfo=UTC)
D1, D2 = TODAY - timedelta(days=1), TODAY - timedelta(days=2)


def entry(value: str, tier: str = "standard", **kw: Any) -> FeedEntry:
    base: dict[str, Any] = {
        "value": value,
        "family": 4,
        "tier": tier,
        "categories": ["login-success"],
        "services": ["ssh"],
        "first_seen": "2026-10-30",
        "last_seen": "2026-10-31",
        "expires": "2026-11-07",
    }
    base.update(kw)
    return FeedEntry(**base)


def secret() -> minisign.SecretKey:
    return minisign.generate_keypair()


def render(serial: int, now: datetime, inbound: list[FeedEntry], **kw: Any) -> dict[str, Any]:
    lists = {"inbound": inbound, "inbound-high": [e for e in inbound if e.tier == "high"]}
    return publish.render_all(
        serial=serial, now=now, valid_days=3, lists=lists, allow_documentation=True, **kw
    )


def stat_ns(root: Path) -> dict[str, int]:
    return {p.name: p.stat().st_mtime_ns for p in root.iterdir() if p.is_file()}


# --- pure publication --------------------------------------------------------------------------


def test_files_are_signed_and_listed_in_the_index(tmp_path: Path) -> None:
    key = secret()
    rendered = render(1, T0, [entry("192.0.2.1"), entry("192.0.2.2", "high")])
    publish.publish(
        tmp_path,
        key,
        serial=1,
        now=T0,
        valid_days=3,
        rendered=rendered,
        other={"stats.json": b"{}"},
    )
    index = publish.read_index(tmp_path)
    assert index is not None and index.serial == 1
    index_bytes = (tmp_path / "index.json").read_bytes()
    verify_index(index_bytes, (tmp_path / "index.json.minisig").read_text(), key.public, now=T0)
    names = [f.name for lst in index.lists for f in lst.files] + [o.name for o in index.other]
    assert "inbound.txt" in names and "stats.json" in names
    for name in names:
        verify_file_against_index(
            index,
            name,
            (tmp_path / name).read_bytes(),
            (tmp_path / (name + ".minisig")).read_text(),
            key.public,
        )
    assert (tmp_path / "inbound-high.txt").read_text().split() == ["192.0.2.2"]
    assert sorted(p.name for p in tmp_path.iterdir() if p.name.startswith(".")) == []


def test_index_and_its_signature_are_moved_last(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    moved: list[str] = []
    real = os.replace

    def spy(src: Any, dst: Any) -> None:
        moved.append(Path(dst).name)
        real(src, dst)

    monkeypatch.setattr("hub.feeds.publish.os.replace", spy)
    publish.publish(
        tmp_path,
        secret(),
        serial=1,
        now=T0,
        valid_days=3,
        rendered=render(1, T0, [entry("192.0.2.1")]),
        other={"stats.json": b"{}"},
    )
    assert moved[-1] == "index.json" and moved[-2] == "index.json.minisig"
    assert moved.index("inbound.txt") < moved.index("index.json")
    assert all(not m.startswith("index.json") for m in moved[:-3])


def test_a_failure_before_the_move_leaves_the_published_files_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = secret()
    publish.publish(
        tmp_path,
        key,
        serial=1,
        now=T0,
        valid_days=3,
        rendered=render(1, T0, [entry("192.0.2.1")]),
        other={},
    )
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir() if p.is_file()}

    def boom(*_a: Any, **_k: Any) -> str:
        raise OSError("disk full")

    monkeypatch.setattr("hub.feeds.publish.minisign.sign_feed_file", boom)
    later = T0 + timedelta(hours=1)
    with pytest.raises(publish.PublishError):
        publish.publish(
            tmp_path,
            key,
            serial=2,
            now=later,
            valid_days=3,
            rendered=render(2, later, [entry("192.0.2.1"), entry("192.0.2.9")]),
            other={},
        )
    after = {p.name: p.read_bytes() for p in tmp_path.iterdir() if p.is_file()}
    assert after == before


def test_unchanged_files_keep_their_mtime_but_get_a_new_signature(tmp_path: Path) -> None:
    key = secret()
    one = [entry("192.0.2.1")]
    publish.publish(
        tmp_path, key, serial=1, now=T0, valid_days=3, rendered=render(1, T0, one), other={}
    )
    first = stat_ns(tmp_path)
    inbound_sig = (tmp_path / "inbound.txt.minisig").read_text()
    later = T0 + timedelta(hours=2)
    # Only the high list changes.
    two = [*one, entry("192.0.2.2", "high")]
    rendered = render(2, later, two)
    assert publish.changed_files(tmp_path, rendered, {}) != []
    publish.publish(tmp_path, key, serial=2, now=later, valid_days=3, rendered=rendered, other={})
    second = stat_ns(tmp_path)
    for name in ("inbound.v6.txt", "outbound.txt", "outbound-domains.csv", "outbound-high.rsc"):
        assert second[name] == first[name], name
    # inbound.txt gained a line, so it changed; the nft/ipset/rsc headers alone never count.
    assert second["inbound.txt"] != first["inbound.txt"]
    assert (tmp_path / "inbound.txt.minisig").read_text() != inbound_sig
    index = publish.read_index(tmp_path)
    assert index is not None and index.serial == 2
    verify_file_against_index(
        index,
        "outbound.txt",
        (tmp_path / "outbound.txt").read_bytes(),
        (tmp_path / "outbound.txt.minisig").read_text(),
        key.public,
    )


def test_only_the_header_changing_counts_as_unchanged(tmp_path: Path) -> None:
    key = secret()
    same = [entry("192.0.2.1")]
    publish.publish(
        tmp_path, key, serial=1, now=T0, valid_days=3, rendered=render(1, T0, same), other={}
    )
    later = T0 + timedelta(hours=5)
    assert publish.changed_files(tmp_path, render(7, later, same), {}) == []
    moved = [entry("192.0.2.1", last_seen="2026-10-31", expires="2026-11-08")]
    assert "inbound.json" in publish.changed_files(tmp_path, render(7, later, moved), {})


def test_gzip_sidecars_are_deterministic(tmp_path: Path) -> None:
    key = secret()
    a, b = tmp_path / "a", tmp_path / "b"
    rendered = render(1, T0, [entry("192.0.2.1")])
    for root in (a, b):
        publish.publish(root, key, serial=1, now=T0, valid_days=3, rendered=rendered, other={})
    for gz in a.glob("*.gz"):
        assert gz.read_bytes() == (b / gz.name).read_bytes()
        assert gzip.decompress(gz.read_bytes()) == (a / gz.name[:-3]).read_bytes()
    assert gz.read_bytes()[4:8] == b"\x00\x00\x00\x00"  # gzip mtime field is zero


def test_an_oversized_file_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key = secret()
    publish.publish(
        tmp_path,
        key,
        serial=1,
        now=T0,
        valid_days=3,
        rendered=render(1, T0, [entry("192.0.2.1")]),
        other={},
    )
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir() if p.is_file()}
    monkeypatch.setattr("suckerpot_netproto.feeds.render.MAX_FILE_BYTES", 300)
    with pytest.raises(publish.PublishError, match="too_large"):
        render(2, T0, [entry(f"192.0.2.{i}") for i in range(1, 60)])
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir() if p.is_file()} == before


def test_mode_off_reads_and_writes_nothing(tmp_path: Path) -> None:
    import asyncio

    s = Settings(feed_mode="off", feed_dir=str(tmp_path / "feeds"))
    res = asyncio.run(job.run_once(None, s, T0, force=True))  # type: ignore[arg-type]
    assert res.state == "off" and not (tmp_path / "feeds").exists()
    s2 = Settings(feed_mode="auto", feed_dir=str(tmp_path / "feeds"), external_ranges_enabled=False)
    assert asyncio.run(job.run_once(None, s2, T0, force=True)).state == "off"  # type: ignore[arg-type]


def test_every_list_has_files_even_when_empty(tmp_path: Path) -> None:
    publish.publish(
        tmp_path, secret(), serial=1, now=T0, valid_days=3, rendered=render(1, T0, []), other={}
    )
    index = publish.read_index(tmp_path)
    assert index is not None and [lst.id for lst in index.lists] == list(LIST_IDS)
    assert (tmp_path / "inbound.txt").read_text() == ""


# --- the job: serials, breaker, review mode ------------------------------------------------------


async def seed_attackers(env: Env, ids: list[Any], count: int, start: int = 0) -> list[str]:
    values = [f"192.0.2.{start + i}" for i in range(1, count + 1)]
    for v in values:
        await observe(env.worker, ids, "ip", v, [D1, D2], **SSH_FIELDS)
    return values


@pytest.mark.integration
async def test_serial_is_monotonic_and_an_idle_run_changes_nothing(
    env: Env, feed_dir: Path, key_file: Path
) -> None:
    s = feed_settings(feed_dir, key_file)
    await add_ranges(env)
    ids = await add_nodes(env.worker, 5)
    await seed_attackers(env, ids, 3)
    await confirm(env, s)
    first = await run_job(env, s, T0)
    listed = await run_job(env, s, T0 + timedelta(hours=7))
    assert first.serial is not None and listed.serial is not None and listed.serial > first.serial
    snapshot = stat_ns(feed_dir)
    idle = await run_job(env, s, T0 + timedelta(hours=8))
    assert idle.state == "unchanged" and stat_ns(feed_dir) == snapshot
    index = publish.read_index(feed_dir)
    assert index is not None and index.serial == listed.serial


@pytest.mark.integration
async def test_keepalive_resigns_before_the_index_expires_without_touching_data(
    env: Env, feed_dir: Path, key_file: Path
) -> None:
    s = feed_settings(feed_dir, key_file)
    await add_ranges(env)
    ids = await add_nodes(env.worker, 5)
    await seed_attackers(env, ids, 2)
    await confirm(env, s)
    await run_job(env, s, T0)
    done = await run_job(env, s, T0 + timedelta(hours=7))
    data = {
        k: v
        for k, v in stat_ns(feed_dir).items()
        if not k.endswith((".minisig", "index.json", "index.json.gz"))
    }
    assert done.serial is not None
    # Two days later the index has 1 day of validity left: re-sign with a new serial.
    alive = await run_job(env, s, T0 + timedelta(days=2, hours=7))
    assert alive.state == "published" and alive.serial is not None and alive.serial > done.serial
    after = stat_ns(feed_dir)
    for name, ns in data.items():
        if name in ("stats.json", "stats.json.gz", "removed.json", "removed.json.gz"):
            continue
        assert after[name] == ns, name
    index = publish.read_index(feed_dir)
    assert index is not None and index.serial == alive.serial


@pytest.mark.integration
async def test_breaker_holds_a_large_change_until_the_operator_releases_it(
    env: Env, feed_dir: Path, key_file: Path
) -> None:
    s = feed_settings(feed_dir, key_file, feed_breaker_min=5)
    await add_ranges(env)
    ids = await add_nodes(env.worker, 5)
    await seed_attackers(env, ids, 10)
    await confirm(env, s)
    await run_job(env, s, T0)  # pending (publishes the empty lists)
    held = await run_job(env, s, T0 + timedelta(hours=7))  # 0 -> 10 entries: over the breaker
    assert held.state == "held" and held.serial is not None
    assert read(feed_dir / "inbound.txt") == ""  # previous (empty) files keep serving
    async with env.worker() as ses:
        assert await job.release(ses, held.serial)
    out = await run_job(env, s, T0 + timedelta(hours=8))
    assert out.state == "published" and len(read(feed_dir / "inbound.txt").split()) == 10
    # +6 on 10 is +60 %: held again, files untouched, the audit trail has the entry.
    await seed_attackers(env, ids, 6, start=20)
    await confirm(env, s)
    await run_job(env, s, T0 + timedelta(hours=9))
    before = stat_ns(feed_dir)
    tripped = await run_job(env, s, T0 + timedelta(hours=16))
    assert tripped.state == "held" and stat_ns(feed_dir) == before
    again = await run_job(env, s, T0 + timedelta(hours=17))  # the same change is not held twice
    assert again.state == "held" and again.serial == tripped.serial
    async with env.worker() as ses:
        assert await job.release(ses, tripped.serial or 0)
    final = await run_job(env, s, T0 + timedelta(hours=18))
    assert final.state == "published" and len(read(feed_dir / "inbound.txt").split()) == 16
    async with env.worker() as ses:
        from sqlalchemy import text

        audit = (
            (await ses.execute(text("SELECT action FROM hub_audit ORDER BY id"))).scalars().all()
        )
    assert audit.count("feeds.held") == 2 and "feeds.release" in audit


@pytest.mark.integration
async def test_discarded_change_is_not_held_again(env: Env, feed_dir: Path, key_file: Path) -> None:
    s = feed_settings(feed_dir, key_file, feed_breaker_min=5)
    await add_ranges(env)
    ids = await add_nodes(env.worker, 5)
    await seed_attackers(env, ids, 10)
    await confirm(env, s)
    await run_job(env, s, T0)
    held = await run_job(env, s, T0 + timedelta(hours=7))
    async with env.worker() as ses:
        assert await job.discard(ses, held.serial or 0)
    res = await run_job(env, s, T0 + timedelta(hours=8))
    assert res.state == "discarded" and read(feed_dir / "inbound.txt") == ""


@pytest.mark.integration
async def test_review_mode_holds_every_run_with_additions(
    env: Env, feed_dir: Path, key_file: Path
) -> None:
    s = feed_settings(feed_dir, key_file, feed_mode="review", feed_breaker_min=1000)
    await add_ranges(env)
    ids = await add_nodes(env.worker, 5)
    await seed_attackers(env, ids, 1)
    await confirm(env, s)
    await run_job(env, s, T0)
    held = await run_job(env, s, T0 + timedelta(hours=7))
    assert held.state == "held" and "192.0.2.1" not in read(feed_dir / "inbound.txt")
    async with env.worker() as ses:
        await job.release(ses, held.serial or 0)
    assert (await run_job(env, s, T0 + timedelta(hours=8))).state == "published"
    assert read(feed_dir / "inbound.txt").split() == ["192.0.2.1"]


@pytest.mark.integration
async def test_an_oversized_list_fails_the_run_and_keeps_the_old_files(
    env: Env, feed_dir: Path, key_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = feed_settings(feed_dir, key_file)
    await add_ranges(env)
    ids = await add_nodes(env.worker, 5)
    await seed_attackers(env, ids, 3)
    await confirm(env, s)
    await run_job(env, s, T0)
    monkeypatch.setattr("suckerpot_netproto.feeds.render.MAX_FILE_BYTES", 200)
    res = await run_job(env, s, T0 + timedelta(hours=7))
    assert res.state == "failed" and res.error_code == "too_large"
    assert read(feed_dir / "inbound.txt") == ""
    got = await entries(env, "state = 'listed'")
    assert got == {}  # the run's storing was rolled back with it
    async with env.worker() as ses:
        from sqlalchemy import text

        states = (
            (await ses.execute(text("SELECT state FROM feed_runs ORDER BY serial"))).scalars().all()
        )
    assert states[-1] == "failed"


@pytest.mark.integration
async def test_paused_and_interval(env: Env, feed_dir: Path, key_file: Path) -> None:
    s = feed_settings(feed_dir, key_file)
    await add_ranges(env)
    async with env.worker() as ses:
        await job.set_paused(ses, True)
        assert (await job.run_once(ses, s, T0, force=True)).state == "paused"
        await job.set_paused(ses, False)
        assert (await job.run_once(ses, s, T0)).state in ("published", "unchanged")
        assert (await job.run_once(ses, s, T0 + timedelta(minutes=10))).state == "skipped"
        assert (await job.run_once(ses, s, T0 + timedelta(minutes=61))).state in (
            "published",
            "unchanged",
        )


@pytest.mark.integration
async def test_taken_down_hosts_leave_at_the_next_run(
    env: Env, feed_dir: Path, key_file: Path
) -> None:
    from sqlalchemy import text

    s = feed_settings(feed_dir, key_file)
    await add_ranges(env)
    ids = await add_nodes(env.worker, 10)
    host = "198.51.100.7"
    for batch, fetched in ((ids[:2], True), (ids[2:], False)):
        await observe(
            env.worker,
            batch,
            "payload_ip",
            host,
            [D1, D2],
            activity=["download"],
            families=["mirai"],
            fetched=fetched,
            services=[],
            tags=[],
        )
    await confirm(env, s)
    async with env.worker() as ses:
        await ses.execute(
            text(
                "INSERT INTO targets (id, kind, value_b, state, first_day, last_day, confirmed_day) "
                "VALUES ('t_0000000000aa', 'url', 'urlblind', 'confirmed', :d, :d, :d)"
            ),
            {"d": D1},
        )
        await ses.execute(
            text("INSERT INTO payload_links VALUES (:d, 'payload_ip', :h, 'urlblind')"),
            {"d": D1, "h": host},
        )
        await ses.commit()
    await run_job(env, s, T0)
    await run_job(env, s, T0 + timedelta(hours=7))
    assert host in read(feed_dir / "outbound.txt")
    async with env.worker() as ses:
        await ses.execute(
            text("UPDATE targets SET state = 'taken_down' WHERE id = 't_0000000000aa'")
        )
        await ses.commit()
    res = await run_job(env, s, T0 + timedelta(hours=8))
    assert res.state == "published" and host not in read(feed_dir / "outbound.txt")
    row = (await entries(env))[("outbound", host)]
    assert (row.state, row.removed_reason) == ("removed", "taken_down")
    assert host in read(feed_dir / "removed.json")


@pytest.mark.integration
async def test_invalid_key_file_stops_the_run(env: Env, feed_dir: Path, tmp_path: Path) -> None:
    bad = tmp_path / "nokey"
    bad.write_text("not a key")
    s = feed_settings(feed_dir, bad)
    res = await run_job(env, s)
    assert (res.state, res.error_code) == ("failed", "no_key") and not is_there(feed_dir)


def test_documentation_flag_is_needed_for_example_addresses() -> None:
    # The renderers refuse documentation ranges unless the test flag is set.
    ctx_kwargs: dict[str, Any] = {
        "serial": 1,
        "now": T0,
        "valid_days": 3,
        "lists": {"inbound": [entry("192.0.2.1")]},
    }
    rendered = publish.render_all(allow_documentation=False, **ctx_kwargs)
    assert rendered["inbound"].entries == [] and rendered["inbound"].dropped == 1
    assert date.fromisoformat("2026-11-01")


@pytest.mark.integration
async def test_payload_hosts_are_recorded_without_a_node_and_hidden_from_nodes(env: Env) -> None:
    from sqlalchemy import text

    from .helpers import batch

    (node,) = await env.enrolled()
    body = batch(
        "2026-10-31",
        payloads=[
            {
                "url_b": "ab" * 32,
                "host_ip": "192.0.2.1",
                "sha256": "12" * 32,
                "fetched": True,
                "family": "mirai",
            },
            {"url_b": "cd" * 32, "host_b": "ef" * 32},
        ],
    )
    reply = await node.call("POST", "/v1/observations", body)
    assert reply.status == 200, reply.json
    async with env.worker() as ses:
        links = (await ses.execute(text("SELECT * FROM payload_links ORDER BY kind"))).all()
        await ses.execute(
            text(
                "INSERT INTO targets (id, kind, value, state, first_day, last_day, seq) VALUES "
                "('t_00000000bb01', 'payload_ip', '192.0.2.1', 'confirmed', :d, :d, 0)"
            ),
            {"d": D1},
        )
        await ses.commit()
    assert [(r.kind, r.value) for r in links] == [
        ("domain", "ef" * 32),
        ("payload_ip", "192.0.2.1"),
    ]
    assert not hasattr(links[0], "node_id")
    got = await node.call("GET", "/v1/targets")
    assert got.status == 200 and got.json["targets"] == []  # nodes never see payload_ip


@pytest.mark.integration
async def test_models_match_the_migration(env: Env) -> None:
    from sqlalchemy import text

    from hub import models

    names = [
        "feed_entries", "feed_runs", "feed_daily", "feed_allow", "feed_auto_ranges",
        "payload_links", "target_hosts", "delist_challenges", "delist_requests",
    ]  # fmt: skip
    async with env.worker() as ses:
        for name in names:
            rows = await ses.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = 'public' AND table_name = :t"
                ),
                {"t": name},
            )
            assert {r[0] for r in rows} == {
                c.name for c in models.Base.metadata.tables[name].columns
            }

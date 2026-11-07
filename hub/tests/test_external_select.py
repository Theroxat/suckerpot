"""Selection, breaker and publication of the external list (design M36 T3).

The first half is pure (no database). The second half runs the whole job against a throwaway
PostgreSQL with fixture rows: nothing reaches abuse.ch.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from suckerpot_netproto.feeds import minisign
from suckerpot_netproto.feeds.external import (
    parse_external_list_json,
    parse_external_txt,
    verify_external_file,
    verify_external_index,
)

from hub.external_feed import job as ejob
from hub.external_feed import select
from hub.external_feed.select import SourceRow

from .conftest import Env, make_settings
from .seed import TODAY, shipped_ranges
from .test_feeds_select import add_ranges

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
D = timedelta(days=1)


def row(value: str, *, last: date = TODAY, first: date | None = None, **kw: Any) -> SourceRow:
    fam = 6 if ":" in value else 4
    base: dict[str, Any] = {
        "source": "feodotracker",
        "value": value,
        "family": fam,
        "ports": (443,),
        "families": (),
        "first_seen": first or last,
        "last_seen": last,
    }
    base.update(kw)
    return SourceRow(**base)


def keep_all(_value: str) -> str | None:
    return None


# --- pure selection ---------------------------------------------------------------------------


def test_entries_carry_the_source_and_expire_seven_days_after_last_seen() -> None:
    sel = select.select_entries(
        [row("203.0.113.45", last=TODAY - 2 * D, first=TODAY - 5 * D)],
        today=TODAY,
        excluded=keep_all,
    )
    (e,) = sel.entries
    assert e["sources"] == ["feodotracker"] and e["categories"] == ["c2"]
    assert e["list"] == "external-outbound" and e["ports"] == [443]
    assert (e["first_seen"], e["last_seen"]) == ("2026-10-27", "2026-10-30")
    assert e["expires"] == "2026-11-06"


def test_expiry_boundary() -> None:
    rows = [row("203.0.113.1", last=TODAY - 7 * D), row("203.0.113.2", last=TODAY - 8 * D)]
    sel = select.select_entries(rows, today=TODAY, excluded=keep_all)
    assert sel.values == {"203.0.113.1"} and sel.expired == 1


def test_excluded_values_are_dropped_and_counted_by_reason() -> None:
    reasons = {"203.0.113.1": "cdn", "203.0.113.2": "tor", "203.0.113.3": "never_list"}
    rows = [row(v) for v in (*reasons, "203.0.113.4")]
    sel = select.select_entries(rows, today=TODAY, excluded=reasons.get)
    assert sel.values == {"203.0.113.4"}
    assert dict(sel.excluded) == {"cdn": 1, "tor": 1, "never_list": 1}


def test_sources_merge_by_value() -> None:
    rows = [
        row("203.0.113.1", ports=(443,), last=TODAY - D),
        row("203.0.113.1", source="other", ports=(80, 443), last=TODAY, first=TODAY - 9 * D),
    ]
    (e,) = select.select_entries(rows, today=TODAY, excluded=keep_all).entries
    assert e["sources"] == ["feodotracker", "other"] and e["ports"] == [80, 443]
    assert (e["first_seen"], e["last_seen"]) == ("2026-10-23", "2026-11-01")


def test_the_cap_keeps_the_newest_and_is_deterministic() -> None:
    rows = [row(f"203.0.113.{i}", last=TODAY - (i % 3) * D) for i in range(1, 11)]
    a = select.select_entries(rows, today=TODAY, excluded=keep_all, cap=4)
    b = select.select_entries(list(reversed(rows)), today=TODAY, excluded=keep_all, cap=4)
    assert a.capped == 6 and len(a.entries) == 4 and a.entries == b.entries
    newest = {"203.0.113.3", "203.0.113.6", "203.0.113.9"}
    assert newest <= {e["value"] for e in a.entries}


def test_ports_are_capped_at_sixteen() -> None:
    (e,) = select.select_entries(
        [row("203.0.113.1", ports=tuple(range(1000, 1040)))], today=TODAY, excluded=keep_all
    ).entries
    assert len(e["ports"]) == 16


def test_breaker_thresholds() -> None:
    old = {f"203.0.113.{i}" for i in range(1, 11)}
    kw = {"add_pct": 50, "remove_pct": 50, "minimum": 3}
    assert select.breaker(None, old, **kw) == []  # the first publication is never held
    assert select.breaker(old, old | {"198.51.100.1"}, **kw) == []
    assert [
        t.reason for t in select.breaker(old, old | {f"198.51.100.{i}" for i in range(6)}, **kw)
    ] == ["add"]
    assert [t.reason for t in select.breaker(old, set(list(old)[:2]), **kw)] == ["remove"]
    assert select.breaker(old, set(list(old)[:8]), **kw) == []  # below the minimum count


def test_digest_names_exactly_the_change() -> None:
    a, b = {"203.0.113.1"}, {"203.0.113.1", "203.0.113.2"}
    assert select.digest(a, b) == select.digest(a, b)
    assert select.digest(a, b) != select.digest(a, {"203.0.113.1", "203.0.113.3"})


# --- the job (database) -----------------------------------------------------------------------


def secret_of(key_file: Path) -> minisign.SecretKey:
    return minisign.parse_secret_key(key_file.read_text(encoding="ascii"))


def ext_settings(feed_dir: Path, key_file: Path, **over: Any) -> Any:
    base: dict[str, Any] = {
        "feed_mode": "auto",
        "external_feed_mode": "publish",
        "feed_dir": str(feed_dir),
        "feed_signing_key_file": str(key_file),
        "feed_breaker_min": 1000,
    }
    return make_settings(**{**base, **over})


async def seed(
    env: Env, values: Iterable[str], *, last: date = TODAY, ok: bool = True, ports: tuple[int, ...] = (443,)
) -> None:
    async with env.worker() as ses:
        for v in values:
            await ses.execute(
                text(
                    "INSERT INTO external_entries (source, value, family, ports, first_seen, "
                    "last_seen) VALUES ('feodotracker', :v, :f, CAST(:p AS integer[]), :l, :l) "
                    "ON CONFLICT (source, value) DO UPDATE SET last_seen = EXCLUDED.last_seen"
                ),
                {"v": v, "f": 6 if ":" in v else 4, "p": list(ports), "l": last},
            )
        if ok:
            await ses.execute(
                text(
                    "INSERT INTO external_feed_state (source, last_try_at, last_ok_at, entry_count) "
                    "VALUES ('feodotracker', :n, :n, 0) ON CONFLICT (source) DO NOTHING"
                ),
                {"n": NOW},
            )
        await ses.commit()


async def run_ext(env: Env, s: Any, now: datetime = NOW) -> ejob.JobResult:
    async with env.worker() as ses:
        return await ejob.run_once(ses, s, now)


def exists(path: Path) -> bool:
    return path.exists()


def external_dir(feed_dir: Path) -> Path:
    return feed_dir / "external"


def published_txt(feed_dir: Path) -> list[str]:
    return (external_dir(feed_dir) / "external-outbound.txt").read_text().split()


@pytest.mark.integration
async def test_nothing_is_published_while_off_or_waiting(
    env: Env, feed_dir: Path, key_file: Path
) -> None:
    await add_ranges(env)
    await seed(env, ["203.0.113.45"])
    off = ext_settings(feed_dir, key_file, external_feed_mode="off")
    assert (await run_ext(env, off)).state == "off"
    assert not exists(feed_dir)
    async with env.worker() as ses:
        await ses.execute(text("DELETE FROM external_feed_state"))
        await ses.commit()
    # No successful fetch yet: an empty list would pass for "no C2 exists", so nothing is served.
    assert (await run_ext(env, ext_settings(feed_dir, key_file))).state == "waiting"
    assert not exists(feed_dir)


@pytest.mark.integration
async def test_publish_with_zero_nodes_verifies_with_the_feed_key(
    env: Env, feed_dir: Path, key_file: Path
) -> None:
    await add_ranges(env)
    await seed(env, ["203.0.113.45", "198.51.100.9", "2001:db8::45"])
    res = await run_ext(env, ext_settings(feed_dir, key_file))
    assert (res.state, res.serial) == ("published", 1)
    root = external_dir(feed_dir)
    pub = secret_of(key_file).public
    raw = (root / "index.json").read_bytes()
    index = verify_external_index(raw, (root / "index.json.minisig").read_text(), pub, now=NOW)
    assert index.lists[0].entries == 3 and index.sources[0].id == "feodotracker"
    for ref in index.lists[0].files:
        data = (root / ref.name).read_bytes()
        verify_external_file(
            index, ref.name, data, (root / (ref.name + ".minisig")).read_text(), pub
        )
        assert (root / (ref.name + ".gz")).exists()
    readme = index.find_file("readme.txt")
    assert readme is not None
    text_ = (root / "readme.txt").read_text()
    assert "Feodo Tracker" in text_ and "Not confirmed by the SuckerPot network" in text_
    values = parse_external_txt(
        (root / "external-outbound.txt").read_bytes(), allow_documentation=True
    )
    assert values == ["198.51.100.9", "203.0.113.45", "2001:db8::45"]
    parsed = parse_external_list_json(
        (root / "external-outbound.json").read_bytes(), allow_documentation=True
    )
    assert parsed.feed.entries[0].sources == ["feodotracker"]
    assert not list(root.glob(".tmp-*"))


@pytest.mark.integration
async def test_excluded_values_never_reach_a_file(env: Env, feed_dir: Path, key_file: Path) -> None:
    await add_ranges(env)  # tor 203.0.113.64/28, cdn 203.0.113.128/28
    async with env.worker() as ses:
        await ses.execute(
            text(
                "INSERT INTO feed_allow (value, kind, reason, added_day, source) "
                "VALUES ('198.51.100.20', 'ip', 'owner_request', :d, 'admin')"
            ),
            {"d": TODAY},
        )
        await ses.commit()
    private = ".".join(("10", "9", "8", "7"))
    excluded = ["203.0.113.70", "203.0.113.130", "198.51.100.20", "198.51.100.99", private]
    await seed(env, ["203.0.113.45", *excluded])
    s = ext_settings(feed_dir, key_file, feed_never=("198.51.100.99",))
    res = await run_ext(env, s)
    assert res.state == "published"
    root = external_dir(feed_dir)
    assert published_txt(feed_dir) == ["203.0.113.45"]
    blob = b"".join(p.read_bytes() for p in root.iterdir() if not p.name.endswith(".gz"))
    for value in excluded:
        assert value.encode() not in blob, value
    assert res.detail["excluded"] == {
        "cdn": 1,
        "tor": 1,
        "allow_list": 1,
        "never_list": 1,
        "reserved": 1,
    }


@pytest.mark.integration
async def test_a_delisting_decision_on_outbound_removes_the_value(
    env: Env, feed_dir: Path, key_file: Path
) -> None:
    await add_ranges(env)
    await seed(env, ["203.0.113.45", "203.0.113.46"])
    async with env.worker() as ses:
        await ses.execute(
            text(
                "INSERT INTO feed_allow (value, kind, reason, added_day, source, list) "
                "VALUES ('203.0.113.46', 'ip', 'false_positive', :d, 'delist', 'outbound')"
            ),
            {"d": TODAY},
        )
        await ses.commit()
    await run_ext(env, ext_settings(feed_dir, key_file))
    assert published_txt(feed_dir) == ["203.0.113.45"]


@pytest.mark.integration
async def test_stale_ranges_stop_the_job_and_keep_the_files(
    env: Env, feed_dir: Path, key_file: Path
) -> None:
    await add_ranges(env)
    await seed(env, ["203.0.113.45"])
    s = ext_settings(feed_dir, key_file)
    assert (await run_ext(env, s)).state == "published"
    before = (external_dir(feed_dir) / "index.json").read_bytes()
    res = await run_ext(env, s, NOW + timedelta(days=40))
    assert (res.state, res.error_code) == ("failed", "ranges_stale")
    assert (external_dir(feed_dir) / "index.json").read_bytes() == before


@pytest.mark.integration
async def test_missing_key_fails_closed(env: Env, feed_dir: Path, tmp_path: Path) -> None:
    await add_ranges(env)
    await seed(env, ["203.0.113.45"])
    res = await run_ext(env, ext_settings(feed_dir, tmp_path / "absent.key"))
    assert (res.state, res.error_code) == ("failed", "no_key")
    assert not exists(feed_dir)


@pytest.mark.integration
async def test_unchanged_run_publishes_nothing_and_expired_rows_leave(
    env: Env, feed_dir: Path, key_file: Path
) -> None:
    await add_ranges(env)
    await seed(env, ["203.0.113.45"])
    await seed(env, ["203.0.113.46"], last=TODAY - 8 * D)
    s = ext_settings(feed_dir, key_file)
    first = await run_ext(env, s)
    assert first.state == "published" and published_txt(feed_dir) == ["203.0.113.45"]
    index_before = (external_dir(feed_dir) / "index.json").read_bytes()
    again = await run_ext(env, s, NOW + timedelta(hours=1))
    assert again.state == "unchanged"
    assert (external_dir(feed_dir) / "index.json").read_bytes() == index_before


@pytest.mark.integration
async def test_a_stale_index_is_refreshed_with_a_new_serial(
    env: Env, feed_dir: Path, key_file: Path
) -> None:
    await add_ranges(env)
    await seed(env, ["203.0.113.45"])
    s = ext_settings(feed_dir, key_file, feed_valid_days=2)
    await run_ext(env, s)
    later = NOW + timedelta(hours=40)
    await shipped_ranges(env.worker, later.date())
    async with env.worker() as ses:
        await ses.execute(text("UPDATE external_entries SET last_seen = :d"), {"d": later.date()})
        await ses.commit()
    res = await run_ext(env, s, later)
    assert (res.state, res.serial) == ("published", 2)


@pytest.mark.integration
async def test_upstream_removal_propagates_and_serials_only_grow(
    env: Env, feed_dir: Path, key_file: Path
) -> None:
    await add_ranges(env)
    await seed(env, ["203.0.113.45", "203.0.113.46"])
    s = ext_settings(feed_dir, key_file)
    assert (await run_ext(env, s)).serial == 1
    async with env.worker() as ses:
        await ses.execute(text("DELETE FROM external_entries WHERE value = '203.0.113.46'"))
        await ses.commit()
    res = await run_ext(env, s, NOW + timedelta(hours=1))
    assert (res.state, res.serial) == ("published", 2)
    assert published_txt(feed_dir) == ["203.0.113.45"]
    index = json.loads((external_dir(feed_dir) / "index.json").read_bytes())
    assert index["serial"] == 2 and index["schema"] == "selfhostr-external/1"


@pytest.mark.integration
async def test_a_large_change_is_held_until_an_operator_releases_it(
    env: Env, feed_dir: Path, key_file: Path
) -> None:
    await add_ranges(env)
    await seed(env, [f"203.0.113.{i}" for i in range(1, 5)])
    s = ext_settings(feed_dir, key_file, feed_breaker_min=3)
    assert (await run_ext(env, s)).state == "published"
    await seed(env, [f"198.51.100.{i}" for i in range(1, 8)])
    held = await run_ext(env, s, NOW + timedelta(hours=1))
    assert held.state == "held" and len(published_txt(feed_dir)) == 4
    async with env.worker() as ses:
        assert await ejob.release(ses) is True
    res = await run_ext(env, s, NOW + timedelta(hours=2))
    assert res.state == "published" and len(published_txt(feed_dir)) == 11
    async with env.worker() as ses:
        assert await ejob.release(ses) is False  # nothing is held any more
        info = await ejob.status(ses)
    assert info["held"] is False and info["last_run"]["state"] == "published"

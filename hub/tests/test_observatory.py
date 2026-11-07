"""The public network observatory (design M34): anonymity rules, publication, worker step."""

from __future__ import annotations

import gzip
import json
import re
import stat
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text

from hub import observatory as obs
from hub.config import Settings
from hub.observatory import DayRow, ItemRow, ObservatoryInput, OutcomeDay
from hub.worker import WorkerContext, run_cycle

from .conftest import Env
from .seed import TODAY, add_nodes, observe

HUB = Path(__file__).resolve().parent.parent
D0 = date(2026, 11, 7)  # a Saturday
LAST = D0 - timedelta(days=obs.FINAL_LAG_DAYS)  # last published activity day

# Keys (or key parts) that must never appear anywhere in the document.
FORBIDDEN_TOKENS = {
    "id_node",
    "node_id",
    "nodeid",
    "fingerprint",
    "pseudonym",
    "pubkey",
    "key",
    "ip",
    "ips",
    "address",
    "addr",
    "host",
    "value",
    "country_code",
    "reputation",
    "tier",
}
IP_LIKE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-f:]*:[0-9a-f:]+$", re.I)
HEX_ID = re.compile(r"^[0-9a-f]{8,}$", re.I)


def walk(doc: Any, path: str = "$") -> list[tuple[str, str, Any]]:
    """Every (path, key, value) in the document."""
    out: list[tuple[str, str, Any]] = []
    if isinstance(doc, dict):
        for k, v in doc.items():
            out.append((path, k, v))
            out.extend(walk(v, f"{path}.{k}"))
    elif isinstance(doc, list):
        for i, v in enumerate(doc):
            out.extend(walk(v, f"{path}[{i}]"))
    return out


def assert_clean(doc: dict[str, Any]) -> None:
    """No key that names a node or an address, no value that looks like one."""
    for path, key, value in walk(doc):
        low = key.lower()
        tokens = set(low.split("_")) | {low}
        assert not tokens & FORBIDDEN_TOKENS, f"forbidden key {path}.{key}"
        for word in ("node_id", "fingerprint", "pseudonym", "pubkey", "address"):
            assert word not in low, f"forbidden key {path}.{key}"
        if isinstance(value, str):
            assert not IP_LIKE.match(value), f"{path}.{key} looks like an address"
            assert not HEX_ID.match(value), f"{path}.{key} looks like an identifier"


def day_row(d: date, nodes: int, sources: int = 1234, **values: int) -> DayRow:
    base = {"sources": sources, "login": 456, "command": 78, "download": 9, "exploit": 3}
    base.update({"payload_urls": 12, "files": 40, "c2": 2})
    base.update(values)
    return DayRow(d, nodes, base)


def scenario(nodes: int, *, days: int = 35, **over: Any) -> ObservatoryInput:
    rows = [day_row(LAST - timedelta(days=i), nodes) for i in range(days)]
    items: list[ItemRow] = []
    for r in rows:
        items += [
            ItemRow(r.day, "service", "ssh", 900, nodes),
            ItemRow(r.day, "service", "telnet", 300, nodes),
            ItemRow(r.day, "service", "web", 34, nodes),
            ItemRow(r.day, "tag", "mirai", 120, nodes),
            ItemRow(r.day, "tag", "recon", 400, nodes),
            ItemRow(r.day, "family", "mirai", 30, nodes),
        ]
    base: dict[str, Any] = {
        "today": D0,
        "min_nodes": 5,
        "members": nodes,
        "active_7d": nodes,
        "eligible": 0,
        "days": rows,
        "items": items,
    }
    base.update(over)
    return ObservatoryInput(**base)


# --- rounding ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("n", "sig", "want"),
    [
        (0, 1, 0),
        (4, 1, 0),
        (5, 1, 10),
        (14, 2, 10),
        (15, 2, 20),
        (1234, 1, 1000),
        (1234, 2, 1200),
        (1250, 2, 1300),
        (2600, 1, 3000),
        (98765, 2, 99000),
        (-3, 2, 0),
    ],
)
def test_round_figure(n: int, sig: int, want: int) -> None:
    assert obs.round_figure(n, sig) == want


def test_round_figure_never_returns_an_exact_small_count() -> None:
    for n in range(1, 2000):
        for sig in (1, 2):
            assert obs.round_figure(n, sig) % 10 == 0


@pytest.mark.parametrize(
    ("part", "whole", "step", "want"),
    [(0, 10, 1, 0), (5, 0, 1, 0), (1, 3, 1, 33), (1, 3, 5, 35), (2, 100, 5, 0), (3, 100, 5, 5)],
)
def test_round_share(part: int, whole: int, step: int, want: int) -> None:
    assert obs.round_share(part, whole, step) == want


# --- bootstrap ----------------------------------------------------------------------------------


def test_earliest_eligible_waits_for_age_and_active_days() -> None:
    enrolled = D0 - timedelta(days=3)
    got = obs.earliest_eligible(D0, enrolled, [], min_age_days=14, min_active_days=7)
    assert got == enrolled + timedelta(days=14)
    # Old enough, 4 batch days in the window: 3 more days of batches are needed.
    batches = [D0 - timedelta(days=i) for i in (1, 2, 3, 4)]
    old = D0 - timedelta(days=60)
    got = obs.earliest_eligible(D0, old, batches, min_age_days=14, min_active_days=7)
    assert got == D0 + timedelta(days=3)
    # Already eligible: today.
    batches = [D0 - timedelta(days=i) for i in range(1, 8)]
    assert obs.earliest_eligible(D0, old, batches, min_age_days=14, min_active_days=7) == D0


def test_first_consensus_day() -> None:
    assert obs.first_consensus_day(D0, 5, 0, [D0]) is None
    days = [D0 + timedelta(days=i) for i in (0, 2, 4, 9, 11, 30)]
    assert obs.first_consensus_day(D0, 5, 1, days) == D0 + timedelta(days=11)
    assert obs.first_consensus_day(D0, 5, 5, []) == D0


def test_bootstrap_with_one_node_says_how_many_are_missing() -> None:
    doc = obs.render(scenario(1, earliest_eligible=[D0 + timedelta(days=3)]))
    boot = doc["bootstrap"]
    assert boot == {
        "min_nodes": 5,
        "eligible_nodes": 0,
        "nodes_missing": 5,
        "consensus_possible": False,
        "first_consensus_day": None,
        "days_until_first_consensus": None,
    }
    assert doc["nodes"]["members"] == 1


def test_bootstrap_reads_min_nodes_from_the_settings_value() -> None:
    doc = obs.render(scenario(2, min_nodes=2, eligible=2))
    assert doc["bootstrap"]["min_nodes"] == 2 and doc["bootstrap"]["consensus_possible"]
    assert doc["bootstrap"]["days_until_first_consensus"] == 0
    five = [D0 + timedelta(days=i) for i in (0, 1, 2, 3, 6)]
    doc = obs.render(scenario(5, min_nodes=5, eligible=2, earliest_eligible=five))
    assert doc["bootstrap"]["first_consensus_day"] == (D0 + timedelta(days=6)).isoformat()
    assert doc["bootstrap"]["days_until_first_consensus"] == 6
    assert doc["bootstrap"]["nodes_missing"] == 3


def test_settings_min_nodes_is_never_hardcoded() -> None:
    source = (HUB / "hub" / "observatory.py").read_text()
    assert "min_nodes=s.min_nodes" in source
    assert not re.search(r"min_nodes\s*=\s*\d", source)


# --- countries (k = 3) ------------------------------------------------------------------------------


def test_node_countries_need_three_members() -> None:
    doc = obs.render(scenario(1, country_members={"CH": 2, "DE": 3, "FR": 1, "NL": 7}))
    assert doc["nodes"]["countries"] == [{"cc": "DE", "members": 3}, {"cc": "NL", "members": 7}]
    doc = obs.render(scenario(1, country_members={"CH": 1}))
    assert doc["nodes"]["countries"] == []


# --- activity: suppression and precision ------------------------------------------------------------


@pytest.mark.parametrize("nodes", [1, 2])
def test_below_three_nodes_the_series_is_weekly_and_coarse(nodes: int) -> None:
    doc = obs.render(scenario(nodes))
    series = doc["activity"]["series"]
    assert series, "attack figures are shown from day one"
    for entry in series:
        assert entry["precision"] == "coarse"
        assert entry["days"] == 7  # complete ISO weeks only
        for f in obs.SERIES_FIELDS:
            v = entry[f]
            assert v is None or v == obs.round_figure(v, 1)  # one significant figure
    assert series[-1]["sources"] == 1000  # 1234 per day, one significant figure
    starts = [date.fromisoformat(e["start"]) for e in series]
    assert all(s.weekday() == 0 for s in starts)
    # The partial weeks at both ends (LAST is a Tuesday) are left out.
    assert starts[-1] + timedelta(days=6) < LAST
    assert doc["activity"]["window"]["precision"] == "coarse"


def test_a_single_nodes_day_off_is_not_visible() -> None:
    inp = scenario(1)
    gap = LAST - timedelta(days=10)
    inp.days = [r for r in inp.days if r.day != gap]
    doc = obs.render(inp)
    week = gap - timedelta(days=gap.weekday())
    entry = next(e for e in doc["activity"]["series"] if e["start"] == week.isoformat())
    assert entry["days"] == 7 and entry["sources"] == 1000
    assert all(e["sources"] != 0 for e in doc["activity"]["series"])
    assert all(e["days"] == 7 for e in doc["activity"]["series"])


def test_a_week_with_no_report_at_all_is_null_not_zero() -> None:
    inp = scenario(1)
    week = LAST - timedelta(days=LAST.weekday()) - timedelta(days=14)
    inp.days = [r for r in inp.days if not week <= r.day < week + timedelta(days=7)]
    doc = obs.render(inp)
    entry = next(e for e in doc["activity"]["series"] if e["start"] == week.isoformat())
    assert entry["sources"] is None and entry["precision"] == "coarse"


def test_from_three_nodes_full_weeks_are_daily_with_two_figures() -> None:
    doc = obs.render(scenario(3))
    daily = [e for e in doc["activity"]["series"] if e["days"] == 1]
    assert daily and all(e["precision"] == "standard" for e in daily)
    assert daily[-1]["sources"] == 1200 and daily[-1]["login"] == 460
    assert daily[-1]["exploit"] == 0  # 3 rounds to tens, never exact
    assert doc["activity"]["window"]["precision"] == "standard"


def test_one_thin_day_makes_its_whole_week_coarse() -> None:
    inp = scenario(3)
    thin = LAST - timedelta(days=9)
    inp.days = [day_row(r.day, 2) if r.day == thin else r for r in inp.days]
    doc = obs.render(inp)
    week = thin - timedelta(days=thin.weekday())
    entries = [e for e in doc["activity"]["series"] if e["start"] == week.isoformat()]
    assert len(entries) == 1 and entries[0]["precision"] == "coarse" and entries[0]["days"] == 7
    assert not any(
        week <= date.fromisoformat(e["start"]) < week + timedelta(days=7) and e["days"] == 1
        for e in doc["activity"]["series"]
    )


def test_only_final_days_are_published() -> None:
    inp = scenario(3)
    late = [day_row(D0 - timedelta(days=i), 9, sources=99999) for i in range(obs.FINAL_LAG_DAYS)]
    inp.days = inp.days + late
    doc = obs.render(inp)
    assert doc["activity"]["last_day"] == LAST.isoformat()
    for e in doc["activity"]["series"]:
        start = date.fromisoformat(e["start"])
        assert start + timedelta(days=e["days"] - 1) <= LAST
        assert e["sources"] != 99000 and e["sources"] != 100000
    assert doc["outcomes"]["last_day"] == (D0 - timedelta(days=2)).isoformat()
    assert obs.FINAL_LAG_DAYS >= 2 and obs.OUTCOME_LAG_DAYS >= 2  # at least 24 h after the day


def test_series_covers_at_most_ninety_days() -> None:
    doc = obs.render(scenario(3, days=200))
    first = date.fromisoformat(doc["activity"]["series"][0]["start"])
    assert (LAST - first).days < obs.SERIES_DAYS
    assert len(doc["outcomes"]["daily"]) == obs.SERIES_DAYS


def test_no_frozen_day_means_an_empty_series() -> None:
    doc = obs.render(scenario(1, days=0))
    assert doc["activity"]["series"] == []
    window = doc["activity"]["window"]
    assert window["services"] == [] and window["tags"] == [] and window["families"] == []


# --- activity: services, tags and families -------------------------------------------------------


def test_window_shares_are_coarse_below_three_nodes() -> None:
    window = obs.render(scenario(1))["activity"]["window"]
    services = {s["id"]: s["share_pct"] for s in window["services"]}
    assert services == {"ssh": 75, "telnet": 25, "web": 5}  # steps of 5 points
    assert [t["id"] for t in window["tags"]] == ["recon", "mirai"]
    assert all(t["share_pct"] % 5 == 0 for t in window["tags"])
    assert window["families"] == [{"id": "mirai", "share_pct": 75}]


def test_window_shares_are_finer_from_three_nodes() -> None:
    window = obs.render(scenario(3))["activity"]["window"]
    services = {s["id"]: s["share_pct"] for s in window["services"]}
    assert services == {"ssh": 73, "telnet": 24, "web": 3}


def test_items_need_support_and_two_nodes_once_the_network_has_three() -> None:
    inp = scenario(3)
    rare = [ItemRow(LAST, "tag", "cve-2026-109618", obs.ITEM_MIN - 1, 3)]
    solo = [ItemRow(LAST - timedelta(days=i), "tag", "crypto-miner", 500, 1) for i in range(5)]
    inp.items = inp.items + rare + solo
    tags = {t["id"] for t in obs.render(inp)["activity"]["window"]["tags"]}
    assert "cve-2026-109618" not in tags  # too little support
    assert "crypto-miner" not in tags  # only ever one node at a time
    assert {"mirai", "recon"} <= tags


def test_unknown_names_from_the_database_are_never_published() -> None:
    inp = scenario(1)
    inp.items = [
        *inp.items,
        ItemRow(LAST, "service", "192.0.2.5", 5000, 1),
        ItemRow(LAST, "tag", "free text", 5000, 1),
        ItemRow(LAST, "family", "my-own-name", 5000, 1),
    ]
    text_doc = json.dumps(obs.render(inp))
    for bad in ("192.0.2.5", "free text", "my-own-name"):
        assert bad not in text_doc


def test_top_lists_are_capped() -> None:
    inp = scenario(3)
    tags = ["mirai", "recon", "crypto-miner", "malware-drop", "php2shell", "eternalblue"]
    tags += [f"cve-2026-{1000 + i}" for i in range(10)]
    inp.items = [ItemRow(LAST, "tag", t, 500, 3) for t in tags]
    assert len(obs.render(inp)["activity"]["window"]["tags"]) == obs.TOP_TAGS


# --- outcomes -------------------------------------------------------------------------------------


def test_outcomes_are_daily_with_thirty_day_totals() -> None:
    last = D0 - timedelta(days=obs.OUTCOME_LAG_DAYS)
    inp = scenario(
        1,
        outcomes=[
            OutcomeDay(last, confirmed=2, reported=1),
            OutcomeDay(last - timedelta(days=40), confirmed=7),
            OutcomeDay(D0 - timedelta(days=1), confirmed=50),  # too recent: not published
        ],
        reports_sent_30d=1,
        takedown_gaps=[3, 5, 9],
    )
    out = obs.render(inp)["outcomes"]
    assert out["daily"][-1] == {
        "day": last.isoformat(),
        "confirmed": 2,
        "reported": 1,
        "taken_down": 0,
    }
    assert out["confirmed_30d"] == 2 and out["reported_30d"] == 1
    assert sum(d["confirmed"] for d in out["daily"]) == 9
    assert out["reports_sent_30d"] == 1 and out["median_days_to_takedown"] == 5


# --- the document as a whole ---------------------------------------------------------------------


@pytest.mark.parametrize("nodes", [0, 1, 2, 3, 7])
def test_no_forbidden_key_or_identifying_value_anywhere(nodes: int) -> None:
    inp = scenario(
        nodes,
        country_members={"CH": 3, "DE": 1},
        earliest_eligible=[D0] * nodes,
        outcomes=[OutcomeDay(D0 - timedelta(days=3), 1, 1, 1)],
        takedown_gaps=[2],
    )
    doc = obs.render(inp)
    assert_clean(doc)
    assert doc["schema"] == "selfhostr-network-stats/1" and doc["licence"] == "CC0-1.0"
    raw = obs.render_bytes(inp)
    assert json.loads(raw) == doc and raw.endswith(b"\n") and raw.isascii()


def test_the_key_walker_catches_what_it_should() -> None:
    for bad in (
        {"node_id": 1},
        {"x": [{"fingerprint": "3f9a1c07"}]},
        {"pseudonym": "a"},
        {"ip": "x"},
        {"source_ip": "x"},
        {"address": "x"},
        {"ok": "198.51.100.23"},
        {"ok": "2001:db8::1"},
        {"ok": "3f9a1c07"},
    ):
        with pytest.raises(AssertionError):
            assert_clean(bad)


def test_the_document_has_no_time_of_day() -> None:
    raw = obs.render_bytes(scenario(3)).decode()
    assert not re.search(r"T\d\d:\d\d", raw)


# --- publication ----------------------------------------------------------------------------------


def test_publish_is_atomic_and_world_readable(tmp_path: Path) -> None:
    root = tmp_path / "feeds"
    obs.publish(root, b'{"a":1}\n')
    obs.publish(root, b'{"a":2}\n')
    body = (root / "network.json").read_bytes()
    assert body == b'{"a":2}\n'
    assert gzip.decompress((root / "network.json.gz").read_bytes()) == body
    for name in ("network.json", "network.json.gz"):
        assert stat.S_IMODE((root / name).stat().st_mode) == 0o644
    assert sorted(p.name for p in root.iterdir()) == ["network.json", "network.json.gz"]


def test_the_observatory_is_off_by_default() -> None:
    assert Settings.from_env({}).observatory_enabled is False
    assert Settings.from_env({"HUB_OBSERVATORY_ENABLED": "true"}).observatory_enabled
    assert Settings.from_env({"HUB_OBSERVATORY_ENABLED": "true"}).feed_mode == "off"


@pytest.mark.parametrize("name", ["Caddyfile", "Caddyfile.tunnel"])
def test_caddy_allows_one_origin_for_the_observatory(name: str) -> None:
    caddy = (HUB / name).read_text()
    block = re.search(
        r"@observatory path ([^\n]+)\n\s*header @observatory \{(.*?)\n\t*\}", caddy, re.S
    )
    assert block is not None
    assert block.group(1).split() == ["/v1/network.json", "/v1/network.json.gz"]
    assert (
        'Access-Control-Allow-Origin "{$HUB_OBSERVATORY_ORIGIN:https://suckerpot.selfhostr.io}"'
        in block.group(2)
    )
    assert 'Access-Control-Allow-Methods "GET"' in block.group(2)
    # The wildcard stays limited to the feed index and statistics.
    assert "network.json" not in re.search(r"@project path ([^\n]+)", caddy).group(1)  # type: ignore[union-attr]


def test_compose_passes_the_origin_to_caddy() -> None:
    compose = (HUB / "docker-compose.yml").read_text()
    want = "HUB_OBSERVATORY_ORIGIN: ${HUB_OBSERVATORY_ORIGIN:-https://suckerpot.selfhostr.io}"
    assert want in compose


def test_observatory_code_makes_no_outbound_call() -> None:
    source = (HUB / "hub" / "observatory.py").read_text()
    imports = re.findall(r"^\s*(?:import|from)\s+([\w.]+)", source, flags=re.M)
    assert not {"httpx", "requests", "urllib", "aiohttp", "socket"} & set(imports)


# --- database and worker (integration) -------------------------------------------------------------

DAY = TODAY - timedelta(days=obs.FINAL_LAG_DAYS)


async def _rows(env: Env) -> list[Any]:
    async with env.worker() as s:
        return list(
            await s.execute(
                text(
                    "SELECT day, metric, key, total, nodes FROM observatory_daily ORDER BY 1, 2, 3"
                )
            )
        )


@pytest.mark.integration
async def test_published_with_feed_mode_off(env_factory: Any, tmp_path: Path) -> None:
    root = tmp_path / "feeds"
    env: Env = await env_factory(feed_mode="off", observatory_enabled=True, feed_dir=str(root))
    ids = await add_nodes(env.worker, 2)
    await observe(env.worker, ids, "ip", "192.0.2.10", [DAY], services=["ssh"], tags=["mirai"])
    ctx = WorkerContext(settings=env.settings, sessionmaker=env.worker, clock=env.clock)
    first = await run_cycle(ctx)
    assert first.failed == [] and first.steps["feeds"]["state"] == "off"  # type: ignore[index]
    assert first.steps["observatory"]["published"] is True  # type: ignore[index]
    assert not (root / "index.json").exists() and not (root / "stats.json").exists()
    doc = json.loads((root / "network.json").read_text())
    assert doc["schema"] == obs.SCHEMA and doc["generated_day"] == TODAY.isoformat()
    assert doc["nodes"]["members"] == 2 and doc["bootstrap"]["min_nodes"] == 5
    assert doc["activity"]["series"][-1]["precision"] == "coarse"
    assert_clean(doc)
    assert "192.0.2.10" not in (root / "network.json").read_text()
    second = await run_cycle(ctx)
    assert second.steps["observatory"] == {"frozen": 0, "published": False}


@pytest.mark.integration
async def test_nothing_happens_when_disabled(env_factory: Any, tmp_path: Path) -> None:
    root = tmp_path / "feeds"
    env: Env = await env_factory(observatory_enabled=False, feed_dir=str(root))
    ids = await add_nodes(env.worker, 1)
    await observe(env.worker, ids, "ip", "192.0.2.11", [DAY])
    out = await run_cycle(
        WorkerContext(settings=env.settings, sessionmaker=env.worker, clock=env.clock)
    )
    assert "observatory" not in out.steps and not (root / "network.json").exists()
    assert await _rows(env) == []


@pytest.mark.integration
async def test_a_final_day_is_frozen_once(env: Env) -> None:
    ids = await add_nodes(env.worker, 3)
    for i, v in enumerate(("192.0.2.20", "192.0.2.21", "192.0.2.22")):
        await observe(
            env.worker,
            ids[: i + 1],
            "ip",
            v,
            [DAY],
            services=["ssh", "telnet"],
            activity=["login", "command"],
            tags=["mirai"],
        )
    await observe(env.worker, ids[:1], "sha256", "ab" * 32, [DAY], families=["mirai"])
    await observe(env.worker, ids[:2], "url", "cd" * 32, [DAY], tags=[], families=["mirai"])
    # A day that is not final yet is never stored.
    await observe(env.worker, ids, "ip", "192.0.2.30", [TODAY - timedelta(days=1)])
    async with env.worker() as s:
        assert await obs.freeze_days(s, env.settings, TODAY) == env.settings.obs_retention_days - 3
    rows = {(r.day, r.metric, r.key): (r.total, r.nodes) for r in await _rows(env)}
    assert rows[(DAY, "total", "")] == (3, 3)
    assert rows[(DAY, "service", "ssh")] == (3, 3)
    assert rows[(DAY, "activity", "login")] == (3, 3)
    assert rows[(DAY, "tag", "mirai")] == (3, 3)
    assert rows[(DAY, "family", "mirai")] == (1, 1)
    assert rows[(DAY, "kind", "files")] == (1, 1)
    assert rows[(DAY, "kind", "payload_urls")] == (1, 2)
    assert not any(d >= TODAY - timedelta(days=obs.FINAL_LAG_DAYS - 1) for d, _, _ in rows)
    # Late data and a node that leaves change nothing already frozen.
    await observe(env.worker, ids, "ip", "192.0.2.40", [DAY])
    async with env.worker() as s:
        await s.execute(text("DELETE FROM nodes WHERE id = :n"), {"n": ids[2]})
        await s.commit()
        assert await obs.freeze_days(s, env.settings, TODAY) == 0
    after = {(r.day, r.metric, r.key): (r.total, r.nodes) for r in await _rows(env)}
    assert after == rows


@pytest.mark.integration
async def test_load_and_render_from_the_database(env: Env) -> None:
    ids = await add_nodes(env.worker, 3, countries=["CH", "CH", "CH"], show_country=True)
    await observe(env.worker, ids, "ip", "192.0.2.50", [DAY], tags=["recon"])
    async with env.worker() as s:
        await obs.freeze_days(s, env.settings, TODAY)
        inp = await obs.load(s, env.settings, TODAY)
    # add_nodes makes aged nodes with 7 batch days: all three are eligible today.
    assert inp.members == 3 and inp.active_7d == 3 and inp.eligible == 3
    assert inp.earliest_eligible == [TODAY] * 3
    doc = obs.render(inp)
    assert doc["nodes"]["countries"] == [{"cc": "CH", "members": 3}]
    assert doc["activity"]["last_day"] == DAY.isoformat()
    assert_clean(doc)
    assert "192.0.2.50" not in json.dumps(doc)


@pytest.mark.integration
async def test_retention_keeps_observatory_rows_for_400_days(env: Env) -> None:
    from hub import retention

    async with env.worker() as s:
        for d in (TODAY - timedelta(days=401), TODAY - timedelta(days=399)):
            await s.execute(
                text(
                    "INSERT INTO observatory_daily (day, metric, key, total, nodes) "
                    "VALUES (:d, 'total', '', 1, 1)"
                ),
                {"d": d},
            )
        await s.commit()
        res = await retention.run_retention(s, env.settings, env.clock(), TODAY)
    assert res.deleted["observatory_daily"] == 1
    assert len(await _rows(env)) == 1

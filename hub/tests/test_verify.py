"""Link verification core (design M32 sections 6.2, 7.1, 7.2, 7.4): worker job, routes, retention."""

from __future__ import annotations

import random
import uuid
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from suckerpot_netproto import blind

from hub import retention, verify
from hub.config import ConfigError, Settings
from hub.models import Base
from hub.never import Never, load_never
from hub.never_seed import ensure_seed

from .conftest import Env
from .helpers import NodeClient
from .seed import TODAY, add_nodes, observe, shipped_ranges

D1 = TODAY - timedelta(days=1)
URL_A = "http://198.51.100.30/bins/arm7"
URL_B = "http://198.51.100.31/x.sh"
HASH_A = blind.blind("url", URL_A)
HASH_B = blind.blind("url", URL_B)


# ---------------------------------------------------------------- pure unit tests


def test_settings_default_off_and_min_reporters_floor() -> None:
    assert Settings().verify_mode == "off" and not Settings().verify_enabled
    assert Settings.from_env({"HUB_VERIFY_MODE": "review"}).verify_enabled
    for bad in ({"HUB_VERIFY_MODE": "yes"}, {"HUB_VERIFY_MIN_REPORTERS": "1"}):
        with pytest.raises(ConfigError):
            Settings.from_env(bad)
    with pytest.raises(ConfigError):
        Settings.from_env({"HUB_VERIFY_DELAY_MIN_H": "9", "HUB_VERIFY_DELAY_MAX_H": "3"})


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("ftp://198.51.100.1/x", "scheme"),
        ("http://127.0.0.1/x", "private"),
        ("http://100.64.0.1/x", "private"),
        ("http://169.254.0.1/x", "private"),
        ("http://[fd00::1]/x", "private"),
        ("http://198.51.100.1/x", "private"),  # documentation range
        ("http://[2001:db8::1]/x", "private"),
        ("http://localhost.local/x", "host"),
        ("http://intranet/x", "host"),
        ("http://127.1/x", "host"),
        ("http://user:pw@example.org/x", "credentials"),
        ("http://example.org/" + "a" * 1100, "length"),
    ],
)
def test_basic_refusal_codes(url: str, code: str) -> None:
    assert verify.basic_refusal(url, Never(), allow_documentation=False) == code


def test_basic_refusal_accepts_public_and_honours_never_and_overlay() -> None:
    never = Never.from_rows([("bad.example.org", "domain"), ("203.0.113.0/24", "ip")])
    assert (
        verify.basic_refusal("http://files.example.net/x", Never(), allow_documentation=False)
        is None
    )
    assert (
        verify.basic_refusal("http://a.bad.example.org/x", never, allow_documentation=False)
        == "never_list"
    )
    assert verify.basic_refusal("http://198.51.100.1/x", Never(), allow_documentation=True) is None
    assert (
        verify.basic_refusal("http://203.0.113.5/x", never, allow_documentation=True)
        == "never_list"
    )


def test_task_ids_match_the_wire_pattern() -> None:
    import re

    assert re.fullmatch(r"v_[0-9a-f]{12}", verify.new_task_id())


def test_only_the_lease_links_a_task_to_a_node() -> None:
    cols = Base.metadata.tables["verify_tasks"].columns
    refs = {c.name for c in cols if any(fk.column.table.name == "nodes" for fk in c.foreign_keys)}
    assert refs == {"lease_node"}
    assert not any("ip" == c.name or c.name.endswith("_ip") for c in cols)


# ---------------------------------------------------------------- helpers


async def eligible(env: Env, clients: list[NodeClient]) -> list[uuid.UUID]:
    """Make enrolled nodes count (age, active days, as ``add_nodes`` does for seeded ones)."""
    ids = [uuid.UUID(c.node_id or "") for c in clients]
    async with env.worker() as s:
        for i, node in enumerate(ids):
            await s.execute(
                text("UPDATE nodes SET enrolled_day = :e, reputation = 0.8 WHERE id = :n"),
                {"e": TODAY - timedelta(days=20 + 7 * i), "n": node},
            )
            for d in range(1, 8):
                await s.execute(
                    text(
                        "INSERT INTO batches (node_id, day, batch_id, items) VALUES (:n, :d, :b, 1)"
                    ),
                    {"n": node, "d": TODAY - timedelta(days=d), "b": uuid.uuid4().bytes},
                )
        await s.commit()
    return ids


async def grant(env: Env, node: NodeClient) -> None:
    async with env.worker() as s:
        await s.execute(
            text("INSERT INTO node_roles (node_id, role, granted_day) VALUES (:n, 'verifier', :d)"),
            {"n": uuid.UUID(node.node_id or ""), "d": TODAY},
        )
        await s.commit()


async def run_verify(env: Env, seed: int = 1) -> verify.VerifyResult:
    async with env.worker() as s:
        await ensure_seed(s)
        rng = random.Random(seed)  # noqa: S311 - a fixed test seed
        return await verify.run(s, env.settings, env.clock(), never=await load_never(s), rng=rng)


async def task(env: Env, url_b: str) -> Any:
    async with env.worker() as s:
        return (
            (await s.execute(text("SELECT * FROM verify_tasks WHERE url_b = :b"), {"b": url_b}))
            .mappings()
            .first()
        )


async def reporters(env: Env, n: int = 2, urls: tuple[str, ...] = (HASH_A,)) -> list[NodeClient]:
    clients = await env.enrolled(n)
    ids = await eligible(env, clients)
    for h in urls:
        await observe(env.worker, ids, "url", h, [D1])
    await shipped_ranges(env.worker)
    return clients


def reveal_body(url: str) -> dict[str, Any]:
    return {
        "protocol": "spn/1",
        "items": [{"kind": "url", "value": url, "value_b": blind.blind("url", url)}],
    }


async def reveal(node: NodeClient, url: str) -> Any:
    return await node.call("POST", "/v1/reveals", reveal_body(url))


async def queued_task(env: Env, url: str = URL_A) -> tuple[list[NodeClient], NodeClient]:
    """Two reporters reveal ``url``; a verifier exists; the worker queued the task (auto mode)."""
    rep = await reporters(env, urls=(blind.blind("url", url),))
    verifier = (await env.enrolled(1))[0]
    await grant(env, verifier)
    await run_verify(env)
    assert (await reveal(rep[0], url)).json["accepted"] == 1
    await run_verify(env)
    env.clock.advance(hours=31)
    return rep, verifier


# ---------------------------------------------------------------- off by default


@pytest.mark.integration
async def test_off_creates_nothing_and_answers_empty(env: Env) -> None:
    rep = await reporters(env)
    verifier = (await env.enrolled(1))[0]
    await grant(env, verifier)
    assert (await run_verify(env)).created == 0
    assert await task(env, HASH_A) is None
    assert (await rep[0].call("GET", "/v1/verify/reveals")).json == {"items": []}
    assert (await verifier.call("GET", "/v1/verify/tasks")).json == {"tasks": []}


# ---------------------------------------------------------------- creation


@pytest.mark.integration
async def test_two_eligible_reporters_make_a_task_one_or_young_ones_do_not(
    env_factory: Any,
) -> None:
    env: Env = await env_factory(verify_mode="review")
    ids = await add_nodes(env.worker, 3)
    young = await env.enrolled(2)  # enrolled today: not eligible
    await observe(env.worker, ids[:2], "url", HASH_A, [D1])
    await observe(env.worker, ids[2:], "url", HASH_B, [D1])  # one reporter
    await observe(env.worker, [uuid.UUID(c.node_id or "") for c in young], "url", "cc" * 32, [D1])
    res = await run_verify(env)
    assert res.created == 1
    row = await task(env, HASH_A)
    assert row["state"] == "waiting_reveal" and row["url"] is None
    assert (row["reporters"], row["reporter_cohorts"]) == (2, 2)
    assert row["id"].startswith("v_") and row["last_report_day"] == D1
    assert await task(env, HASH_B) is None and await task(env, "cc" * 32) is None
    await run_verify(env)  # idempotent
    async with env.worker() as s:
        assert (await s.execute(text("SELECT count(*) FROM verify_tasks"))).scalar_one() == 1


@pytest.mark.integration
async def test_links_already_submitted_to_abusech_get_no_task(env_factory: Any) -> None:
    env: Env = await env_factory(verify_mode="review")
    ids = await add_nodes(env.worker, 2)
    await observe(env.worker, ids, "url", HASH_A, [D1])
    async with env.worker() as s:
        await s.execute(
            text(
                "INSERT INTO targets (id, kind, value, value_b, state) "
                "VALUES ('t_u1', 'url', :v, :b, 'confirmed')"
            ),
            {"v": URL_A, "b": HASH_A},
        )
        await s.execute(
            text(
                "INSERT INTO abusech_submissions (kind, target_id, indicator, state, created_day) "
                "VALUES ('urlhaus', 't_u1', :v, 'sent', :d)"
            ),
            {"v": URL_A, "d": TODAY},
        )
        await s.commit()
    assert (await run_verify(env)).created == 0


# ---------------------------------------------------------------- reveals


@pytest.mark.integration
async def test_reveal_goes_to_the_task_not_to_the_target(env_factory: Any) -> None:
    env: Env = await env_factory(verify_mode="review")
    rep = await reporters(env)
    async with env.worker() as s:  # a candidate target that stays blinded (D10)
        await s.execute(
            text(
                "INSERT INTO targets (id, kind, value_b, state) VALUES ('t_c', 'url', :b, 'candidate')"
            ),
            {"b": HASH_A},
        )
        await s.commit()
    await run_verify(env)
    listed = await rep[0].call("GET", "/v1/verify/reveals")
    assert listed.status == 200 and listed.signature_ok
    assert listed.json == {"items": [{"kind": "url", "value_b": HASH_A}]}
    assert (await reveal(rep[0], URL_A)).json == {"accepted": 1, "rejected": 0}
    row = await task(env, HASH_A)
    assert row["url"] == URL_A and row["site"] == "198.51.100.30" and row["revealed_day"] == TODAY
    async with env.worker() as s:
        assert (
            await s.execute(text("SELECT value FROM targets WHERE id = 't_c'"))
        ).scalar() is None
    # Once revealed, the link is no longer asked for.
    assert (await rep[1].call("GET", "/v1/verify/reveals")).json == {"items": []}


@pytest.mark.integration
async def test_only_the_reporter_can_reveal_and_the_value_must_match(env_factory: Any) -> None:
    env: Env = await env_factory(verify_mode="review")
    rep = await reporters(env)
    stranger = (await env.enrolled(1))[0]
    await run_verify(env)
    assert (await stranger.call("GET", "/v1/verify/reveals")).json == {"items": []}
    assert (await reveal(stranger, URL_A)).json == {"accepted": 0, "rejected": 1}
    wrong = reveal_body(URL_B)
    wrong["items"][0]["value_b"] = HASH_A
    assert (await rep[0].call("POST", "/v1/reveals", wrong)).json == {"accepted": 0, "rejected": 1}
    assert (await task(env, HASH_A))["url"] is None


@pytest.mark.integration
async def test_reveal_is_ignored_while_verification_is_off(env: Env) -> None:
    rep = await reporters(env)
    async with env.worker() as s:  # a task left over from an earlier mode
        await s.execute(
            text(
                "INSERT INTO verify_tasks (id, url_b, state, reporters, reporter_cohorts, "
                "last_report_day, created_day) VALUES ('v_000000000001', :b, 'waiting_reveal', "
                "2, 2, :d, :d)"
            ),
            {"b": HASH_A, "d": D1},
        )
        await s.commit()
    assert (await reveal(rep[0], URL_A)).json == {"accepted": 0, "rejected": 1}
    assert (await task(env, HASH_A))["url"] is None


@pytest.mark.integration
async def test_unsafe_revealed_links_refuse_the_task_without_storing_them(
    env_factory: Any,
) -> None:
    env: Env = await env_factory(verify_mode="review", allow_documentation=False)
    internal = "http://100.64.0.9/x.sh"
    never_url = "http://dl.github.com/x.sh"
    rep = await reporters(env, urls=(blind.blind("url", internal), blind.blind("url", never_url)))
    await run_verify(env)
    for url, code in ((internal, "private"), (never_url, "never_list")):
        res = await reveal(rep[0], url)
        assert res.json == {"accepted": 0, "rejected": 1}
        row = await task(env, blind.blind("url", url))
        assert (row["state"], row["refusal"], row["url"]) == ("refused", code, None)
        assert row["ended_day"] == TODAY


# ---------------------------------------------------------------- admission, caps, exclusions


async def two_reporters_for(env: Env, urls: list[str]) -> list[NodeClient]:
    return await reporters(env, urls=tuple(blind.blind("url", u) for u in urls))


@pytest.mark.integration
async def test_review_mode_holds_for_the_operator_auto_mode_delays(env_factory: Any) -> None:
    review: Env = await env_factory(verify_mode="review")
    rep = await two_reporters_for(review, [URL_A])
    await run_verify(review)
    await reveal(rep[0], URL_A)
    res = await run_verify(review)
    row = await task(review, HASH_A)
    assert res.admitted == 1 and row["state"] == "pending_review" and row["release_at"] is None
    verifier = (await review.enrolled(1))[0]
    await grant(review, verifier)
    assert (await verifier.call("GET", "/v1/verify/tasks")).json == {"tasks": []}


@pytest.mark.integration
async def test_auto_mode_releases_after_six_to_thirty_hours(env_factory: Any) -> None:
    env: Env = await env_factory(verify_mode="auto")
    rep = await two_reporters_for(env, [URL_A])
    await run_verify(env)
    await reveal(rep[0], URL_A)
    await run_verify(env, seed=3)
    row = await task(env, HASH_A)
    delay = row["release_at"] - env.clock()
    assert row["state"] == "queued"
    assert timedelta(hours=6) <= delay <= timedelta(hours=30)
    verifier = (await env.enrolled(1))[0]
    await grant(env, verifier)
    assert (await verifier.call("GET", "/v1/verify/tasks")).json == {"tasks": []}  # not yet
    env.clock.advance(hours=31)
    got = await verifier.call("GET", "/v1/verify/tasks")
    assert got.status == 200 and got.signature_ok
    assert [t["url"] for t in got.json["tasks"]] == [URL_A]


async def reveal_many(env: Env, urls: list[str]) -> Any:
    rep = await two_reporters_for(env, urls)
    await run_verify(env)
    body = {
        "protocol": "spn/1",
        "items": [{"kind": "url", "value": u, "value_b": blind.blind("url", u)} for u in urls],
    }
    assert (await rep[0].call("POST", "/v1/reveals", body)).json["accepted"] == len(urls)
    return await run_verify(env)


@pytest.mark.integration
async def test_per_host_cap(env_factory: Any) -> None:
    env: Env = await env_factory(verify_mode="review", verify_host_daily_cap=2)
    urls = [f"http://198.51.100.40/f{i}" for i in range(3)] + ["http://198.51.100.41/f"]
    res = await reveal_many(env, urls)
    assert res.refused == {"host_cap": 1} and res.admitted == 3
    async with env.worker() as s:
        rows = (await s.execute(text("SELECT site, state FROM verify_tasks"))).all()
    assert sorted(r.state for r in rows if r.site == "198.51.100.40") == [
        "pending_review",
        "pending_review",
        "refused",
    ]


@pytest.mark.integration
async def test_network_daily_cap_counts_across_cycles(env_factory: Any) -> None:
    env: Env = await env_factory(verify_mode="review", verify_daily_cap=2)
    urls = [f"http://198.51.100.{50 + i}/f" for i in range(3)]
    res = await reveal_many(env, urls)
    assert res.refused == {"daily_cap": 1} and res.admitted == 2
    # Tomorrow the cap is fresh again for new links.
    env.clock.advance(days=1)
    more = "http://198.51.100.60/f"
    rep = await reporters(env, urls=(blind.blind("url", more),))
    await run_verify(env)
    assert (await reveal(rep[0], more)).json["accepted"] == 1
    assert (await run_verify(env)).admitted == 1


@pytest.mark.integration
async def test_exclusions_shared_hosts_and_stale_ranges(env_factory: Any) -> None:
    env: Env = await env_factory(verify_mode="review")
    allowed = "http://203.0.113.80/x"
    shared = "http://raw.githubusercontent.com/o/r/x.sh"
    rep = await two_reporters_for(env, [allowed, shared, URL_A])
    async with env.worker() as s:
        await s.execute(
            text(
                "INSERT INTO feed_allow (value, kind, reason, added_day, source) "
                "VALUES ('203.0.113.80', 'ip', 'policy', :d, 'admin')"
            ),
            {"d": TODAY},
        )
        await s.commit()
    await run_verify(env)
    for u in (allowed, shared, URL_A):
        await reveal(rep[0], u)
    await run_verify(env)
    assert (await task(env, blind.blind("url", allowed)))["refusal"] == "excluded"
    assert (await task(env, blind.blind("url", shared)))["refusal"] == "never_list"
    assert (await task(env, HASH_A))["state"] == "pending_review"


@pytest.mark.integration
async def test_stale_ranges_make_an_address_link_wait_not_fail(env_factory: Any) -> None:
    env2: Env = await env_factory(verify_mode="review")
    rep2 = await reporters(env2)
    async with env2.worker() as s:
        await s.execute(text("DELETE FROM feed_auto_ranges"))
        await s.commit()
    await run_verify(env2)
    await reveal(rep2[0], URL_A)
    res = await run_verify(env2)
    assert res.waiting == 1 and (await task(env2, HASH_A))["state"] == "waiting_reveal"


# ---------------------------------------------------------------- leases and results


@pytest.mark.integration
async def test_tasks_and_results_need_the_verifier_role(env_factory: Any) -> None:
    env: Env = await env_factory(verify_mode="auto")
    member = (await env.enrolled(1))[0]
    got = await member.call("GET", "/v1/verify/tasks")
    assert (got.status, got.error, got.signature_ok) == (403, "not_verifier", True)
    body = {"protocol": "spn/1", "items": [{"id": "v_000000000001", "outcome": "timeout"}]}
    res = await member.call("POST", "/v1/verify/results", body)
    assert (res.status, res.error) == (403, "not_verifier")
    assert (await member.call("GET", "/v1/verify/reveals")).status == 200
    assert (await member.call("GET", "/v1/verify/tasks?limit=0")).error in {
        "invalid_payload",
        "not_verifier",
    }


@pytest.mark.integration
async def test_lease_result_and_attestation_flow(env_factory: Any) -> None:
    env: Env = await env_factory(verify_mode="auto")
    _, verifier = await queued_task(env)
    other = (await env.enrolled(1))[0]
    await grant(env, other)
    got = await verifier.call("GET", "/v1/verify/tasks?limit=5")
    (leased,) = got.json["tasks"]
    row = await task(env, HASH_A)
    assert row["state"] == "leased" and str(row["lease_node"]) == verifier.node_id
    # A retried call returns the same live lease; another verifier gets nothing.
    again = await verifier.call("GET", "/v1/verify/tasks")
    assert [t["id"] for t in again.json["tasks"]] == [leased["id"]]
    assert (await other.call("GET", "/v1/verify/tasks")).json == {"tasks": []}
    done = {
        "protocol": "spn/1",
        "items": [
            {
                "id": leased["id"],
                "outcome": "fetched",
                "sha256": "ab" * 32,
                "size": 4096,
                "file_type": "elf-arm",
                "family": "mirai",
            },
            {"id": "v_ffffffffffff", "outcome": "timeout"},
        ],
    }
    assert (await other.call("POST", "/v1/verify/results", done)).json == {
        "accepted": 0,
        "rejected": 2,
    }
    res = await verifier.call("POST", "/v1/verify/results", done)
    assert res.json == {"accepted": 1, "rejected": 1}
    row = await task(env, HASH_A)
    assert (row["state"], row["lease_node"], row["lease_until"]) == ("attested", None, None)
    assert row["ended_day"] == env.clock().date()
    async with env.worker() as s:
        att = (await s.execute(text("SELECT * FROM verify_attestations"))).mappings().one()
    assert att["malware_like"] is True and att["family"] == "mirai" and att["size"] == 4096
    # One result per task and node: the second answer is refused.
    assert (await verifier.call("POST", "/v1/verify/results", done)).json["accepted"] == 0


@pytest.mark.integration
async def test_a_page_is_attested_but_not_malware_like(env_factory: Any) -> None:
    env: Env = await env_factory(verify_mode="auto")
    _, verifier = await queued_task(env)
    (leased,) = (await verifier.call("GET", "/v1/verify/tasks")).json["tasks"]
    item = {
        "id": leased["id"],
        "outcome": "fetched",
        "sha256": "cd" * 32,
        "size": 90,
        "file_type": "other",
        "family": None,
    }
    await verifier.call("POST", "/v1/verify/results", {"protocol": "spn/1", "items": [item]})
    async with env.worker() as s:
        like = (await s.execute(text("SELECT malware_like FROM verify_attestations"))).scalar_one()
    assert like is False


@pytest.mark.integration
async def test_retriable_outcomes_requeue_once_then_fail(env_factory: Any) -> None:
    env: Env = await env_factory(verify_mode="auto")
    _, first = await queued_task(env)
    second = (await env.enrolled(1))[0]
    await grant(env, second)
    (t1,) = (await first.call("GET", "/v1/verify/tasks")).json["tasks"]
    miss: dict[str, Any] = {
        "protocol": "spn/1",
        "items": [{"id": t1["id"], "outcome": "unreachable"}],
    }
    assert (await first.call("POST", "/v1/verify/results", miss)).json["accepted"] == 1
    row = await task(env, HASH_A)
    assert (row["state"], row["attempts"], row["lease_node"]) == ("queued", 1, None)
    # The node that already answered is not handed the task again; another verifier is.
    assert (await first.call("GET", "/v1/verify/tasks")).json == {"tasks": []}
    (t2,) = (await second.call("GET", "/v1/verify/tasks")).json["tasks"]
    miss["items"][0]["outcome"] = "timeout"
    assert (await second.call("POST", "/v1/verify/results", miss)).json["accepted"] == 1
    row = await task(env, HASH_A)
    assert (row["state"], row["attempts"], row["ended_day"]) == ("failed", 2, env.clock().date())
    assert t1["id"] == t2["id"]


@pytest.mark.integration
async def test_expired_leases_return_then_fail(env_factory: Any) -> None:
    env: Env = await env_factory(verify_mode="auto")
    _, verifier = await queued_task(env)
    await verifier.call("GET", "/v1/verify/tasks")
    env.clock.advance(hours=7)
    res = await run_verify(env)
    row = await task(env, HASH_A)
    assert res.leases_returned == 1 and (row["state"], row["attempts"]) == ("queued", 1)
    assert row["lease_node"] is None
    await verifier.call("GET", "/v1/verify/tasks")  # leased again (same node, no answer yet)
    env.clock.advance(hours=7)
    res = await run_verify(env)
    row = await task(env, HASH_A)
    assert res.leases_failed == 1 and (row["state"], row["attempts"]) == ("failed", 2)


# ---------------------------------------------------------------- expiry, own fetches, counters


@pytest.mark.integration
async def test_stale_tasks_expire(env_factory: Any) -> None:
    env: Env = await env_factory(verify_mode="review")
    await reporters(env)
    await run_verify(env)
    assert (await task(env, HASH_A))["state"] == "waiting_reveal"
    env.clock.advance(days=5)  # the sightings are now older than three days
    res = await run_verify(env)
    row = await task(env, HASH_A)
    assert res.expired == 1 and row["state"] == "expired" and row["ended_day"] == env.clock().date()


@pytest.mark.integration
async def test_a_verifiers_own_malware_fetch_attests_without_a_lease(env_factory: Any) -> None:
    env: Env = await env_factory(verify_mode="review")
    ids = await add_nodes(env.worker, 2)
    await observe(env.worker, ids[1:], "url", HASH_A, [D1])
    await observe(env.worker, ids[:1], "url", HASH_A, [D1], fetched=True, file_type="elf-arm")
    await run_verify(env)
    assert (await task(env, HASH_A))["state"] == "waiting_reveal"  # not a verifier yet
    async with env.worker() as s:
        await s.execute(
            text("INSERT INTO node_roles (node_id, role, granted_day) VALUES (:n, 'verifier', :d)"),
            {"n": ids[0], "d": TODAY},
        )
        await s.commit()
    res = await run_verify(env)
    row = await task(env, HASH_A)
    assert res.self_attested == 1 and row["state"] == "attested" and row["lease_node"] is None
    async with env.worker() as s:
        att = (await s.execute(text("SELECT node_id, malware_like FROM verify_attestations"))).one()
    assert att.node_id == ids[0] and att.malware_like is True


@pytest.mark.integration
async def test_a_reveal_after_an_own_fetch_still_lands_on_the_task(env_factory: Any) -> None:
    env: Env = await env_factory(verify_mode="review")
    rep = await env.enrolled(2)
    ids = await eligible(env, rep)
    await observe(env.worker, ids[1:], "url", HASH_A, [D1])
    await observe(env.worker, ids[:1], "url", HASH_A, [D1], fetched=True, file_type="elf-arm")
    await shipped_ranges(env.worker)
    async with env.worker() as s:
        await s.execute(
            text("INSERT INTO node_roles (node_id, role, granted_day) VALUES (:n, 'verifier', :d)"),
            {"n": ids[0], "d": TODAY},
        )
        await s.commit()
    await run_verify(env)
    assert (await task(env, HASH_A))["state"] == "attested"
    assert (await reveal(rep[1], URL_A)).json["accepted"] == 1
    row = await task(env, HASH_A)
    assert row["state"] == "attested" and row["url"] == URL_A


@pytest.mark.integration
async def test_daily_counters(env_factory: Any) -> None:
    env: Env = await env_factory(verify_mode="review")
    rep = await reporters(env)
    await run_verify(env)
    await reveal(rep[0], URL_A)
    await run_verify(env)
    await run_verify(env)  # recount, not accumulate
    async with env.worker() as s:
        row = (
            (
                await s.execute(
                    text("SELECT * FROM verify_daily WHERE day = :d"), {"d": env.clock().date()}
                )
            )
            .mappings()
            .one()
        )
    assert (row["created"], row["revealed"], row["queued"], row["refused"]) == (1, 1, 1, 0)


# ---------------------------------------------------------------- retention, roles, privacy


@pytest.mark.integration
async def test_retention_deletes_clear_links_with_their_task(env_factory: Any) -> None:
    env: Env = await env_factory(verify_mode="auto")
    _, verifier = await queued_task(env)
    (leased,) = (await verifier.call("GET", "/v1/verify/tasks")).json["tasks"]
    item = {
        "id": leased["id"],
        "outcome": "fetched",
        "sha256": "ab" * 32,
        "size": 9,
        "file_type": "elf-arm",
        "family": None,
    }
    await verifier.call("POST", "/v1/verify/results", {"protocol": "spn/1", "items": [item]})
    async with env.worker() as s:
        early = await retention.run_retention(s, env.settings, env.clock(), env.clock().date())
    assert early.deleted["verify_tasks"] == 0
    env.clock.advance(days=15)
    async with env.worker() as s:
        res = await retention.run_retention(s, env.settings, env.clock(), env.clock().date())
    assert res.deleted["verify_tasks"] == 1
    async with env.worker() as s:
        for table in ("verify_tasks", "verify_attestations"):
            assert (await s.execute(text(f"SELECT count(*) FROM {table}"))).scalar_one() == 0


@pytest.mark.integration
async def test_deleting_a_node_clears_its_lease_and_keeps_the_task(env_factory: Any) -> None:
    env: Env = await env_factory(verify_mode="auto")
    _, verifier = await queued_task(env)
    await verifier.call("GET", "/v1/verify/tasks")
    async with env.worker() as s:
        await s.execute(
            text("DELETE FROM nodes WHERE id = :n"), {"n": uuid.UUID(verifier.node_id or "")}
        )
        await s.commit()
    assert (await task(env, HASH_A))["lease_node"] is None


@pytest.mark.integration
async def test_api_role_cannot_create_tasks_or_grant_roles(env: Env) -> None:
    rep = await env.enrolled(1)
    node = uuid.UUID(rep[0].node_id or "")
    statements = (
        "INSERT INTO verify_tasks (id, url_b, state, reporters, reporter_cohorts, "
        "last_report_day, created_day) VALUES ('v_000000000009', 'x', 'queued', 2, 2, now(), now())",
        f"INSERT INTO node_roles (node_id, role, granted_day) VALUES ('{node}', 'verifier', now())",
        "DELETE FROM verify_tasks",
        "UPDATE verify_tasks SET url_b = 'y'",
        "INSERT INTO verify_daily (day) VALUES (now())",
    )
    for sql in statements:
        async with env.ctx.sessionmaker() as s:
            with pytest.raises(DBAPIError):
                await s.execute(text(sql))

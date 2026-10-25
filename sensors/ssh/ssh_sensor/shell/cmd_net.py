"""Download tools. They NEVER fetch anything: they record a ``download_attempt`` and print
believable output, then drop a tiny stub file into the fake filesystem."""

from __future__ import annotations

import posixpath
import re
from urllib.parse import urlsplit

from suckerpot_common import EventType

from ssh_sensor.shell.baseimage import ELF_STUB
from ssh_sensor.shell.core import CmdIO, PendingEvent, parse_flags
from ssh_sensor.shell.fs import FSError
from ssh_sensor.shell.interp import Shell

MAX_URLS = 8
_SCRIPT_STUB = b"#!/bin/sh\nexit 0\n"
_IP_ECHO_HOSTS = (
    "ifconfig.me",
    "icanhazip.com",
    "ipinfo.io",
    "api.ipify.org",
    "checkip.amazonaws.com",
)


def _normalize_url(raw: str) -> str:
    raw = raw.strip()[:2048]
    return raw if "://" in raw else "http://" + raw


def _record(sh: Shell, url: str, tool: str, io: CmdIO) -> None:
    sh.pending.append(
        PendingEvent(EventType.download_attempt, {"url": url, "tool": tool, "command": io.cmdline})
    )


def _drop(sh: Shell, io: CmdIO, path: str, url: str) -> int:
    """Create the fake downloaded file. Returns its size."""
    name = posixpath.basename(urlsplit(url).path)
    script = name.endswith((".sh", ".py", ".pl"))
    data = _SCRIPT_STUB if script else ELF_STUB
    if not sh.fs.may_write(path, sh.user.name, sh.user.home):
        raise FSError("Permission denied")
    sh.fs.write(path, data, append=False, owner=sh.user.name, tag="script" if script else "elf")
    return len(data)


def _local_name(sh: Shell, url: str, directory: str, default: str = "index.html") -> str:
    name = posixpath.basename(urlsplit(url).path) or default
    name = re.sub(r"[^A-Za-z0-9._@+-]", "_", name)[:100] or default
    path = posixpath.join(directory, name)
    n = 0
    while sh.fs.exists(path):
        n += 1
        path = posixpath.join(directory, f"{name}.{n}")
    return path


def _stamp(sh: Shell) -> str:
    import time

    t = time.gmtime(sh.now())
    return (
        f"{t.tm_year}-{t.tm_mon:02d}-{t.tm_mday:02d} {t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}"
    )


def _wait(sh: Shell, seconds: float) -> None:
    if sh.cfg.command_delay:
        sh.delay += seconds


def cmd_wget(sh: Shell, io: CmdIO) -> int:
    flags, values, operands = parse_flags(io.args, "OPTtUoeiw")
    urls = [_normalize_url(o) for o in operands][:MAX_URLS]
    if not urls:
        io.error(
            "wget: missing URL\nUsage: wget [OPTION]... [URL]...\n\nTry `wget --help' for more options.\n"
        )
        return 1
    quiet = "q" in flags
    out_name = values.get("O")
    directory = sh.abspath(values["P"]) if "P" in values else sh.cwd
    status = 0
    for url in urls:
        _record(sh, url, "wget", io)
        parts = urlsplit(url)
        host = parts.hostname or "localhost"
        port = parts.port or (443 if parts.scheme == "https" else 80)
        try:
            if out_name == "-":
                size = len(_SCRIPT_STUB)
                dest_shown = "STDOUT"
            else:
                dest = sh.abspath(out_name) if out_name else _local_name(sh, url, directory)
                size = _drop(sh, io, dest, url)
                dest_shown = posixpath.basename(dest)
        except FSError as exc:
            io.error(
                f"{dest_shown if out_name else posixpath.basename(urlsplit(url).path) or 'index.html'}: {exc}\n"
            )
            status = 1
            continue
        ip = sh.profile.resolve(host)
        if not quiet:
            io.error(
                f"--{_stamp(sh)}--  {url}\n"
                f"Resolving {host} ({host})... {ip}\n"
                f"Connecting to {host} ({host})|{ip}|:{port}... connected.\n"
                f"HTTP request sent, awaiting response... 200 OK\n"
                f"Length: {size} ({size}) [application/octet-stream]\n"
                f"Saving to: ‘{dest_shown}’\n\n"
                f"{dest_shown:<24} 100%[===================>] {size:>5}  --.-KB/s    in 0s\n\n"
                f"{_stamp(sh)} (1.2 MB/s) - ‘{dest_shown}’ saved [{size}/{size}]\n\n"
            )
        _wait(sh, 1.0)
    return status


def cmd_curl(sh: Shell, io: CmdIO) -> int:
    flags, values, operands = parse_flags(io.args, "oHdXAmubeTx")
    urls = [_normalize_url(o) for o in operands if "." in o or "://" in o or "/" in o][:MAX_URLS]
    if not urls:
        io.error("curl: try 'curl --help' or 'curl --manual' for more information\n")
        return 2
    status = 0
    for url in urls:
        _record(sh, url, "curl", io)
        host = urlsplit(url).hostname or ""
        saves = "o" in values or "O" in flags or "remote-name" in flags
        if saves:
            try:
                dest = sh.abspath(values["o"]) if "o" in values else _local_name(sh, url, sh.cwd)
                size = _drop(sh, io, dest, url)
            except FSError as exc:
                io.error(f"curl: (23) Failure writing output to destination: {exc}\n")
                status = 23
                continue
            if "s" not in flags and "silent" not in flags:
                io.error(
                    "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
                    "                                 Dload  Upload   Total   Spent    Left  Speed\n"
                    f"100 {size:>5}  100 {size:>5}    0     0  {size * 7:>6}      0 --:--:-- --:--:-- --:--:-- {size * 7:>6}\n"
                )
        elif host in _IP_ECHO_HOSTS:
            io.write(sh.profile.public_ip + "\n")
        _wait(sh, 1.0)
    return status


def cmd_tftp(sh: Shell, io: CmdIO) -> int:
    flags, values, operands = parse_flags(io.args, "lrc")
    host = ""
    remote = values.get("r", "")
    if "c" in values and operands:  # tftp host -c get file
        host = operands[0] if values["c"] == "get" and len(operands) > 1 else operands[0]
        remote = remote or (operands[-1] if len(operands) > 1 else "")
        if values["c"] != "get":
            remote = operands[0]
    elif operands:
        host = operands[-1]
    elif io.args:
        host = io.args[0]
    if not host:
        io.error("usage: tftp [-h] [-g|-p] [-l FILE] [-r FILE] HOST [PORT]\n")
        return 1
    remote = remote or "file"
    url = f"tftp://{host}/{remote.lstrip('/')}"
    _record(sh, url, "tftp", io)
    local = values.get("l") or posixpath.basename(remote)
    try:
        _drop(sh, io, sh.abspath(local), url)
    except FSError as exc:
        io.error(f"tftp: can't open '{local}': {exc}\n")
        return 1
    _wait(sh, 1.0)
    return 0


def cmd_ftpget(sh: Shell, io: CmdIO) -> int:
    _, values, operands = parse_flags(io.args, "upPv")
    if len(operands) < 2:
        io.error("ftpget: short read\n")
        return 1
    host, local = operands[0], operands[1]
    remote = operands[2] if len(operands) > 2 else local
    url = f"ftp://{host}/{remote.lstrip('/')}"
    _record(sh, url, "ftpget", io)
    try:
        _drop(sh, io, sh.abspath(local), url)
    except FSError as exc:
        io.error(f"ftpget: can't open '{local}': {exc}\n")
        return 1
    _wait(sh, 1.0)
    return 0


def _is_remote_spec(arg: str) -> bool:
    """``[user@]host:path``: a colon before any slash or whitespace. Linear scan, no regex."""
    head, colon, _ = arg.partition(":")
    return bool(
        colon
        and head
        and not arg.startswith("-")
        and "/" not in head
        and not any(c.isspace() for c in head)
    )


def cmd_scp(sh: Shell, io: CmdIO) -> int:
    _, _, operands = parse_flags(io.args, "PiloFJS")
    remote = next((o for o in operands if _is_remote_spec(o)), "")
    if not remote:
        io.error(
            "usage: scp [-346ABCOpqRrsTvx] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n"
        )
        return 1
    host, _, path = remote.partition(":")
    from_remote = operands.index(remote) < len(operands) - 1
    if from_remote:
        _record(sh, f"scp://{host}/{path.lstrip('/')}", "scp", io)
    hostname = host.rpartition("@")[2]
    _wait(sh, 2.0)
    io.error(
        f"ssh: connect to host {hostname} port 22: Connection timed out\nscp: Connection closed\n"
    )
    return 255


def cmd_busybox(sh: Shell, io: CmdIO) -> int:
    from ssh_sensor.shell.commands import COMMANDS

    if not io.args:
        io.write(
            "BusyBox v1.36.1 (Ubuntu 1:1.36.1-6ubuntu3.1) multi-call binary.\n"
            "BusyBox is copyrighted by many authors between 1998-2015.\n"
            "Licensed under GPLv2. See source distribution for detailed\ncopyright notices.\n\n"
            "Usage: busybox [function [arguments]...]\n"
            "   or: busybox --list[-full]\n"
            "   or: function [arguments]...\n"
        )
        return 0
    applet = io.args[0]
    if applet in COMMANDS and applet != "busybox":
        return sh.run_argv(io.args, io)
    io.error(f"{applet}: applet not found\n")
    return 127


def cmd_sh(sh: Shell, io: CmdIO) -> int:
    flags, values, operands = parse_flags(io.args, "c")
    if "c" in values:
        text, status = sh.run_nested(values["c"], io.stdin, limit=io.room)
        io.write(text)
        return status
    if operands:
        try:
            from ssh_sensor.shell.util import read_text

            content = read_text(sh, sh.abspath(operands[0]))
        except FSError as exc:
            io.error(
                f"sh: 0: cannot open {operands[0]}: {exc}\n"
                if False
                else f"{io.cmdline.split()[0]}: {operands[0]}: {exc}\n"
            )
            return 127
        return sh.run_script(content, io)
    if io.stdin:
        return sh.run_script(io.stdin, io)
    return 0

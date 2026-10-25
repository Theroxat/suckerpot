"""The Android shell: the SSH sensor's emulated shell, re-skinned as /system/bin/sh (mksh).

The interpreter (parsing, expansion, redirections, the fake filesystem and its limits) is shared.
What changes is the command set, the error format, the prompt and the environment.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field

from ssh_sensor.shell.core import CmdIO, ShellExit
from ssh_sensor.shell.fs import FSError
from ssh_sensor.shell.interp import Shell, UserInfo
from ssh_sensor.shell.parser import Command

from adb_sensor.commands import (
    BUSYBOX_ONLY,
    COMMANDS,
    cmd_busybox,
    device_of,
    record_missing_download,
)
from adb_sensor.device import BUSYBOX_APPLETS, Device

_BIN_DIRS = ("/system/bin", "/system/xbin", "/bin", "/sbin", "/vendor/bin")
_WRITE_OPS = frozenset({">", ">>", "2>", "2>>", "&>"})
_APPLET_SET = frozenset(BUSYBOX_APPLETS)
ROOT_USER = UserInfo("root", 0, 0, "/", "/system/bin/sh")
SHELL_USER = UserInfo("shell", 2000, 2000, "/", "/system/bin/sh")
BOOTCLASSPATH = (
    "/system/framework/core-oj.jar:/system/framework/core-libart.jar:"
    "/system/framework/conscrypt.jar:/system/framework/okhttp.jar:"
    "/system/framework/bouncycastle.jar:/system/framework/framework.jar"
)


def _mksh_syntax(text: str) -> str:
    """Parser messages in mksh's words: ``<stdin>[1]: syntax error: 'x' unexpected``. Loops
    (``while``, ``for``) are not emulated by the shared shell; they fail like a syntax error."""
    if "unexpected EOF" in text:
        return "<stdin>[1]: syntax error: unexpected EOF\n"
    marker = "syntax error near unexpected token `"
    if marker in text:
        token = text.split(marker, 1)[1].split("'", 1)[0][:32]
        return f"<stdin>[1]: syntax error: '{token}' unexpected\n"
    return text


def _is_text(data: bytes) -> bool:
    """True when the bytes decode as UTF-8 (a cut multi-byte character at the end is fine)."""
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        return exc.start >= len(data) - 3
    return True


_GNU_VERBS = ("access", "remove", "stat", "open", "create directory", "create regular file")


def androidize_error(command: str, text: str) -> str:
    """Rewrite coreutils-style messages (``cannot access 'x': ...``) as toybox/toolbox prints
    them (``x: ...``). Plain string methods only; ``text`` is already bounded."""
    out: list[str] = []
    for line in text.split("\n"):
        head, sep, rest = line.partition(": cannot ")
        if sep:
            for verb in _GNU_VERBS:
                if rest.startswith(verb + " '"):
                    inner = rest[len(verb) + 2 :]
                    name, quote, reason = inner.partition("': ")
                    if quote:
                        line = f"{head}: {name}: {reason}"
                    break
        out.append(line)
    return "\n".join(out)


@dataclass
class AndroidShell(Shell):
    device: Device | None = None
    flags: set[str] = field(default_factory=set)
    rebooted: bool = False

    def __post_init__(self) -> None:
        super().__post_init__()
        self.cwd = "/"
        self.env = {
            "ANDROID_BOOTLOGO": "1",
            "ANDROID_ROOT": "/system",
            "ANDROID_ASSETS": "/system/app",
            "ANDROID_DATA": "/data",
            "ANDROID_STORAGE": "/storage",
            "ASEC_MOUNTPOINT": "/mnt/asec",
            "EXTERNAL_STORAGE": "/sdcard",
            "LOOP_MOUNTPOINT": "/mnt/obb",
            "BOOTCLASSPATH": BOOTCLASSPATH,
            "PATH": "/sbin:/vendor/bin:/system/sbin:/system/bin:/system/xbin",
            "HOME": "/",
            "TERM": self.term if self.term and self.term != "xterm" else "xterm-256color",
            "SHELL": "/system/bin/sh",
            "HOSTNAME": device_of(self).model.device,
            "USER": self.user.name,
            "PWD": "/",
        }
        self.history = []
        self._history_bytes = 0

    def error_prefix(self) -> str:
        return "/system/bin/sh: "

    def prompt(self) -> str:
        dev = device_of(self)
        sign = "#" if self.is_root else "$"
        who = f"{self.user.name}@" if dev.model.prompt_with_user else ""
        return f"{who}{dev.model.device}:{self.cwd or '/'} {sign} "

    def _setup_user(self, name: str) -> UserInfo:
        return SHELL_USER if name == "shell" else ROOT_USER

    def _to_terminal(self, text: str, err: bool = False) -> None:
        if err and text.startswith("bash: "):  # parser errors are formatted by the interpreter
            text = "/system/bin/sh: " + _mksh_syntax(text[6:])
        if "fork: retry: Resource temporarily unavailable" in text:
            text = "/system/bin/sh: can't fork: Out of memory\n"
        super()._to_terminal(text, err)

    def lookup(self, name: str) -> str:
        if name == "0":
            return "/system/bin/sh"
        if name == "$":
            return str(self.pid)
        return super().lookup(name)

    def _run_simple(self, cmd: Command, stdin: str | None, *, piped_out: bool) -> tuple[str, int]:
        if not cmd.words and cmd.redirs:
            # Redirections without a command (``>.t && cat .t``, the usual "is it writable?"
            # probe of loaders) still create or truncate their targets, as in a real shell.
            self._budget -= 1
            self.tick()
            if self._budget < 0:
                self._to_terminal("/system/bin/sh: can't fork: Out of memory\n", True)
                raise ShellExit(1)
            for redir in cmd.redirs:
                if redir.target is None or redir.op not in _WRITE_OPS:
                    continue
                try:
                    target = self.expand_string(redir.target)
                    path = self.abspath(target) if target else ""
                    err = self._prepare_target(path, target, redir.op.endswith(">>"))
                except FSError as exc:
                    err = f"/system/bin/sh: {exc}\n"
                if err:
                    self._to_terminal(err, True)
                    return "", 1
            return "", 0
        try:
            return super()._run_simple(cmd, stdin, piped_out=piped_out)
        except FSError as exc:
            self._to_terminal(f"/system/bin/sh: {exc}\n", True)
            return "", 1

    def dispatch(self, name: str, io: CmdIO) -> int:
        dev = device_of(self)
        if "/" in name:
            return self._run_path(name, io)
        fn = COMMANDS.get(name)
        if fn is not None:
            status = fn(self, io)
            if io.err:
                io.err[:] = [androidize_error(name, text) for text in io.err]
            return status
        if dev.busybox:
            if name == "busybox":
                return cmd_busybox(self, io)
            applet = BUSYBOX_ONLY.get(name)
            if applet is not None:
                return applet(self, io)
            if name in _APPLET_SET:
                return 0
        if name in self.base.binaries:
            return 0  # an Android binary without a canned output: succeeds silently
        record_missing_download(self, name, io)
        io.error(f"{self.error_prefix()}{name[:128]}: {dev.model.not_found}\n")
        return 127

    def _run_path(self, name: str, io: CmdIO) -> int:
        directory, _, base = name.rpartition("/")
        prefix = self.error_prefix()
        if posixpath.normpath(directory or "/") in _BIN_DIRS:
            node = self.fs.stat(posixpath.normpath(directory + "/" + base))
            if node is not None and (
                base in COMMANDS
                or base in self.base.binaries
                or base in _APPLET_SET
                or base == "busybox"
            ):
                return self.dispatch(base, io)
        try:
            path = self.abspath(name)
        except FSError as exc:
            io.error(f"{prefix}{name[:128]}: {exc}\n")
            return 126
        node = self.fs.stat(path)
        if node is None:
            io.error(f"{prefix}{name[:128]}: No such file or directory\n")
            return 127
        if node.kind == "d":
            io.error(f"{prefix}{name[:128]}: can't execute: Is a directory\n")
            return 126
        if not node.mode & 0o111 or not self.can_read(path):
            io.error(f"{prefix}{name[:128]}: can't execute: Permission denied\n")
            return 126
        try:
            content = self.fs.read(path)
        except FSError as exc:
            io.error(f"{prefix}{name[:128]}: {exc}\n")
            return 126
        if content.startswith(b"\x7fELF"):
            return 0  # a "binary" starts and runs silently; nothing is ever executed
        head = content[:4096]
        if b"\0" in head or not _is_text(head):
            io.error(f"{prefix}{name[:128]}: can't execute: Exec format error\n")
            return 126
        return self.run_script(content.decode("utf-8", "replace"), io)

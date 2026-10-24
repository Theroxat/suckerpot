"""The device shell: the SSH sensor's emulated shell, restricted and re-skinned as BusyBox ash.

The interpreter (parsing, expansion, redirections, the fake filesystem and its limits) is shared.
What changes is the command set (BusyBox applets only, device-specific output), the error
format (``sh: foo: not found``), the prompt and the environment (nothing SSH or Ubuntu).
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass

from ssh_sensor.shell.core import CmdIO, ShellExit
from ssh_sensor.shell.fs import FSError
from ssh_sensor.shell.interp import Shell, UserInfo, parse_passwd
from ssh_sensor.shell.parser import Command

from telnet_sensor.commands import COMMANDS, record_missing_download
from telnet_sensor.device import APPLETS

_BIN_DIRS = ("/bin", "/sbin", "/usr/bin", "/usr/sbin")
_APPLET_SET = frozenset(APPLETS)
_WRITE_OPS = frozenset({">", ">>", "2>", "2>>", "&>"})


@dataclass
class DeviceShell(Shell):
    personality_name: str = "dvr"

    def __post_init__(self) -> None:
        super().__post_init__()
        # No trace of SSH or of a desktop distribution in the environment.
        self.env = {
            "USER": self.user.name,
            "HOME": self.user.home,
            "LOGNAME": self.user.name,
            "SHELL": "/bin/sh",
            "PATH": "/sbin:/usr/sbin:/bin:/usr/bin",
            "PWD": self.cwd,
            "TERM": self.term if self.term and self.term != "xterm" else "vt102",
            "HOSTNAME": self.profile.hostname,
        }
        self.history = []
        self._history_bytes = 0

    def error_prefix(self) -> str:
        return "sh: "

    def prompt(self) -> str:
        sign = "#" if self.is_root else "$"
        return f"{self.display_cwd()} {sign} "

    def _to_terminal(self, text: str, err: bool = False) -> None:
        if err and text.startswith("bash: "):  # parser errors are formatted by the interpreter
            text = "sh: " + text[6:]
        if "fork: retry: Resource temporarily unavailable" in text:
            text = "sh: can't fork: Resource temporarily unavailable\n"
        super()._to_terminal(text, err)

    def _setup_user(self, name: str) -> UserInfo:
        users = parse_passwd(self.fs.read("/etc/passwd").decode())
        if name in users:
            return users[name]
        safe = re.sub(r"[^A-Za-z0-9_-]", "", name)[:32] or "user"
        if safe in users:
            return users[safe]
        uid = 1003 + len([u for u in users.values() if u.uid >= 1000])
        info = UserInfo(safe, uid, uid, f"/home/{safe}", "/bin/sh")
        line = f"{safe}:x:{uid}:{uid}:Linux User,,,:{info.home}:/bin/sh\n"
        try:
            self.fs.write("/etc/passwd", line.encode(), append=True, owner="root")
            self.fs.mkdir(info.home, safe, 0o755)
        except FSError:
            pass
        return info

    def lookup(self, name: str) -> str:
        if name == "0":
            return "sh"
        if name == "$":
            return str(self.pid)  # the same pid `ps` shows for this shell
        return super().lookup(name)

    def _run_simple(self, cmd: Command, stdin: str | None, *, piped_out: bool) -> tuple[str, int]:
        if not cmd.words and cmd.redirs:
            # Redirections without a command (``>.t && cat .t``, the usual "is it writable?"
            # probe of loaders) still create or truncate their targets, as in a real shell.
            self._budget -= 1
            self.tick()
            if self._budget < 0:
                self._to_terminal("sh: can't fork\n", True)
                raise ShellExit(1)
            for redir in cmd.redirs:
                if redir.target is None or redir.op not in _WRITE_OPS:
                    continue
                try:
                    target = self.expand_string(redir.target)
                    path = self.abspath(target) if target else ""
                    err = self._prepare_target(path, target, redir.op.endswith(">>"))
                except FSError as exc:
                    err = f"sh: {exc}\n"
                if err:
                    self._to_terminal(err, True)
                    return "", 1
            return "", 0
        try:
            return super()._run_simple(cmd, stdin, piped_out=piped_out)
        except FSError as exc:  # e.g. a path that is too long or loops through symlinks
            self._to_terminal(f"sh: {exc}\n", True)
            return "", 1

    def dispatch(self, name: str, io: CmdIO) -> int:
        if "/" in name:
            return self._run_path(name, io)
        fn = COMMANDS.get(name)
        if fn is not None:
            return fn(self, io)
        if name in _APPLET_SET:
            return 0  # an applet without a canned output: succeeds silently
        record_missing_download(self, name, io)
        io.error(f"{self.error_prefix()}{name[:128]}: not found\n")
        return 127

    def _run_path(self, name: str, io: CmdIO) -> int:
        directory, _, base = name.rpartition("/")
        if posixpath.normpath(directory or "/") in _BIN_DIRS and (
            base in COMMANDS or base in _APPLET_SET
        ):
            return self.dispatch(base, io)
        prefix = self.error_prefix()
        try:
            path = self.abspath(name)
        except FSError as exc:
            io.error(f"{prefix}{name[:128]}: {exc}\n")
            return 126
        node = self.fs.stat(path)
        if node is None:
            io.error(f"{prefix}{name[:128]}: not found\n")
            return 127
        if node.kind == "d" or not node.mode & 0o111 or not self.can_read(path):
            io.error(f"{prefix}{name[:128]}: Permission denied\n")
            return 126
        try:
            content = self.fs.read(path)
        except FSError as exc:
            io.error(f"{prefix}{name[:128]}: {exc}\n")
            return 126
        if content.startswith(b"\x7fELF"):
            return 0  # a "binary" starts and runs silently; nothing is ever executed
        return self.run_script(content.decode("utf-8", "replace"), io)

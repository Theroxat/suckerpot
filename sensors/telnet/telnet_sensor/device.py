"""The fake device: personalities (a cheap DVR or router) and their base filesystem image.

Everything here is data. ``build_base_image`` turns it into an immutable ``BaseImage`` (the type
of the SSH sensor's emulated shell) shared by all sessions. Nothing is read from the real host.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass

from ssh_sensor.shell.baseimage import Profile, derive_profile
from ssh_sensor.shell.fs import BaseImage, Node

BASE_MTIME = 1_516_272_000  # firmware build date: 2018-01-18

# 52-byte ELF headers, limited to bytes below 0x80 so they survive the text round trip of the
# emulated shell and a loader that runs ``cat /bin/echo`` sees the right architecture.
_ELF_ARM = (
    b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00\x28\x00\x01\x00\x00\x00\x40\x4d\x00\x00"
    b"\x34\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x05\x34\x00\x20\x00\x02\x00\x28\x00\x00\x00\x00\x00"
)
_ELF_MIPS = (
    b"\x7fELF\x01\x02\x01\x00" + b"\x00" * 8 + b"\x00\x02\x00\x08\x00\x00\x00\x01\x00\x40\x4d\x00"
    b"\x00\x00\x00\x34\x00\x00\x00\x00\x70\x00\x10\x05\x00\x34\x00\x20\x00\x02\x00\x28\x00\x00\x00\x00"
)

_CPUINFO_ARM = """Processor\t: ARMv7 Processor rev 5 (v7l)
BogoMIPS\t: 1494.01
Features\t: swp half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt
CPU implementer\t: 0x41
CPU architecture: 7
CPU variant\t: 0x0
CPU part\t: 0xc07
CPU revision\t: 5

Hardware\t: hi3516
Revision\t: 0000
Serial\t\t: 0000000000000000
"""

_CPUINFO_MIPS = """system type\t\t: Atheros AR9344 rev 2
machine\t\t\t: Generic AR934x board
processor\t\t: 0
cpu model\t\t: MIPS 74Kc V4.12
BogoMIPS\t\t: 265.42
wait instruction\t: yes
microsecond timers\t: yes
tlb_entries\t\t: 32
extra interrupt vector\t: yes
hardware watchpoint\t: yes, count: 4, address/irw mask: [0x0ffc, 0x0ffc, 0x0ffb, 0x0ffb]
isa\t\t\t: mips1 mips2 mips32r1 mips32r2
ASEs implemented\t: mips16 dsp
shadow register sets\t: 1
kscratch registers\t: 0
core\t\t\t: 0
VCED exceptions\t\t: not available
VCEI exceptions\t\t: not available
"""


@dataclass(frozen=True)
class Personality:
    name: str
    hostname_prefix: str
    arch: str  # uname -m
    kernel: str
    kernel_build: str  # uname -v
    proc_version: str
    busybox: str  # e.g. "v1.19.4 (2018-01-18 10:56:12 CST)"
    cpuinfo: str
    elf_header: bytes
    mem_total_kb: int
    mem_free_kb: int
    mem_buffers_kb: int
    mem_cached_kb: int
    oui: str
    mounts: str
    df_rows: tuple[tuple[str, int, int, str], ...]  # filesystem, 1k blocks, used, mount point
    listen_ports: tuple[int, ...]
    processes: tuple[tuple[int, str, int, str, str], ...]  # pid, user, vsz, stat, command
    base_pid: int  # pid of the telnetd that forked our shell

    @property
    def motd(self) -> str:
        return (
            f"\r\n\r\nBusyBox {self.busybox} built-in shell (ash)\r\n"
            "Enter 'help' for a list of built-in commands.\r\n\r\n"
        )


DVR = Personality(
    name="dvr",
    hostname_prefix="dvr",
    arch="armv7l",
    kernel="3.0.8",
    kernel_build="#1 Thu Jan 18 10:55:23 CST 2018",
    proc_version=(
        "Linux version 3.0.8 (root@localhost.localdomain) (gcc version 4.6.1 "
        "(Hisilicon_v400_20140611) ) #1 Thu Jan 18 10:55:23 CST 2018\n"
    ),
    busybox="v1.19.4 (2018-01-18 10:56:12 CST)",
    cpuinfo=_CPUINFO_ARM,
    elf_header=_ELF_ARM,
    mem_total_kb=59404,
    mem_free_kb=21312,
    mem_buffers_kb=2316,
    mem_cached_kb=14872,
    oui="00:12:16",
    mounts=(
        "rootfs / rootfs rw 0 0\n"
        "/dev/root / squashfs rw,relatime 0 0\n"
        "proc /proc proc rw,relatime 0 0\n"
        "sysfs /sys sysfs rw,relatime 0 0\n"
        "tmpfs /dev tmpfs rw,relatime,size=29700k 0 0\n"
        "devpts /dev/pts devpts rw,relatime,mode=600 0 0\n"
        "tmpfs /var tmpfs rw,relatime,size=8192k 0 0\n"
        "/dev/mtdblock3 /mnt/mtd jffs2 rw,relatime 0 0\n"
    ),
    df_rows=(
        ("/dev/root", 7936, 7936, "/"),
        ("tmpfs", 29700, 4, "/dev"),
        ("tmpfs", 8192, 312, "/var"),
        ("/dev/mtdblock3", 4096, 1124, "/mnt/mtd"),
    ),
    listen_ports=(80, 23, 554, 34567),
    processes=(
        (1, "root", 1296, "S", "init"),
        (2, "root", 0, "SW", "[kthreadd]"),
        (3, "root", 0, "SW", "[ksoftirqd/0]"),
        (5, "root", 0, "SW", "[kworker/u:0]"),
        (61, "root", 0, "SW", "[mtdblock3]"),
        (74, "root", 0, "SW", "[jffs2_gcd_mtd3]"),
        (118, "root", 1424, "S", "/sbin/syslogd"),
        (141, "root", 1212, "S", "/sbin/udhcpc -i eth0 -b"),
        (167, "root", 38144, "S", "/mnt/mtd/app/dvrbox"),
        (181, "root", 3184, "S", "/mnt/mtd/app/httpd -p 80"),
    ),
    base_pid=203,
)

ROUTER = Personality(
    name="router",
    hostname_prefix="wr",
    arch="mips",
    kernel="2.6.31",
    kernel_build="#1 Wed May 3 17:27:45 CST 2017",
    proc_version=(
        "Linux version 2.6.31--LSDK-9.2.0_U12.18 (jenkins@build02) (gcc version 4.3.3 (GCC) ) "
        "#1 Wed May 3 17:27:45 CST 2017\n"
    ),
    busybox="v1.17.3 (2017-05-03 17:19:31 CST)",
    cpuinfo=_CPUINFO_MIPS,
    elf_header=_ELF_MIPS,
    mem_total_kb=29628,
    mem_free_kb=6420,
    mem_buffers_kb=1792,
    mem_cached_kb=8412,
    oui="14:cc:20",
    mounts=(
        "rootfs / rootfs rw 0 0\n"
        "/dev/root / squashfs rw,relatime 0 0\n"
        "proc /proc proc rw,relatime 0 0\n"
        "sysfs /sys sysfs rw,relatime 0 0\n"
        "tmpfs /tmp tmpfs rw,nosuid,nodev,noatime,size=14812k 0 0\n"
        "tmpfs /dev tmpfs rw,relatime,size=512k,mode=755 0 0\n"
        "devpts /dev/pts devpts rw,relatime,mode=600 0 0\n"
        "/dev/mtdblock3 /overlay jffs2 rw,relatime 0 0\n"
    ),
    df_rows=(
        ("/dev/root", 2816, 2816, "/"),
        ("tmpfs", 14812, 188, "/tmp"),
        ("tmpfs", 512, 0, "/dev"),
        ("/dev/mtdblock3", 960, 212, "/overlay"),
    ),
    listen_ports=(80, 23, 1900, 5555),
    processes=(
        (1, "root", 1200, "S", "init"),
        (2, "root", 0, "SW", "[kthreadd]"),
        (3, "root", 0, "SW", "[ksoftirqd/0]"),
        (6, "root", 0, "SW", "[mtdblock2]"),
        (88, "root", 1076, "S", "/sbin/syslogd -C16"),
        (97, "root", 1076, "S", "/sbin/klogd"),
        (143, "root", 1180, "S", "udhcpc -i eth0.2 -p /var/run/udhcpc.pid"),
        (160, "root", 2640, "S", "/usr/sbin/httpd -P /var/run/httpd.pid"),
        (172, "root", 1472, "S", "/usr/sbin/miniupnpd -f /etc/upnpd.conf"),
    ),
    base_pid=191,
)

PERSONALITY_BY_NAME = {p.name: p for p in (DVR, ROUTER)}

# Applets of the fake BusyBox, in the order of ``busybox --list``. Commands without an
# implementation still exist (they do nothing and succeed), everything else is "not found".
APPLETS = (
    "[ [[ ash awk basename cat chgrp chmod chown chroot clear cp cut date dd df dirname dmesg "
    "du echo egrep env expr false fgrep find free ftpget ftpput getty grep gunzip gzip halt head "
    "hostname id ifconfig init insmod kill killall ln login ls lsmod mkdir mkfifo mknod mount mv "
    "nc netstat nslookup passwd ping ping6 poweroff printf ps pwd reboot renice rm rmdir rmmod "
    "route sed sh sleep sort stat sync sysctl tail tar tee telnet telnetd test tftp touch tr "
    "traceroute true umount uname uniq uptime usleep vi wc wget which whoami xargs zcat"
).split()
_SBIN_APPLETS = frozenset(
    "chroot getty halt ifconfig init insmod login lsmod mknod mount poweroff reboot rmmod route "
    "sysctl umount".split()
)

_USERS_DB = """root:x:0:0:root:/root:/bin/sh
daemon:x:1:1:daemon:/usr/sbin:/bin/false
bin:x:2:2:bin:/bin:/bin/false
sys:x:3:3:sys:/dev:/bin/false
sync:x:4:100:sync:/bin:/bin/sync
mail:x:8:8:mail:/var/mail:/bin/false
www-data:x:33:33:www-data:/var/www:/bin/false
ftp:x:40:40:ftp:/home/ftp:/bin/false
admin:x:1000:1000:Linux User,,,:/home/admin:/bin/sh
support:x:1001:1001:Linux User,,,:/home/support:/bin/sh
user:x:1002:1002:Linux User,,,:/home/user:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/false
"""

_GROUP = """root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:
tty:x:5:
mail:x:8:
www-data:x:33:
admin:x:1000:
support:x:1001:
user:x:1002:
nogroup:x:65534:
"""


def derive_device(seed: str, cfg_hostname: str, personality: Personality) -> Profile:
    """Fake identity of the device, derived from the private deployment secret."""
    digest = hashlib.sha256(f"{seed}|telnet-device".encode()).digest()
    hostname = cfg_hostname or f"{personality.hostname_prefix}-{digest[0]:02x}{digest[1]:02x}"
    ip = f"192.168.{1 + digest[2] % 20}.{20 + digest[3] % 200}"
    profile = derive_profile(
        seed + "|telnet",
        hostname,
        ip,
        kernel=personality.kernel,
        kernel_build=personality.kernel_build,
    )
    return profile


_CRYPT_ALPHABET = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def md5_crypt_like(seed: str, user: str) -> str:
    """A ``$1$salt$hash`` string whose salt and hash come from the deployment secret."""
    raw = hashlib.sha256(f"{seed}|shadow|{user}".encode()).digest()
    chars = "".join(_CRYPT_ALPHABET[b % 64] for b in raw)
    return f"$1${chars[:8]}${chars[8:30]}"


def device_mac(profile: Profile, personality: Personality) -> str:
    digest = hashlib.sha256(f"{profile.seed}|mac".encode()).digest()
    return f"{personality.oui}:{digest[0]:02x}:{digest[1]:02x}:{digest[2]:02x}"


def elf_stub(personality: Personality, size: int = 512) -> bytes:
    """A few hundred bytes with a believable ELF header for the device's architecture."""
    return personality.elf_header + b"\x00" * max(0, size - len(personality.elf_header))


def _meminfo(p: Personality) -> str:
    rows = [
        ("MemTotal", p.mem_total_kb),
        ("MemFree", p.mem_free_kb),
        ("Buffers", p.mem_buffers_kb),
        ("Cached", p.mem_cached_kb),
        ("SwapCached", 0),
        ("Active", 21_040),
        ("Inactive", 9_208),
        ("SwapTotal", 0),
        ("SwapFree", 0),
        ("Dirty", 4),
        ("Writeback", 0),
        ("Mapped", 7_244),
        ("Slab", 4_388),
    ]
    return "".join(f"{k + ':':<16}{v:>8} kB\n" for k, v in rows)


def build_base_image(profile: Profile, p: Personality) -> BaseImage:
    h = profile.hostname
    nodes: dict[str, Node] = {}

    def d(path: str, mode: int = 0o755, owner: str = "root") -> None:
        nodes[path] = Node("d", mode=mode, owner=owner, group=owner, mtime=BASE_MTIME)

    def f(
        path: str, content: str | bytes, mode: int = 0o644, owner: str = "root", group: str = ""
    ) -> None:
        data = content.encode() if isinstance(content, str) else content
        nodes[path] = Node(
            "f", mode=mode, owner=owner, group=group or owner, mtime=BASE_MTIME, content=data
        )

    def link(path: str, target: str) -> None:
        nodes[path] = Node("l", mode=0o777, mtime=BASE_MTIME, target=target)

    d("/")
    for path in (
        "/bin /dev /dev/pts /etc /etc/init.d /home /lib /mnt /mnt/mtd /opt /proc /proc/net "
        "/proc/sys /root /sbin /sys /usr /usr/bin /usr/sbin /usr/lib /var /var/run /var/log "
        "/var/lock /var/tmp /home/admin /home/support /home/user /www"
    ).split():
        d(path)
    d("/root", 0o700)
    d("/tmp", 0o1777)
    d("/var/tmp", 0o1777)
    d("/home/admin", 0o755, "admin")
    d("/home/support", 0o755, "support")
    d("/home/user", 0o755, "user")
    link("/linuxrc", "bin/busybox")
    if p.name == "router":
        d("/overlay")
    f("/bin/busybox", elf_stub(p, 612_000), 0o755)
    for name in APPLETS:
        if name in ("[", "[["):
            continue
        base = "/sbin" if name in _SBIN_APPLETS else "/bin"
        link(f"{base}/{name}", "/bin/busybox" if base == "/sbin" else "busybox")
    f("/bin/[", elf_stub(p, 64), 0o755)
    f("/etc/passwd", _USERS_DB)
    f("/etc/group", _GROUP)
    shadow = "".join(
        f"{u}:{md5_crypt_like(profile.seed, u)}:17549:0:99999:7:::\n"
        for u in ("root", "admin", "support", "user")
    )
    f("/etc/shadow", shadow, 0o600)
    f("/etc/hostname", h + "\n")
    f("/etc/hosts", f"127.0.0.1\tlocalhost\n{profile.ip}\t{h}\n")
    f("/etc/resolv.conf", f"nameserver {profile.gateway}\n")
    f("/etc/issue", f"\n{h} login: \n")
    f("/etc/inittab", "::sysinit:/etc/init.d/rcS\n::respawn:/sbin/getty -L ttyS0 115200 vt100\n")
    f("/etc/init.d/rcS", "#!/bin/sh\nmount -a\n/bin/telnetd -l /bin/login &\n", 0o755)
    f("/etc/fstab", "proc /proc proc defaults 0 0\nsysfs /sys sysfs defaults 0 0\n")
    f("/etc/TZ", "CST-8\n")
    f("/etc/version", p.busybox.split()[0] + "\n")
    f("/proc/cpuinfo", p.cpuinfo)
    f("/proc/meminfo", _meminfo(p))
    f("/proc/version", p.proc_version)
    f("/proc/mounts", p.mounts)
    f("/proc/cmdline", "console=ttyAMA0,115200 root=/dev/mtdblock2 rootfstype=squashfs\n")
    link("/proc/self", str(p.base_pid + 7))
    for pid, _user, _vsz, _stat, command in p.processes:
        d(f"/proc/{pid}", 0o555)
        f(f"/proc/{pid}/cmdline", command.replace(" ", "\0") + "\0", 0o444)
        link(f"/proc/{pid}/exe", "/bin/busybox")
    d(f"/proc/{p.base_pid + 7}", 0o555)
    f(f"/proc/{p.base_pid + 7}/cmdline", "-sh\0", 0o444)
    link(f"/proc/{p.base_pid + 7}/exe", "/bin/busybox")
    f("/proc/uptime", "0.00 0.00\n")
    f("/proc/loadavg", "0.00 0.00 0.00 1/60 1\n")
    f(
        "/proc/net/dev",
        "Inter-|   Receive                                                |  Transmit\n"
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets "
        "errs drop fifo colls carrier compressed\n"
        "    lo:       0       0    0    0    0     0          0         0        0       0 "
        "   0    0    0     0       0          0\n"
        "  eth0:       0       0    0    0    0     0          0         0        0       0 "
        "   0    0    0     0       0          0\n",
    )
    for dev in ("null", "zero", "random", "urandom", "console", "tty", "ttyS0", "watchdog"):
        f(f"/dev/{dev}", b"", 0o666 if dev in ("null", "zero", "tty") else 0o600)
    for i in range(4):
        f(f"/dev/mtdblock{i}", b"", 0o660)
    f("/mnt/mtd/Config/Account1", "", 0o600)
    f("/www/index.html", f"<html><head><title>{h}</title></head><body></body></html>\n")

    boot = profile.boot_epoch

    def uptime() -> bytes:
        up = max(0, int(time.time()) - boot)
        return f"{up}.{up % 97:02d} {up - up // 40}.{up % 89:02d}\n".encode()

    def loadavg() -> bytes:
        return b"0.02 0.04 0.00 1/58 8123\n"

    dynamic: dict[str, Callable[[], bytes]] = {
        "/proc/uptime": uptime,
        "/proc/loadavg": loadavg,
    }
    return BaseImage.build(nodes, dynamic, tuple(sorted(set(APPLETS))))

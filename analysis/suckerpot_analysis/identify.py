"""File type and architecture identification from bounded header reads.

Only a handful of fields are read with `struct`; every offset is checked against the buffer.
"""

from __future__ import annotations

import re
import struct

from .models import FileInfo

_MAX_HEADERS = 256

_ELF_MACHINES = {
    2: "sparc",
    3: "x86",
    4: "m68k",
    8: "mips",
    18: "sparc",
    20: "ppc",
    21: "ppc64",
    40: "arm",
    42: "superh",
    43: "sparc",
    45: "arc",
    62: "x86-64",
    93: "arc",
    183: "aarch64",
}
_PE_MACHINES = {0x14C: "x86", 0x8664: "x86-64", 0x1C0: "arm", 0x1C4: "arm", 0xAA64: "aarch64"}
_MACHO_CPUS = {7: "x86", 0x01000007: "x86-64", 12: "arm", 0x0100000C: "aarch64"}
_SHELL_HINT = re.compile(
    rb"\b(wget|curl|chmod|busybox|tftp|echo|cd\s+/|rm\s+-|sh\s|bash|export|nohup|crontab|pkill)\b"
)


def _unpack(fmt: str, data: bytes, offset: int) -> tuple[int, ...] | None:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        return None
    return struct.unpack_from(fmt, data, offset)


def _u(fmt: str, data: bytes, offset: int) -> int | None:
    values = _unpack(fmt, data, offset)
    return None if values is None else int(values[0])


def _identify_elf(data: bytes) -> FileInfo:
    is64 = data[4] == 2
    little = data[5] != 2
    e = "<" if little else ">"
    machine = _u(e + "H", data, 18)
    arch = _ELF_MACHINES.get(machine) if machine is not None else None
    linking: str | None = None
    stripped: bool | None = None
    if is64:
        phoff, shoff = _u(e + "Q", data, 32), _u(e + "Q", data, 40)
        phentsize, phnum = _u(e + "H", data, 54), _u(e + "H", data, 56)
        shentsize, shnum = _u(e + "H", data, 58), _u(e + "H", data, 60)
    else:
        phoff, shoff = _u(e + "I", data, 28), _u(e + "I", data, 32)
        phentsize, phnum = _u(e + "H", data, 42), _u(e + "H", data, 44)
        shentsize, shnum = _u(e + "H", data, 46), _u(e + "H", data, 48)
    min_ph = 56 if is64 else 32
    if phoff is not None and phentsize and phnum is not None and phentsize >= min_ph:
        count = min(phnum, _MAX_HEADERS)
        if phoff + count * phentsize <= len(data):
            linking = "static"
            for i in range(count):
                if _u(e + "I", data, phoff + i * phentsize) == 3:  # PT_INTERP
                    linking = "dynamic"
                    break
    min_sh = 64 if is64 else 40
    if shoff and shentsize and shnum is not None and shentsize >= min_sh:
        count = min(shnum, _MAX_HEADERS)
        if shoff + count * shentsize <= len(data):
            stripped = True
            for i in range(count):
                if _u(e + "I", data, shoff + i * shentsize + 4) == 2:  # SHT_SYMTAB
                    stripped = False
                    break
    elif shoff == 0 and shnum == 0:
        stripped = True  # no section headers at all
    return FileInfo(
        kind="elf",
        arch=arch,
        bits=64 if is64 else 32,
        endian="little" if little else "big",
        linking=linking,  # type: ignore[arg-type]
        stripped=stripped,
    )


def _identify_pe(data: bytes) -> FileInfo | None:
    lfanew = _u("<I", data, 0x3C)
    if lfanew is None or data[lfanew : lfanew + 4] != b"PE\x00\x00":
        return None
    machine = _u("<H", data, lfanew + 4)
    chars = _u("<H", data, lfanew + 22)
    magic = _u("<H", data, lfanew + 24)
    bits = {0x10B: 32, 0x20B: 64}.get(magic) if magic is not None else None
    return FileInfo(
        kind="pe",
        arch=_PE_MACHINES.get(machine) if machine is not None else None,
        bits=bits,
        endian="little",
        is_dll=bool(chars & 0x2000) if chars is not None else None,
    )


def _identify_macho(data: bytes) -> FileInfo | None:
    magic = data[:4]
    table = {
        b"\xcf\xfa\xed\xfe": ("<", 64),
        b"\xce\xfa\xed\xfe": ("<", 32),
        b"\xfe\xed\xfa\xcf": (">", 64),
        b"\xfe\xed\xfa\xce": (">", 32),
    }
    if magic not in table:
        return None
    e, bits = table[magic]
    cpu = _u(e + "I", data, 4)
    return FileInfo(
        kind="macho",
        arch=_MACHO_CPUS.get(cpu) if cpu is not None else None,
        bits=bits,
        endian="little" if e == "<" else "big",
    )


def _packer(data: bytes) -> str | None:
    head = data[: 1024 * 1024]
    if b"UPX!" in head or b"UPX0" in head or b"$Info: This file is packed with the UPX" in head:
        return "upx"
    return None


def _identify_text(data: bytes) -> FileInfo:
    head = data[:4096]
    if head.startswith(b"#!"):
        line = head[2:].split(b"\n", 1)[0].decode("ascii", errors="replace").strip()
        parts = line.split()
        if parts and parts[0].rsplit("/", 1)[-1] == "env" and len(parts) > 1:
            parts = parts[1:]
        interp = parts[0].rsplit("/", 1)[-1][:32] if parts else None
        return FileInfo(kind="script", interpreter=interp or None)
    if not head or b"\x00" in head:
        return FileInfo(kind="data")
    printable = sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13))
    if printable / len(head) < 0.95:
        return FileInfo(kind="data")
    if _SHELL_HINT.search(head):
        return FileInfo(kind="script", interpreter="sh")
    return FileInfo(kind="text")


def identify(data: bytes) -> FileInfo:
    """Return kind, arch, bits, endianness, linking and packer. Never raises."""
    try:
        info = _identify(data)
    except (struct.error, IndexError, ValueError):  # defensive: parsers are bounds-checked
        info = FileInfo(kind="data")
    packer = _packer(data)
    if packer and info.kind in {"elf", "pe", "macho"}:
        info = info.model_copy(update={"packer": packer})
    return info


def _identify(data: bytes) -> FileInfo:
    if data[:4] == b"\x7fELF" and len(data) >= 20:
        return _identify_elf(data)
    if data[:2] == b"MZ":
        pe = _identify_pe(data)
        if pe is not None:
            return pe
    macho = _identify_macho(data)
    if macho is not None:
        return macho
    if data[:2] == b"\x1f\x8b":
        return FileInfo(kind="gzip")
    if data[:4] == b"PK\x03\x04":
        return FileInfo(kind="zip")
    if data[:6] == b"\xfd7zXZ\x00":
        return FileInfo(kind="xz")
    if data[:6] == b"7z\xbc\xaf\x27\x1c":
        return FileInfo(kind="7z")
    if data[:3] == b"BZh" and data[3:4] in {b"1", b"2", b"3", b"4", b"5", b"6", b"7", b"8", b"9"}:
        return FileInfo(kind="bzip2")
    if data[257:262] == b"ustar":
        return FileInfo(kind="tar")
    return _identify_text(data)

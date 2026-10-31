"""Run the analysis child: the only process spawn in this package.

``asyncio.create_subprocess_exec`` with a fixed argv, no shell, an empty environment apart from
three settings, and the sample on stdin. The child is our own parser code being isolated, never the
sample being run. The parent enforces a wall-clock timeout and a stdout cap, and validates the
output against the ``AnalysisResult`` model, so a confused child cannot write arbitrary rows.
"""

from __future__ import annotations

import asyncio
import contextlib
import signal
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError
from suckerpot_analysis import AnalysisResult

from collector.analysis_child import EXIT_MEMORY

MAX_STDOUT = 2 * 1024 * 1024
CHILD_ARGV = (sys.executable, "-I", "-m", "collector.analysis_child")


@dataclass(frozen=True)
class ChildOutcome:
    status: str  # done | failed | timeout
    code: str | None = None  # constant failure code
    result: AnalysisResult | None = None


async def _feed(proc: asyncio.subprocess.Process, data: bytes) -> None:
    stdin = proc.stdin
    if stdin is None:
        return
    try:
        stdin.write(data)
        await stdin.drain()
        stdin.close()
    except (BrokenPipeError, ConnectionResetError):
        pass  # the child exited early; the exit code explains why


async def _collect(proc: asyncio.subprocess.Process) -> bytes | None:
    stdout = proc.stdout
    if stdout is None:
        return None
    out = bytearray()
    while chunk := await stdout.read(65536):
        out += chunk
        if len(out) > MAX_STDOUT:
            return None
    return bytes(out)


def _kill(proc: asyncio.subprocess.Process) -> None:
    with contextlib.suppress(ProcessLookupError):
        proc.kill()


async def run_child(
    data: bytes,
    *,
    timeout_s: float,
    memory_mb: int,
    rules_dir: Path,
    argv: Sequence[str] = CHILD_ARGV,
) -> ChildOutcome:
    env = {
        "RULES_DIR": str(rules_dir),
        "ANALYZER_MEMORY_MB": str(memory_mb),
        "ANALYZER_CPU_S": str(max(1, min(30, int(timeout_s // 2)))),
    }
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        env=env,
    )
    feeder = asyncio.create_task(_feed(proc, data))
    try:
        async with asyncio.timeout(timeout_s):
            out = await _collect(proc)
            if out is None:
                _kill(proc)
                await proc.wait()
                return ChildOutcome("failed", "output_too_large")
            code = await proc.wait()
    except TimeoutError:
        _kill(proc)
        await proc.wait()
        return ChildOutcome("timeout", "timeout")
    finally:
        _kill(proc)
        feeder.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await feeder
    if code == EXIT_MEMORY:
        return ChildOutcome("failed", "memory")
    if code == -signal.SIGXCPU or code == -signal.SIGKILL:
        return ChildOutcome("failed", "cpu_limit" if code == -signal.SIGXCPU else "killed")
    if code != 0:
        return ChildOutcome("failed", "child_error")
    try:
        return ChildOutcome("done", None, AnalysisResult.model_validate_json(out))
    except ValidationError:
        return ChildOutcome("failed", "invalid_output")

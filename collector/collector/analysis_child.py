"""The analysis child process: reads one sample on stdin, writes an AnalysisResult as JSON.

Started by ``collector.runner`` with a fixed argv, an empty environment (no database password, no
proxy credentials) and the sample on stdin, so it never opens a path it was told by a file. The
first thing it does is lower its own limits. It parses; it never executes.
"""

from __future__ import annotations

import os
import resource
import sys
from pathlib import Path

MIB = 1024 * 1024
MAX_INPUT = 16 * MIB
EXIT_MEMORY = 75
EXIT_ERROR = 1


def apply_limits(memory_mb: int, cpu_s: int) -> None:
    """Hard limits for this process. Not RLIMIT_NPROC: it counts per uid across the host."""
    # CPU: a soft limit sends SIGXCPU (which ends the process); the hard limit is the SIGKILL.
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s + 2))
    for which, value in (
        (resource.RLIMIT_AS, memory_mb * MIB),
        (resource.RLIMIT_FSIZE, 0),
        (resource.RLIMIT_NOFILE, 16),
        (resource.RLIMIT_CORE, 0),
    ):
        resource.setrlimit(which, (value, value))


def main() -> int:
    apply_limits(
        int(os.environ.get("ANALYZER_MEMORY_MB", "384")), int(os.environ["ANALYZER_CPU_S"])
    )
    try:
        from suckerpot_analysis import analyze, compile_rules

        rules = compile_rules(Path(os.environ["RULES_DIR"]))
        data = sys.stdin.buffer.read(MAX_INPUT + 1)
        result = analyze(data, rules=rules)
        sys.stdout.buffer.write(result.model_dump_json().encode())
        sys.stdout.buffer.flush()
    except MemoryError:
        return EXIT_MEMORY
    except Exception:
        return EXIT_ERROR
    return 0


if __name__ == "__main__":
    sys.exit(main())

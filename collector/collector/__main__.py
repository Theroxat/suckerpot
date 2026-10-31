"""Entry point: ``python -m collector fetch`` or ``python -m collector analyze``."""

from __future__ import annotations

import asyncio
import logging
import sys

from suckerpot_db import create_engine, create_session_factory
from suckerpot_egress import EgressGate, EgressSettings

from collector.analyzer import AnalyzerService
from collector.config import CollectorSettings
from collector.service import CollectorService
from collector.store import Quarantine


async def _fetch() -> None:
    settings = CollectorSettings.from_env()
    engine = create_engine(pool_size=4)
    try:
        gate = EgressGate(EgressSettings.from_env())
        service = CollectorService(
            settings, create_session_factory(engine), Quarantine(settings.quarantine_dir), gate
        )
        await service.run()
    finally:
        await engine.dispose()


async def _analyze() -> None:
    settings = CollectorSettings.from_env()
    engine = create_engine(pool_size=2)
    try:
        service = AnalyzerService(
            settings, create_session_factory(engine), Quarantine(settings.quarantine_dir)
        )
        await service.run()
    finally:
        await engine.dispose()


def main(argv: list[str]) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    commands = {"fetch": _fetch, "analyze": _analyze}
    if len(argv) != 2 or argv[1] not in commands:
        print("usage: python -m collector fetch|analyze", file=sys.stderr)
        return 2
    asyncio.run(commands[argv[1]]())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

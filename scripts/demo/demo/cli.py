"""Command line entry point: ``python -m demo``."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import random
import signal
import sys
from collections.abc import Sequence
from datetime import UTC, datetime

from suckerpot_common import Event

from demo.generator import Generator
from demo.sinks import JsonLinesSink, RedisSink, Sink

BATCH = 500
LIVE_MAX_SESSION_S = 90.0


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw else default


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="demo", description="Generate synthetic honeypot attacks.")
    p.add_argument("--days", type=int, default=_env_int("DEMO_DAYS", 30), help="backfill window")
    p.add_argument(
        "--sessions", type=int, default=_env_int("DEMO_SESSIONS", 3000), help="backfill sessions"
    )
    p.add_argument("--seed", type=int, default=_env_int("DEMO_SEED", 42))
    p.add_argument("--live", action="store_true", help="after the backfill, keep trickling")
    p.add_argument("--live-only", action="store_true", help="skip the backfill, trickle only")
    p.add_argument("--dry-run", action="store_true", help="print JSON lines instead of Redis")
    p.add_argument("--now", help="ISO timestamp used as 'now' (for reproducible output)")
    p.add_argument("--live-limit", type=int, default=0, help="stop after N live sessions (tests)")
    p.add_argument("--live-min", type=float, default=1.0, help="min seconds between sessions")
    p.add_argument("--live-max", type=float, default=8.0, help="max seconds between sessions")
    p.add_argument("--live-speed", type=float, default=1.0, help="time compression for sessions")
    args = p.parse_args(argv)
    if args.days < 1 or args.sessions < 0 or args.live_min < 0 or args.live_max < args.live_min:
        p.error("invalid --days/--sessions/--live-min/--live-max")
    if args.live_speed <= 0:
        p.error("--live-speed must be positive")
    return args


def _parse_now(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(UTC)
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


async def backfill(gen: Generator, sink: Sink, sessions: int) -> int:
    events = gen.backfill(sessions)
    for i in range(0, len(events), BATCH):
        await sink.emit(events[i : i + BATCH])
    print(f"backfill: {sessions} sessions, {len(events)} events", file=sys.stderr)
    return len(events)


async def _play(gen: Generator, sink: Sink, speed: float) -> None:
    """Emit one session in (compressed) real time, stamping events with the current time."""
    plan = gen.plan_at(datetime.now(UTC))
    template = gen.events_for(plan, datetime.now(UTC))
    scale = min(1.0, LIVE_MAX_SESSION_S / plan.duration) if plan.duration else 1.0
    prev = 0.0
    for step, event in zip(plan.steps, template, strict=True):
        await asyncio.sleep(max(0.0, (step.offset - prev) * scale / speed))
        prev = step.offset
        await sink.emit([_restamp(event)])


def _restamp(event: Event) -> Event:
    return event.model_copy(update={"ts": datetime.now(UTC)})


async def live(gen: Generator, sink: Sink, args: argparse.Namespace) -> None:
    rng = random.Random(args.seed + 1)
    tasks: set[asyncio.Task[None]] = set()
    started = 0
    try:
        while not args.live_limit or started < args.live_limit:
            task = asyncio.create_task(_play(gen, sink, args.live_speed))
            tasks.add(task)
            task.add_done_callback(tasks.discard)
            started += 1
            await asyncio.sleep(rng.uniform(args.live_min, args.live_max))
        await asyncio.gather(*tasks)
    finally:
        for t in tasks:
            t.cancel()


async def run(args: argparse.Namespace, sink: Sink | None = None) -> None:
    now = _parse_now(args.now)
    gen = Generator(seed=args.seed, now=now, days=args.days)
    sink = sink or (JsonLinesSink() if args.dry_run else RedisSink())
    try:
        if not args.live_only:
            await backfill(gen, sink, args.sessions)
        if args.live or args.live_only:
            print("live: trickling sessions (Ctrl-C to stop)", file=sys.stderr)
            await live(gen, sink, args)
    finally:
        await sink.close()


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    async def _main() -> None:
        loop = asyncio.get_running_loop()
        task = asyncio.current_task()
        assert task is not None  # noqa: S101
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, task.cancel)
        await run(args)

    with contextlib.suppress(asyncio.CancelledError):
        asyncio.run(_main())
    return 0


__all__ = ["main", "parse_args", "run"]

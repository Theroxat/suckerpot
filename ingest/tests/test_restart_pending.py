"""Multi-stream behaviour: orphaned pending entries survive restarts, per-stream trim safety,
sensor/stream validation and future-id handling (in-memory stream with group semantics)."""

import time
from pathlib import Path
from typing import Any

import pytest
from redis.exceptions import ResponseError

from ingest.config import Settings
from ingest.consumer import Consumer

from .helpers import make_event

STREAMS = "events:ssh,events:web"


class FakeStreams:
    """Minimal in-memory Redis streams with consumer-group semantics (one group)."""

    def __init__(self) -> None:
        self.entries: dict[str, list[tuple[str, dict[Any, Any]]]] = {}
        self.delivered: dict[str, int] = {}
        self.pending: dict[str, dict[str, str]] = {}  # stream -> id -> consumer
        self.groups: set[str] = set()
        self.trims: list[tuple[str, str]] = []

    def add(self, stream: str, n: int, *, sensor: str | None = None, ms: int | None = None) -> None:
        sensor = sensor or stream.split(":")[1]
        for _ in range(n):
            lst = self.entries.setdefault(stream, [])
            mid = f"{ms if ms is not None else len(lst) + 1}-{len(lst)}"
            fields = dict(make_event("connect", sensor=sensor).to_stream_fields())
            lst.append((mid, fields))

    async def xgroup_create(self, stream: str, group: str, id: str, mkstream: bool) -> None:
        if stream in self.groups:
            raise ResponseError("BUSYGROUP Consumer Group name already exists")
        self.groups.add(stream)
        self.entries.setdefault(stream, [])

    async def xreadgroup(
        self, group: str, consumer: str, streams: dict[str, str], count: int, block: Any
    ) -> Any:
        out: list[Any] = []
        for stream, start in streams.items():
            pend = self.pending.setdefault(stream, {})
            if start == ">":
                d = self.delivered.get(stream, 0)
                fresh = self.entries.get(stream, [])[d : d + count]
                self.delivered[stream] = d + len(fresh)
                for mid, _ in fresh:
                    pend[mid] = consumer
                msgs = fresh
            else:
                mine = [m for m, c in pend.items() if c == consumer][:count]
                msgs = [e for e in self.entries.get(stream, []) if e[0] in mine]
            if msgs:
                out.append([stream.encode(), msgs])
        return out

    async def xack(self, stream: str, group: str, *ids: Any) -> int:
        for i in ids:
            self.pending.get(stream, {}).pop(i, None)
        return len(ids)

    async def xautoclaim(
        self, stream: str, group: str, consumer: str, min_idle_time: int, start_id: str, count: int
    ) -> Any:
        pend = self.pending.setdefault(stream, {})
        after = int(start_id.split("-")[0])
        todo = sorted((int(m.split("-")[0]), m) for m in pend)
        todo = [t for t in todo if t[0] >= after]
        batch, rest = todo[:count], todo[count:]
        for _, m in batch:
            pend[m] = consumer
        cursor = f"{rest[0][0]}-0" if rest else "0-0"
        ids = {m for _, m in batch}
        return [cursor, [e for e in self.entries.get(stream, []) if e[0] in ids], []]

    async def xtrim(self, stream: str, minid: str, approximate: bool) -> int:
        # Invariant: never trim past the oldest still-pending entry of THIS stream.
        pend = self.pending.get(stream, {})
        oldest = min((int(m.split("-")[0]) for m in pend), default=None)
        assert oldest is None or int(minid.split("-")[0]) <= oldest, "trimmed past pending"
        self.trims.append((stream, minid))
        return 0


def make_consumer(
    fake: FakeStreams, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, batch: str = "4"
) -> tuple[Consumer, list[tuple[str, int]]]:
    written: list[tuple[str, int]] = []

    async def fake_write(_f: Any, events: Any) -> None:
        written.append((str(events[0].sensor), len(events)))

    monkeypatch.setattr("ingest.consumer.write_batch", fake_write)
    settings = Settings.from_env(
        {
            "INGEST_HEARTBEAT_PATH": str(tmp_path / "hb"),
            "INGEST_BATCH_SIZE": batch,
            "INGEST_STREAMS": STREAMS,
        }
    )
    c = Consumer(settings, fake, None)  # type: ignore[arg-type]
    orig = fake.xreadgroup

    async def read_and_stop(*a: Any, **k: Any) -> Any:
        res = await orig(*a, **k)
        all_done = all(
            fake.delivered.get(s, 0) == len(fake.entries.get(s, [])) and not fake.pending.get(s)
            for s in settings.streams
        )
        if not res and all_done:
            c.stop.set()
        return res

    fake.xreadgroup = read_and_stop  # type: ignore[method-assign]
    return c, written


async def test_orphans_survive_restart_on_every_stream(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = FakeStreams()
    fake.groups = {"events:ssh", "events:web"}
    fake.add("events:ssh", 7)
    fake.add("events:web", 3)
    # A previous container read entries and died before acknowledging them.
    await fake.xreadgroup("ingest", "dead-host", {"events:ssh": ">", "events:web": ">"}, 5, None)
    assert len(fake.pending["events:ssh"]) == 5 and len(fake.pending["events:web"]) == 3
    fake.add("events:ssh", 3)  # arrived while ingest was down
    c, written = make_consumer(fake, tmp_path, monkeypatch)
    await c.run()
    assert sum(n for sensor, n in written if sensor == "ssh") == 10
    assert sum(n for sensor, n in written if sensor == "web") == 3
    assert not fake.pending["events:ssh"] and not fake.pending["events:web"]
    assert "events:ssh" in {s for s, _ in fake.trims}


async def test_trim_is_per_stream_and_waits_for_drain(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = FakeStreams()
    fake.groups = {"events:ssh", "events:web"}
    fake.add("events:ssh", 9)
    fake.add("events:web", 2)
    await fake.xreadgroup("ingest", "dead-host", {"events:ssh": ">"}, 9, None)
    c, _ = make_consumer(fake, tmp_path, monkeypatch, batch="3")
    await c.run()  # the fake asserts on every xtrim
    assert not fake.pending["events:ssh"]


async def test_sensor_stream_mismatch_is_dropped_and_acked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = FakeStreams()
    fake.groups = {"events:ssh", "events:web"}
    fake.add("events:ssh", 2)
    fake.add("events:ssh", 3, sensor="web")  # forged: web event on the ssh stream
    c, written = make_consumer(fake, tmp_path, monkeypatch)
    await c.run()
    assert written == [("ssh", 2)]
    assert c.sensor_mismatches == 3
    assert not fake.pending["events:ssh"]


async def test_future_ids_warn_once_and_are_never_trim_targets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    fake = FakeStreams()
    fake.groups = {"events:ssh", "events:web"}
    far = int(time.time() * 1000) + 5 * 24 * 3600 * 1000
    now = int(time.time() * 1000)
    fake.add("events:ssh", 1, ms=now)
    fake.add("events:ssh", 2, ms=far)
    fake.add("events:ssh", 1, ms=far + 1)
    c, written = make_consumer(fake, tmp_path, monkeypatch, batch="1")
    with caplog.at_level("WARNING"):
        await c.run()
    assert sum(n for _, n in written) == 4  # still ingested
    assert sum("far in the future" in r.message for r in caplog.records) == 1  # rate-limited
    assert all(int(m.split("-")[0]) < far for _, m in fake.trims)

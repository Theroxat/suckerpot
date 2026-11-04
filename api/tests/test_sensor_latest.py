"""The per-sensor "newest event" read must not scan the window (perf regression, M33)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.dialects import postgresql

from api.sensors import SENSORS, latest_event_per_sensor, latest_event_statement

SINCE = datetime(2026, 11, 1, tzinfo=UTC)


def test_statement_has_one_indexed_max_per_sensor_and_no_group_by() -> None:
    sql = str(latest_event_statement(SINCE).compile(dialect=postgresql.dialect()))  # type: ignore[no-untyped-call]
    assert "GROUP BY" not in sql.upper()
    assert sql.count("max(events.ts)") == len(SENSORS)
    assert sql.count("events.sensor =") == len(SENSORS)


class _Result:
    def __init__(self, row: tuple[Any, ...]) -> None:
        self._row = row

    def one(self) -> tuple[Any, ...]:
        return self._row


class _Db:
    def __init__(self, row: tuple[Any, ...]) -> None:
        self.row = row
        self.statements = 0

    async def execute(self, _stmt: Any) -> _Result:
        self.statements += 1
        return _Result(self.row)


async def test_maps_sensors_and_skips_silent_ones() -> None:
    ts = SINCE + timedelta(hours=1)
    row = tuple(ts if name in ("ssh", "web") else None for name in SENSORS)
    db = _Db(row)
    out = await latest_event_per_sensor(db, SINCE)  # type: ignore[arg-type]
    assert out == {"ssh": ts, "web": ts}
    assert db.statements == 1

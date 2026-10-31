from datetime import UTC, datetime, timedelta
from typing import Any

from suckerpot_common import Event

T0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)


def make_event(
    etype: str,
    *,
    sid: str = "s1",
    offset_s: float = 0,
    data: dict[str, Any] | None = None,
    sensor: str = "ssh",
    ip: str = "203.0.113.7",
    base: datetime = T0,
) -> Event:
    return Event.model_validate(
        {
            "ts": base + timedelta(seconds=offset_s),
            "sensor": sensor,
            "session_id": sid,
            "src_ip": ip,
            "src_port": 40000,
            "dst_port": 2222,
            "type": etype,
            "data": data or {},
        }
    )

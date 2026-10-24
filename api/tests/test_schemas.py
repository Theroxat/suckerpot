from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from types import SimpleNamespace
from typing import Any

import pytest

from api.schemas import EventOut, SessionOut

NOW = datetime(2026, 10, 24, tzinfo=UTC)


@pytest.mark.parametrize(
    ("ip", "expected"),
    [(IPv4Address("203.0.113.7"), "203.0.113.7"), (IPv6Address("2001:db8::1"), "2001:db8::1")],
)
def test_inet_objects_become_strings(ip: IPv4Address | IPv6Address, expected: str) -> None:
    common: dict[str, Any] = {
        "session_id": "s",
        "sensor": "ssh",
        "src_ip": ip,
        "src_port": 1,
        "dst_port": 2,
        "country": None,
        "city": None,
        "asn": None,
        "org": None,
        "abuse_score": None,
        "known_scanner": None,
        "tags": [],
    }
    session = SimpleNamespace(
        **common,
        started_at=NOW,
        ended_at=None,
        last_event_at=NOW,
        event_count=1,
        login_attempts=0,
        login_success=False,
        commands=0,
        downloads=0,
        http_requests=0,
    )
    event = SimpleNamespace(**common, id=1, ts=NOW, type="connect", data={})
    assert SessionOut.model_validate(session, from_attributes=True).src_ip == expected
    out = EventOut.model_validate(event, from_attributes=True)
    assert out.src_ip == expected
    assert out.model_dump(mode="json")["src_ip"] == expected

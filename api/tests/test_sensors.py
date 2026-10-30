"""The sensor list is defined once and every consumer follows it."""

import importlib.util

import pytest

from api import analytics_queries, settings
from api.analytics_schemas import SensorBreakdown
from api.sensors import SENSOR_LABELS, SENSORS


def test_twelve_sensors_in_stable_order() -> None:
    assert SENSORS == (
        "ssh", "telnet", "web", "rdp", "redis", "docker", "mysql", "adb", "mssql", "smb", "sip",
        "synology",
    )  # fmt: skip


def test_all_consumers_share_the_tuple() -> None:
    assert getattr(analytics_queries, "SENSORS") is SENSORS  # noqa: B009
    assert getattr(settings, "SENSORS") is SENSORS  # noqa: B009
    assert tuple(SensorBreakdown.model_fields) == SENSORS
    assert set(SENSOR_LABELS) == set(SENSORS)


@pytest.mark.skipif(importlib.util.find_spec("suckerpot_common") is None, reason="not installed")
def test_matches_sensor_common_enum() -> None:
    enum = importlib.import_module("suckerpot_common").SensorName
    assert tuple(n.value for n in enum) == SENSORS

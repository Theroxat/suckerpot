"""Multi-sensor filter parsing: repeated params, comma lists, single values, bad values."""

import httpx
import pytest
from fastapi import FastAPI

from api.sensors import SensorFilter, split_sensors

app = FastAPI()


@app.get("/t")
async def t(sensor: SensorFilter = None) -> dict[str, list[str] | None]:
    return {"sensor": None if sensor is None else [str(s) for s in sensor]}


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("", None),
        ("sensor=ssh", ["ssh"]),
        ("sensor=ssh&sensor=telnet", ["ssh", "telnet"]),
        ("sensor=ssh,telnet", ["ssh", "telnet"]),
        ("sensor=ssh,telnet&sensor=redis&sensor=ssh", ["ssh", "telnet", "redis"]),
        ("sensor=", None),
        ("sensor=%20ssh%20,", ["ssh"]),
    ],
)
async def test_accepted_forms(query: str, expected: list[str] | None) -> None:
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get(f"/t?{query}")
    assert r.status_code == 200, r.text
    assert r.json() == {"sensor": expected}


@pytest.mark.parametrize("query", ["sensor=ftp", "sensor=ssh,ftp", "sensor=ssh&sensor=nope"])
async def test_unknown_sensor_is_422(query: str) -> None:
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.get(f"/t?{query}")).status_code == 422


def test_split_sensors_is_pure() -> None:
    assert split_sensors(None) is None
    assert split_sensors("a,b") == ["a", "b"]
    assert split_sensors([]) is None

"""When attacks happen: diurnal and weekly rhythm plus a few scripted bursts."""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from suckerpot_common import SensorName

SENSORS = (
    SensorName.ssh,
    SensorName.web,
    SensorName.telnet,
    SensorName.rdp,
    SensorName.redis,
    SensorName.docker,
    SensorName.mysql,
    SensorName.adb,
    SensorName.mssql,
    SensorName.smb,
    SensorName.sip,
)
# Relative weights of the seven service sensors (redis, docker, mysql, adb, mssql, smb, sip).
SERVICE_WEIGHTS = (0.18, 0.14, 0.14, 0.12, 0.12, 0.18, 0.12)
SERVICE_SHARE = 0.25  # share of all sessions that hit the service sensors in a normal period
Mix = tuple[float, float, float, float, float, float, float, float, float, float, float]


def expand_mix(core: tuple[float, float, float, float], service_share: float) -> Mix:
    """Scale the (ssh, web, telnet, rdp) mix down and append the service sensors."""
    c = [x * (1 - service_share) for x in core]
    s = [w * service_share for w in SERVICE_WEIGHTS]
    return (*c, *s)  # type: ignore[return-value]


BASE_MIX = expand_mix((0.50, 0.25, 0.15, 0.10), SERVICE_SHARE)
PHP2SHELL_WINDOW = timedelta(days=3)  # since the CVE disclosure
_WEEKDAY = (1.00, 1.05, 1.10, 1.00, 0.95, 0.80, 0.75)


@dataclass(frozen=True)
class Context:
    weight: float
    mix: Mix  # ssh, web, telnet, rdp, then the service sensors
    botnet_wave: bool
    ssh_campaign: bool
    php2shell_p: float


class Schedule:
    def __init__(self, seed: int, now: datetime, days: int) -> None:
        self.seed = seed
        self.now = now
        self.days = days
        wave_ago = max(1, round(days * 0.4))
        self._wave_start = self._at(now - timedelta(days=wave_ago), 6)
        self._wave_end = self._wave_start + timedelta(hours=8)
        self._camp_start: datetime | None = None
        if days >= 5:
            self._camp_start = self._at(now - timedelta(days=round(days * 0.65)), 1)
        self._php_start = now - PHP2SHELL_WINDOW

    @staticmethod
    def _at(day: datetime, hour: int) -> datetime:
        return day.replace(hour=hour, minute=0, second=0, microsecond=0)

    def _jitter(self, when: datetime) -> float:
        return random.Random(self.seed * 100_003 + when.toordinal()).uniform(0.8, 1.2)

    def context(self, when: datetime) -> Context:
        when = when.astimezone(UTC)
        hour = when.hour + when.minute / 60
        weight = (1 + 0.45 * math.cos(2 * math.pi * (hour - 3) / 24)) * _WEEKDAY[when.weekday()]
        weight *= self._jitter(when)
        mix = BASE_MIX
        wave = self._wave_start <= when < self._wave_end
        camp = self._camp_start is not None and self._camp_start <= when < (
            self._camp_start + timedelta(hours=5)
        )
        php_p = 0.0
        if wave:
            weight *= 4.5
            mix = expand_mix((0.10, 0.07, 0.80, 0.03), 0.05)
        elif camp:
            weight *= 2.5
            mix = expand_mix((0.82, 0.08, 0.05, 0.05), 0.08)
        elif when >= self._php_start:
            weight *= 1.6
            mix = expand_mix((0.40, 0.40, 0.12, 0.08), 0.15)
            php_p = 0.5
        return Context(weight, mix, wave, camp, php_p)

    def sample_starts(self, rng: random.Random, n: int) -> list[datetime]:
        """n session start times in [now - days, now), shaped by hourly weights."""
        total_hours = self.days * 24
        first = self.now - timedelta(hours=total_hours)
        slots = [first + timedelta(hours=i) for i in range(total_hours)]
        weights = [self.context(s + timedelta(minutes=30)).weight for s in slots]
        picks = rng.choices(range(total_hours), weights, k=n)
        return sorted(slots[i] + timedelta(seconds=rng.uniform(0, 3600)) for i in picks)

"""Turns plans into validated Events with consistent session ids, IPs and timing."""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

from suckerpot_common import Event, SensorName

from demo.ips import random_public_ip
from demo.plans import Plan, build_rdp, build_ssh, build_telnet, build_web, pick
from demo.plans_services import (
    build_adb,
    build_docker,
    build_mssql,
    build_mysql,
    build_redis,
    build_sip,
    build_smb,
    build_synology,
)
from demo.schedule import SENSORS, Context, Schedule

CORE_SENSORS = (SensorName.ssh, SensorName.web, SensorName.telnet, SensorName.rdp)
SERVICE_BUILDERS = {
    SensorName.redis: build_redis,
    SensorName.docker: build_docker,
    SensorName.mysql: build_mysql,
    SensorName.adb: build_adb,
    SensorName.mssql: build_mssql,
    SensorName.smb: build_smb,
    SensorName.sip: build_sip,
    SensorName.synology: build_synology,
}


class Generator:
    def __init__(self, *, seed: int, now: datetime, days: int) -> None:
        self.now = now.astimezone(UTC)
        self.days = days
        self.rng = random.Random(seed)
        self.schedule = Schedule(seed, self.now, days)
        self._ids: set[str] = set()
        rng = self.rng
        # Repeat offenders come back often and across several sensors.
        self.repeaters = [random_public_ip(rng) for _ in range(60)]
        self._affinity = {
            ip: set(rng.sample(SENSORS, rng.choice([1, 2, 2, 3, 4]))) for ip in self.repeaters
        }
        self.regulars = [random_public_ip(rng) for _ in range(120)]
        self.campaign = [random_public_ip(rng) for _ in range(14)]
        # A few persistent heavy hitters per service sensor (the same scanners come back daily).
        self.heavy = {
            s: [random_public_ip(rng) for _ in range(3)] for s in SENSORS[len(CORE_SENSORS) :]
        }

    # -- source IP selection

    def _pick_ip(self, sensor: SensorName, ctx: Context) -> str:
        rng = self.rng
        if ctx.ssh_campaign and sensor is SensorName.ssh and rng.random() < 0.75:
            return rng.choice(self.campaign)
        if ctx.botnet_wave and sensor is SensorName.telnet:
            return random_public_ip(rng)
        if sensor in self.heavy and rng.random() < 0.3:
            ips = self.heavy[sensor]
            return rng.choices(ips, [1 / (i + 1) for i in range(len(ips))])[0]
        r = rng.random()
        if r < 0.28:
            cands = [ip for ip in self.repeaters if sensor in self._affinity[ip]]
            if cands:
                # Zipf-like: the first repeaters are much busier than the last.
                return rng.choices(cands, [1 / (i + 1) for i in range(len(cands))])[0]
        elif r < 0.40:
            return rng.choice(self.regulars)
        return random_public_ip(rng)

    def _session_id(self) -> str:
        while True:
            sid = f"{self.rng.getrandbits(64):016x}"
            if sid not in self._ids:
                self._ids.add(sid)
                return sid

    # -- plans

    def plan_at(self, when: datetime) -> Plan:
        ctx = self.schedule.context(when)
        sensor = pick(self.rng, list(zip(SENSORS, ctx.mix, strict=True)))
        ip = self._pick_ip(sensor, ctx)
        rng = self.rng
        if sensor is SensorName.ssh:
            return build_ssh(rng, ip)
        if sensor is SensorName.web:
            return build_web(rng, ip, php2shell_p=ctx.php2shell_p)
        if sensor is SensorName.telnet:
            return build_telnet(rng, ip, wave=ctx.botnet_wave)
        if sensor is SensorName.rdp:
            return build_rdp(rng, ip)
        return SERVICE_BUILDERS[sensor](rng, ip)

    def events_for(self, plan: Plan, start: datetime) -> list[Event]:
        sid = self._session_id()
        return [
            Event(
                ts=start + timedelta(seconds=s.offset),
                sensor=plan.sensor,
                session_id=sid,
                src_ip=plan.src_ip,  # type: ignore[arg-type]
                src_port=plan.src_port,
                dst_port=plan.dst_port,
                type=s.type,
                # Marks the event as demo data: indicators taken from it are never sent to an
                # intel service.
                data={**s.data, "demo": True},
            )
            for s in plan.steps
        ]

    def backfill(self, sessions: int) -> list[Event]:
        """All events for ``sessions`` sessions inside the window, in chronological order."""
        window_start = self.now - timedelta(days=self.days)
        events: list[Event] = []
        for start in self.schedule.sample_starts(self.rng, sessions):
            plan = self.plan_at(start)
            latest = self.now - timedelta(seconds=plan.duration + 0.001)
            start = max(window_start, min(start, latest))
            events.extend(self.events_for(plan, start))
        events.sort(key=lambda e: e.ts)
        return events

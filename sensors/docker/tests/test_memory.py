"""Memory guard, cgroup reading and budget refusals."""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path

from conftest import start

from docker_sensor.memguard import MemoryGuard


def _cgroup(tmp: Path, current: int, maximum: str, inactive: int = 0) -> Path:
    (tmp / "memory.current").write_text(str(current))
    (tmp / "memory.max").write_text(maximum)
    (tmp / "memory.stat").write_text(f"anon 1\ninactive_file {inactive}\n")
    return tmp


def test_guard_reads_cgroup_and_subtracts_page_cache(tmp_path: Path) -> None:
    mib = 1024 * 1024
    guard = MemoryGuard(1 << 40, cgroup=_cgroup(tmp_path, 180 * mib, str(256 * mib), 40 * mib))
    assert guard.source == "cgroup" and guard.limit == 256 * mib
    assert guard.read() == 140 * mib
    assert guard.sample() is False and guard.refusing is False  # 140 < 70 % of 256 = 179
    (tmp_path / "memory.current").write_text(str(230 * mib))
    assert guard.sample() is False and guard.refusing is True  # 190 MiB
    (tmp_path / "memory.current").write_text(str(265 * mib))
    assert guard.sample() is True  # 225 MiB > 85 %
    assert guard.excess() > 0


def test_guard_without_limit_uses_fallback(tmp_path: Path) -> None:
    guard = MemoryGuard(100, cgroup=_cgroup(tmp_path, 10, "max"))
    assert guard.limit == 100


async def test_refusing_guard_rejects_new_connections(tmp_path: Path) -> None:
    mib = 1024 * 1024
    guard = MemoryGuard(1 << 40, cgroup=_cgroup(tmp_path, 200 * mib, str(256 * mib)))
    guard.sample()
    async with start({"guard": guard}) as h:
        r, w = await asyncio.open_connection("127.0.0.1", h.port)
        w.write(b"GET /_ping HTTP/1.1\r\nHost: x\r\n\r\n")
        assert await asyncio.wait_for(r.read(100), 3) == b""
        assert h.sensor.rejected == 1 and guard.refused == 1


async def test_shedding_aborts_the_fattest_connections(tmp_path: Path) -> None:
    mib = 1024 * 1024
    cg = _cgroup(tmp_path, 10 * mib, str(256 * mib))
    guard = MemoryGuard(1 << 40, cgroup=cg)
    async with start({"guard": guard, "max_per_ip": 50}) as h:
        socks = []
        for _ in range(6):
            s = socket.create_connection(("127.0.0.1", h.port))
            s.sendall(
                b"POST /containers/create HTTP/1.1\r\nHost: x\r\nContent-Length: 90000\r\n\r\n{"
            )
            socks.append(s)
        await asyncio.sleep(0.3)
        (cg / "memory.current").write_text(str(240 * mib))
        assert h.sensor.check_memory() >= 1
        assert guard.aborted >= 1
        await asyncio.sleep(0.3)
        for s in socks:
            s.close()


async def test_loopback_healthcheck_is_never_refused(tmp_path: Path) -> None:
    mib = 1024 * 1024
    guard = MemoryGuard(1 << 40, cgroup=_cgroup(tmp_path, 250 * mib, str(256 * mib)))
    guard.sample()
    async with start({"guard": guard, "quiet_loopback": True}) as h:
        status, _, body = await h.http("GET", "/_ping")
        assert (status, body) == (200, b"OK")
        assert h.sensor.rejected == 0

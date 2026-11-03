"""The worker refuses to start with a proxy set and a default route present."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hub import admin, egress_check

HEADER = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
DEFAULT = "eth0\t00000000\t0100A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
LOCAL = "eth0\t0000A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"


def _file(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "route"
    path.write_text(HEADER + body, encoding="ascii")
    return path


def test_default_route_is_detected(tmp_path: Path) -> None:
    assert egress_check.has_default_route(_file(tmp_path, LOCAL + DEFAULT)) is True
    assert egress_check.has_default_route(_file(tmp_path, LOCAL)) is False
    assert egress_check.has_default_route(tmp_path / "missing") is None


def test_refuses_only_with_a_proxy_and_a_default_route(tmp_path: Path) -> None:
    with_default = _file(tmp_path, DEFAULT)
    assert not egress_check.egress_ok("http://proxy.example.org:8888", with_default)
    assert egress_check.egress_ok(None, with_default)  # no proxy: the direct mode
    assert egress_check.egress_ok(
        "http://proxy.example.org:8888", _file(tmp_path, LOCAL), tmp_path / "no-ipv6"
    )
    assert egress_check.CODE == "egress_default_route"


ZEROS = "0" * 32
V6_HEADER_LINES = (
    # a real default route, and the kernel's reject entry, which does not count
    f"{ZEROS} 00 {ZEROS} 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n"
)
V6_REJECT = f"{ZEROS} 00 {ZEROS} 00 {ZEROS} ffffffff 00000001 00000000 00200200 lo\n"


def test_ipv6_default_route_is_detected_and_reject_entries_are_not(tmp_path: Path) -> None:
    v4 = _file(tmp_path, LOCAL)
    v6 = tmp_path / "route6"
    v6.write_text(V6_REJECT, encoding="ascii")
    assert egress_check.egress_ok("http://proxy.example.org:8888", v4, v6)
    v6.write_text(V6_REJECT + V6_HEADER_LINES, encoding="ascii")
    assert not egress_check.egress_ok("http://proxy.example.org:8888", v4, v6)
    assert egress_check.egress_ok("http://proxy.example.org:8888", v4, tmp_path / "no-ipv6")


def test_an_unreadable_table_fails_closed_only_with_a_proxy(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    assert not egress_check.egress_ok("http://proxy.example.org:8888", missing)
    assert egress_check.egress_ok(None, missing)


async def test_online_admin_command_refuses_with_a_proxy_and_a_default_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(egress_check, "ROUTE_FILE", _file(tmp_path, DEFAULT))
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.org:8888")
    engine = create_async_engine("postgresql+asyncpg://nobody@localhost/none")  # never connects
    lines: list[str] = []
    code = await admin.run(
        ["ranges", "refresh"],
        sessionmaker=async_sessionmaker(engine),
        out=lines.append,
        actor="op",
    )
    await engine.dispose()
    assert code == 1 and lines == [egress_check.CODE]

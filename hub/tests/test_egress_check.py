"""The worker refuses to start with a proxy set and a default route present."""

from __future__ import annotations

from pathlib import Path

from hub import egress_check

HEADER = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
DEFAULT = "eth0\t00000000\t0100A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
LOCAL = "eth0\t0000A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"


def _file(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "route"
    path.write_text(HEADER + body, encoding="ascii")
    return path


def test_default_route_is_detected(tmp_path: Path) -> None:
    assert egress_check.has_default_route(_file(tmp_path, LOCAL + DEFAULT))
    assert not egress_check.has_default_route(_file(tmp_path, LOCAL))
    assert not egress_check.has_default_route(tmp_path / "missing")


def test_refuses_only_with_a_proxy_and_a_default_route(tmp_path: Path) -> None:
    with_default = _file(tmp_path, DEFAULT)
    assert not egress_check.egress_ok("http://proxy.example.org:8888", with_default)
    assert egress_check.egress_ok(None, with_default)  # no proxy: the direct mode
    assert egress_check.egress_ok("http://proxy.example.org:8888", _file(tmp_path, LOCAL))
    assert egress_check.CODE == "egress_default_route"

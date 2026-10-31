import pytest

from suckerpot_egress import EgressSettings, selftest
from tests.helpers import FakeProxy


def test_refused_true_for_refusal() -> None:
    p = FakeProxy(answer=403)
    try:
        s = EgressSettings(proxy_url=f"http://127.0.0.1:{p.port}", proxy_password="x" * 24)
        assert (
            selftest.refused(s, "10.0.0.5:8000") is True  # gitleaks:allow
        )
        assert p.requests[0].startswith(
            "CONNECT 10.0.0.5:8000"  # gitleaks:allow
        )
    finally:
        p.close()


def test_refused_false_when_proxy_connects() -> None:
    p = FakeProxy(upstream=("127.0.0.1", 9))
    try:
        s = EgressSettings(proxy_url=f"http://127.0.0.1:{p.port}", proxy_password="x" * 24)
        # upstream refuses at the TCP level inside the proxy; the proxy thread dies after 200 is
        # never sent, so this is still a refusal
        assert selftest.refused(s, "example.test:80") is True
    finally:
        p.close()


def test_exit_code_and_lines(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(selftest, "tcp_fails", lambda h, p: True)
    monkeypatch.setattr(selftest, "udp_dns_unanswered", lambda s: True)
    monkeypatch.setattr(selftest, "resolve_fails", lambda n: False)
    assert selftest.main(["--direct"]) == 1
    out = capsys.readouterr().out
    assert "PASS direct tcp 1.1.1.1:443 fails" in out
    assert "FAIL getaddrinfo example.com fails" in out

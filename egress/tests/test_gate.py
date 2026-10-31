import httpx
import pytest

from suckerpot_egress import EgressClosed
from tests.helpers import VPN_IP, Clock, fake_world, gate_for


async def run(**world: object) -> tuple[bool, str, str | None]:
    gate = gate_for(fake_world(**world))  # type: ignore[arg-type]
    st = await gate.check()
    return st.open, st.reason, st.egress_ip


async def test_ok() -> None:
    assert await run() == (True, "ok", VPN_IP)


async def test_initially_closed() -> None:
    gate = gate_for(fake_world())
    assert gate.status.reason == "not_checked"
    with pytest.raises(EgressClosed) as exc:
        gate.require_open()
    assert exc.value.code == "not_checked"


async def test_no_vpn() -> None:
    assert (await run(vpn=None))[:2] == (False, "no_vpn")


@pytest.mark.parametrize("state", ["stopped", "", "crashed"])
async def test_tunnel_down(state: str) -> None:
    assert (await run(vpn=state))[:2] == (False, "tunnel_down")


async def test_tunnel_down_on_error_status() -> None:
    assert (await run(vpn_status_code=401))[:2] == (False, "tunnel_down")


async def test_no_public_ip() -> None:
    assert (await run(public_ip=None))[:2] == (False, "no_public_ip")


async def test_echo_failed_when_one_answers() -> None:
    echo = {"echo-a.test": VPN_IP, "echo-b.test": None}
    assert (await run(echo=echo))[:2] == (False, "echo_failed")


async def test_echo_failed_on_garbage() -> None:
    echo = {"echo-a.test": "<html>", "echo-b.test": "<html>"}
    assert (await run(echo=echo))[:2] == (False, "echo_failed")


async def test_echo_disagree() -> None:
    echo = {"echo-a.test": VPN_IP, "echo-b.test": "9.9.9.78"}
    assert (await run(echo=echo))[:2] == (False, "echo_disagree")


async def test_ip_mismatch() -> None:
    echo = {"echo-a.test": "9.9.8.9", "echo-b.test": "9.9.8.9"}
    assert await run(echo=echo) == (False, "ip_mismatch", "9.9.8.9")


async def test_ip_not_global() -> None:
    echo = {
        "echo-a.test": "10.0.0.5",  # gitleaks:allow
        "echo-b.test": "10.0.0.5",  # gitleaks:allow
    }
    open_, reason, _ = await run(
        echo=echo,
        public_ip="10.0.0.5",  # gitleaks:allow
    )
    assert (open_, reason) == (False, "ip_not_global")


async def test_ip_not_allowed_shows_observed_ip() -> None:
    gate = gate_for(fake_world(), allowed_cidrs=())
    st = await gate.check()
    assert (st.open, st.reason, st.egress_ip) == (False, "ip_not_allowed", VPN_IP)


async def test_oversize_echo_body_is_a_failure() -> None:
    big = "1" * 200
    assert (await run(echo={"echo-a.test": big, "echo-b.test": big}))[:2] == (False, "echo_failed")


async def test_check_error_is_a_closed_gate() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise RuntimeError("secret detail")

    st = await gate_for(boom).check()
    assert (st.open, st.reason) == (False, "check_error")


async def test_gate_goes_stale() -> None:
    clock = Clock()
    gate = gate_for(fake_world(), clock)
    await gate.check()
    gate.require_open()
    clock.advance(gate.settings.check_interval_s * 2 + 1)
    with pytest.raises(EgressClosed) as exc:
        gate.require_open()
    assert exc.value.code == "stale"


async def test_three_proxy_errors_wake_the_loop() -> None:
    gate = gate_for(fake_world())
    gate.note_proxy_error()
    gate.note_proxy_error()
    assert not gate._wake.is_set()
    gate.note_proxy_error()
    assert gate._wake.is_set()


async def test_closes_again_after_failure() -> None:
    state = {"vpn": "running"}

    def handler(request: httpx.Request) -> httpx.Response:
        return fake_world(vpn=state["vpn"])(request)

    gate = gate_for(handler)
    assert (await gate.check()).open
    state["vpn"] = "stopped"
    assert not (await gate.check()).open
    with pytest.raises(EgressClosed):
        gate.require_open()


async def test_run_publishes_every_check_and_survives_a_failing_publisher() -> None:
    import asyncio

    gate = gate_for(fake_world())
    seen: list[str] = []

    async def publish(status: object) -> None:
        seen.append(getattr(status, "reason", ""))
        if len(seen) == 1:
            raise RuntimeError("db down")
        raise asyncio.CancelledError

    gate._wake.set()
    task = asyncio.create_task(gate.run(publish))
    await asyncio.sleep(0.05)
    assert seen[:1] == ["ok"]  # the first publish failed; the loop went on
    gate._wake.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert seen == ["ok", "ok"]

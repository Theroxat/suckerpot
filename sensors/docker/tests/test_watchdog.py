import asyncio
import threading
import time

from docker_sensor.watchdog import LoopWatchdog


async def test_watchdog_fires_when_loop_blocks() -> None:
    fired = threading.Event()
    lag: list[float] = []

    def stalled(x: float) -> None:
        lag.append(x)
        fired.set()

    wd = LoopWatchdog(limit=0.5, interval=0.1, on_stall=stalled)
    wd.start()
    await asyncio.sleep(0.3)
    assert not fired.is_set()
    time.sleep(1.0)  # block the loop on purpose  # noqa: ASYNC251
    assert fired.wait(2) and lag[0] > 0.5
    wd.stop()


async def test_watchdog_quiet_when_loop_is_healthy() -> None:
    fired = threading.Event()
    wd = LoopWatchdog(limit=0.5, interval=0.1, on_stall=lambda x: fired.set())
    wd.start()
    await asyncio.sleep(1.2)
    wd.stop()
    assert not fired.is_set()

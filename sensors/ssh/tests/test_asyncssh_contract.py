"""Contract with asyncssh internals.

The flow-control and metering code in ``ssh_sensor.server`` swaps ``__class__`` on live
asyncssh objects and reads private attributes. If an asyncssh release renames or reshapes any
of them, these tests fail on purpose so the flow control gets re-verified before shipping.
asyncssh is therefore pinned to an exact version in ``pyproject.toml``.
"""

from __future__ import annotations

import inspect
from typing import Any

import asyncssh
import asyncssh.channel
import pytest

from ssh_sensor import server as server_mod

HINT = "asyncssh internals changed: re-verify flow control"


def _params(func: Any) -> list[str]:
    return list(inspect.signature(func).parameters)


def test_swapped_classes_keep_the_same_layout() -> None:
    for base, sub in (
        (asyncssh.SSHServerConnection, server_mod._MeteredConnection),
        (asyncssh.SSHServerChannel, server_mod._FlowControlledChannel),
    ):
        assert sub.__mro__[1] is base or base in sub.__mro__, HINT
        assert sub.__basicsize__ == base.__basicsize__, f"{HINT} ({sub.__name__} layout differs)"
        assert "__slots__" not in sub.__dict__, f"{HINT} ({sub.__name__} must not add slots)"
        assert "__dict__" in dir(base) or hasattr(base, "__dict__"), HINT


def test_overridden_methods_exist_with_the_same_shape() -> None:
    assert _params(asyncssh.SSHServerConnection.data_received) == [
        "self",
        "data",
        "datatype",
    ], HINT
    for name in ("_accept_data", "_deliver_data"):
        original = getattr(asyncssh.SSHServerChannel, name, None)
        assert callable(original), f"{HINT}: SSHServerChannel.{name} is gone"
        assert _params(original)[:3] == ["self", "data", "datatype"], f"{HINT}: {name} changed"


def test_channel_init_still_sets_the_receive_state() -> None:
    source = inspect.getsource(asyncssh.channel.SSHChannel.__init__)
    for attr in ("_recv_buf", "_recv_window", "_recv_paused"):
        assert f"self.{attr}" in source, f"{HINT}: SSHChannel no longer sets {attr}"


def test_deliver_data_still_reopens_the_window() -> None:
    source = inspect.getsource(asyncssh.channel.SSHChannel._deliver_data)
    assert "_recv_window" in source or "_flow_control" in source, HINT
    accept = inspect.getsource(asyncssh.channel.SSHChannel._accept_data)
    assert "_recv_buf" in accept and "_recv_paused" in accept, HINT


async def test_live_objects_expose_the_expected_attributes(make_harness) -> None:  # type: ignore[no-untyped-def]
    async with make_harness() as h:
        client = await h.connect()
        proc = await client.create_process(term_type="xterm")
        owner = next(iter(h.sensor.connections))
        conn = owner.conn
        assert conn is not None
        transport = getattr(conn, "_transport", None)
        assert transport is not None, f"{HINT}: connection has no _transport"
        for method in ("pause_reading", "resume_reading", "is_closing"):
            assert callable(getattr(transport, method, None)), f"{HINT}: transport.{method}"
        assert isinstance(conn, server_mod._MeteredConnection), HINT
        channels = [c for c in getattr(conn, "_channels", {}).values()]
        assert channels, f"{HINT}: connection._channels is gone"
        chan = next(c for c in channels if isinstance(c, asyncssh.SSHServerChannel))
        assert isinstance(chan, server_mod._FlowControlledChannel), HINT
        assert isinstance(chan._recv_buf, list), f"{HINT}: _recv_buf is no longer a list"
        assert isinstance(chan._recv_window, int), HINT
        assert isinstance(chan._recv_paused, bool), HINT
        proc.close()
        client.close()


def test_hint_is_loud() -> None:
    with pytest.raises(AssertionError, match="re-verify flow control"):
        raise AssertionError(HINT)

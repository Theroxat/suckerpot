from __future__ import annotations

import asyncio
import contextlib
import hashlib
import socket
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, replace

import pytest
from suckerpot_common import Event

from sip_sensor.config import Config
from sip_sensor.events import EventSink, Tracker
from sip_sensor.handler import Handler
from sip_sensor.identity import Profile, derive_profile
from sip_sensor.memguard import MemoryGuard
from sip_sensor.server import Sensor, SipServer


class FakePublisher:
    def __init__(self) -> None:
        self.events: list[Event] = []

    async def publish(self, event: Event) -> bool:
        self.events.append(event)
        return True

    async def close(self) -> None:
        return None


@dataclass
class Harness:
    port: int  # UDP port
    tcp_port: int
    publisher: FakePublisher
    sensor: Sensor
    sink: EventSink
    tracker: Tracker
    cfg: Config
    profile: Profile

    async def events(self, type_: str | None = None) -> list[Event]:
        await asyncio.sleep(0.05)
        await self.sink.flush()
        return [e for e in self.publisher.events if type_ is None or e.type == type_]

    async def close_sessions(self) -> None:
        self.tracker.close_all("test")


@pytest.fixture(scope="session")
def profile() -> Profile:
    return derive_profile("ab" * 32)


HarnessFactory = Callable[..., contextlib.AbstractAsyncContextManager[Harness]]


def make_sensor(profile: Profile, guard: MemoryGuard | None = None, **overrides: object):  # type: ignore[no-untyped-def]
    params: dict[str, object] = {
        "host": "127.0.0.1",
        "port": 0,
        "quiet_loopback": False,
        "sessions_per_sec_per_ip": 1000.0,
        "sessions_burst_per_ip": 1000.0,
        **overrides,
    }
    cfg = replace(Config(), **params)  # type: ignore[arg-type]
    pub = FakePublisher()
    sink = EventSink(pub, dst_port=5060)
    tracker = Tracker(
        sink,
        per_ip_rate=cfg.sessions_per_sec_per_ip,
        per_ip_burst=cfg.sessions_burst_per_ip,
        global_rate=cfg.global_sessions_per_sec,
        max_sessions=cfg.max_sessions,
        idle=cfg.session_idle,
        quota_priority=cfg.quota_priority,
        quiet_loopback=cfg.quiet_loopback,
    )
    sensor = Sensor(cfg, Handler(cfg, profile, tracker), tracker, guard)
    return cfg, pub, sink, tracker, sensor


@pytest.fixture
def make_harness(profile: Profile) -> HarnessFactory:
    @contextlib.asynccontextmanager
    async def factory(
        guard: MemoryGuard | None = None, **overrides: object
    ) -> AsyncIterator[Harness]:
        cfg, pub, sink, tracker, sensor = make_sensor(profile, guard, **overrides)
        sink.start()
        server = SipServer(cfg, sensor)
        await server.start()
        try:
            yield Harness(
                server.udp_port, server.tcp_port, pub, sensor, sink, tracker, cfg, profile
            )
        finally:
            await server.stop()
            await sink.close()

    return factory


# --- message helpers --------------------------------------------------------------------


def sip_request(
    method: str = "OPTIONS",
    uri: str = "sip:100@192.0.2.10",
    *,
    call_id: str = "abc123@198.51.100.7",
    cseq: int = 1,
    ua: str | None = "friendly-scanner",
    extra: tuple[str, ...] = (),
    body: str = "",
    to: str | None = None,
    from_: str | None = None,
) -> bytes:
    lines = [
        f"{method} {uri} SIP/2.0",
        "Via: SIP/2.0/UDP 198.51.100.7:5060;branch=z9hG4bK-1234;rport",
        "Max-Forwards: 70",
        f"From: {from_ or '<sip:100@192.0.2.10>'};tag=3a9b",
        f"To: {to or '<sip:100@192.0.2.10>'}",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq} {method}",
        "Contact: <sip:100@198.51.100.7:5060>",
    ]
    if ua:
        lines.append(f"User-Agent: {ua}")
    lines += list(extra)
    lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode()


def minimal_request(method: str = "OPTIONS") -> bytes:
    """About the smallest legal request: the worst case for amplification."""
    return (
        f"{method} sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP 1.2.3.4;branch=z\r\n"
        f"From: <sip:a@b>;tag=1\r\nTo: <sip:a@b>\r\nCall-ID: 1\r\nCSeq: 1 {method}\r\n\r\n"
    ).encode()


def md5(text: str) -> str:
    return hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()


def digest_header(
    user: str, password: str, realm: str, nonce: str, method: str, uri: str, *, qop: bool = False
) -> str:
    ha1 = md5(f"{user}:{realm}:{password}")
    ha2 = md5(f"{method}:{uri}")
    if qop:
        resp = md5(f"{ha1}:{nonce}:00000001:abcd:auth:{ha2}")
        extra = ', qop=auth, nc=00000001, cnonce="abcd"'
    else:
        resp = md5(f"{ha1}:{nonce}:{ha2}")
        extra = ""
    return (
        f'Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", '
        f'response="{resp}", algorithm=MD5{extra}'
    )


def header_value(reply: bytes, name: str) -> str:
    for line in reply.decode("latin-1").split("\r\n"):
        if line.lower().startswith(name.lower() + ":"):
            return line.split(":", 1)[1].strip()
    return ""


def param(value: str, key: str) -> str:
    marker = f'{key}="'
    start = value.index(marker) + len(marker)
    return value[start : value.index('"', start)]


async def udp_exchange(port: int, payload: bytes, wait: float = 0.4, count: int = 1) -> list[bytes]:
    """Send ``payload`` and collect the datagrams that come back within ``wait`` seconds."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    out: list[bytes] = []
    try:
        for _ in range(count):
            await loop.sock_sendto(sock, payload, ("127.0.0.1", port))
        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(wait):
                while True:
                    data, _ = await loop.sock_recvfrom(sock, 65535)
                    out.append(data)
    finally:
        sock.close()
    return out

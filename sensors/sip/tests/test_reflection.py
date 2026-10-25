"""Anti-reflection: replies never exceed the request, rates and sources are gated."""

from __future__ import annotations

import itertools
import random
import time
from dataclasses import replace

import pytest

from sip_sensor.config import Config
from sip_sensor.guard import ReplyGate, source_allowed
from tests.conftest import (
    HarnessFactory,
    make_sensor,
    minimal_request,
    sip_request,
    udp_exchange,
)

METHODS = ("OPTIONS", "REGISTER", "INVITE", "BYE", "CANCEL", "SUBSCRIBE", "MESSAGE", "FOOBAR")


def corpus() -> list[bytes]:
    out: list[bytes] = []
    for method in METHODS:
        out.append(minimal_request(method))
        out.append(sip_request(method))
        out.append(sip_request(method, ua=None))
        out.append(sip_request(method, uri="sip:0041791234567@gw.example.net", body="v=0\r\n" * 20))
    out.append(sip_request("REGISTER", extra=('Authorization: Digest username="100", realm="x"',)))
    out.append(minimal_request("REGISTER").replace(b"Via: ", b"v: "))  # compact header form
    return out


def test_every_reply_is_not_larger_than_its_request(profile) -> None:  # type: ignore[no-untyped-def]
    """Amplification factor over a flood of every request shape: bytes out / bytes in <= 1."""
    cfg, _pub, _sink, _tracker, sensor = make_sensor(
        profile, allow_private=True, reply_per_ip_rate=1e9, reply_per_ip_burst=1e9,
        reply_global_rate=1e9, reply_global_burst=1e9, reply_bytes_rate=1e12,
        reply_bytes_burst=1e12, pps_per_ip=1e9, pps_per_ip_burst=1e9, pps_global=1e9,
        pps_global_burst=1e9,
    )  # fmt: skip
    total_in = total_out = replies = 0
    worst = 0.0
    for i, raw in enumerate(itertools.islice(itertools.cycle(corpus()), 4000)):
        ip = f"198.51.100.{i % 250 + 1}"
        out = sensor.on_datagram(raw, (ip, 5060))
        total_in += len(raw)
        if out is not None:
            replies += 1
            total_out += len(out)
            worst = max(worst, len(out) / len(raw))
            assert len(out) <= len(raw), (raw, out)
    factor = total_out / total_in
    print(f"\namplification: {replies} replies, {total_in} B in, {total_out} B out, "
          f"factor {factor:.3f}, worst single {worst:.3f}")  # fmt: skip
    assert replies > 1000  # the gate is not simply silent
    assert factor <= 1.0 and worst <= 1.0


def test_minimal_requests_get_no_bigger_reply(profile) -> None:  # type: ignore[no-untyped-def]
    _cfg, _pub, _sink, _tracker, sensor = make_sensor(profile, allow_private=True)
    for method in METHODS:
        raw = minimal_request(method)
        out = sensor.on_datagram(raw, ("198.51.100.9", 5060))
        assert out is None or len(out) <= len(raw), method


def test_flood_from_one_source_is_rate_limited(profile) -> None:  # type: ignore[no-untyped-def]
    _cfg, _pub, _sink, _tracker, sensor = make_sensor(profile, allow_private=True)
    replies = 0
    started = time.monotonic()
    for _ in range(2000):
        if sensor.on_datagram(sip_request("OPTIONS"), ("198.51.100.9", 5060)):
            replies += 1
    elapsed = time.monotonic() - started
    # per source: burst 5 plus 2/s (and the packets-per-second bucket cuts the input first)
    assert replies <= 5 + int(2 * elapsed) + 1


def test_spoofed_source_flood_respects_global_cap(profile) -> None:  # type: ignore[no-untyped-def]
    """Thousands of distinct (spoofed) sources: the global reply cap bounds the total."""
    cfg, _pub, _sink, _tracker, sensor = make_sensor(
        profile, allow_private=True, reply_global_rate=100.0, reply_global_burst=200.0,
        reply_bytes_rate=1e9, reply_bytes_burst=1e9, pps_global=1e9, pps_global_burst=1e9,
    )  # fmt: skip
    rng = random.Random(7)
    replies = 0
    out_bytes = in_bytes = 0
    started = time.monotonic()
    for _ in range(20000):
        ip = f"203.0.{rng.randrange(0, 255)}.{rng.randrange(1, 255)}"
        raw = sip_request("OPTIONS")
        in_bytes += len(raw)
        out = sensor.on_datagram(raw, (ip, rng.randrange(1024, 65535)))
        if out:
            replies += 1
            out_bytes += len(out)
    elapsed = time.monotonic() - started
    assert replies <= 200 + int(100 * elapsed) + 2
    assert replies < 1000
    assert out_bytes / in_bytes <= 0.1


def test_global_byte_cap_holds(profile) -> None:  # type: ignore[no-untyped-def]
    _cfg, _pub, _sink, _tracker, sensor = make_sensor(
        profile, allow_private=True, reply_bytes_rate=10_000.0, reply_bytes_burst=20_000.0,
        reply_global_burst=1e9, reply_global_rate=1e9, pps_global=1e9, pps_global_burst=1e9,
    )  # fmt: skip
    out_bytes = 0
    started = time.monotonic()
    for i in range(10000):
        out = sensor.on_datagram(sip_request("OPTIONS"), (f"203.0.{i % 200}.{i % 250 + 1}", 5060))
        out_bytes += len(out or b"")
    assert out_bytes <= 20_000 + 10_000 * (time.monotonic() - started) + 600


@pytest.mark.parametrize(
    "ip",
    [
        "10.1.2.3", "192.168.1.1", "172.16.5.5", "169.254.1.1", "224.0.0.251", "239.1.1.1",  # gitleaks:allow - RFC 1918 / link-local literals ARE the test: bogon sources get no reply
        "255.255.255.255", "0.0.0.0", "240.0.0.1", "100.64.0.1", "192.0.2.5", "198.51.100.5",
        "203.0.113.5", "198.18.0.1", "::", "fe80::1", "ff02::1", "fc00::1", "2001:db8::1",
        "not-an-ip", "",
    ],
)  # fmt: skip
def test_bogon_sources_never_get_a_reply(ip: str, profile) -> None:  # type: ignore[no-untyped-def]
    _cfg, _pub, sink, _tracker, sensor = make_sensor(profile)  # allow_private stays False
    assert sensor.on_datagram(sip_request("OPTIONS"), (ip, 5060)) is None
    assert sensor.gate.stats.sent == 0 and sensor.gate.stats.denied_source >= 1
    if ip not in ("not-an-ip", ""):  # invalid addresses cannot even be recorded
        assert sink.emitted >= 1  # the probe is recorded, only the answer is withheld


def test_loopback_and_public_sources_are_answered(profile) -> None:  # type: ignore[no-untyped-def]
    cfg = Config()
    assert source_allowed("127.0.0.1", 5060, cfg)
    assert source_allowed("100.0.0.1", 5060, cfg)
    assert source_allowed("2606:4700::1", 5060, cfg)
    assert not source_allowed("100.0.0.1", 0, cfg)
    assert not source_allowed("100.0.0.1", 70000, cfg)
    assert not source_allowed("127.0.0.1", 5060, replace(cfg, allow_loopback=False))
    assert not source_allowed("100.0.0.1", 5060, replace(cfg, own_ips=("100.0.0.1",)))
    assert source_allowed("198.51.100.1", 5060, replace(cfg, allow_private=True))
    assert not source_allowed("224.0.0.1", 5060, replace(cfg, allow_private=True))


def test_responses_are_never_answered(profile) -> None:  # type: ignore[no-untyped-def]
    """Two reflectors must not be able to ping-pong: a response gets no reply at all."""
    _cfg, _pub, _sink, _tracker, sensor = make_sensor(profile, allow_private=True)
    resp = b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 1.2.3.4\r\nFrom: <sip:a@b>\r\nTo: <sip:c@d>\r\nCall-ID: 1\r\nCSeq: 1 OPTIONS\r\n\r\n"
    assert sensor.on_datagram(resp, ("198.51.100.9", 5060)) is None


def test_ack_and_garbage_are_silent(profile) -> None:  # type: ignore[no-untyped-def]
    _cfg, _pub, _sink, _tracker, sensor = make_sensor(profile, allow_private=True)
    assert sensor.on_datagram(sip_request("ACK"), ("198.51.100.9", 5060)) is None
    for junk in (b"", b"\x00" * 100, b"hello", b"\xff" * 4096, b"A" * 5000, b"\r\n\r\n"):
        assert sensor.on_datagram(junk, ("198.51.100.9", 5060)) is None
    assert sensor.udp_oversize == 1


def test_gate_refuses_oversized_reply() -> None:
    gate = ReplyGate(Config(allow_private=True))
    assert not gate.permit("198.51.100.1", 5060, request_size=100, reply_size=101)
    assert gate.permit("198.51.100.1", 5060, request_size=100, reply_size=100)


def test_pps_bucket_stops_processing_floods(profile) -> None:  # type: ignore[no-untyped-def]
    _cfg, _pub, _sink, _tracker, sensor = make_sensor(profile, allow_private=True)
    for _ in range(5000):
        sensor.on_datagram(sip_request("OPTIONS"), ("198.51.100.9", 5060))
    assert sensor.udp_dropped > 4000


async def test_real_socket_flood_amplification(make_harness: HarnessFactory) -> None:
    """Over a real UDP socket: a burst of OPTIONS gets at most the rate-limited trickle."""
    async with make_harness() as h:
        raw = sip_request("OPTIONS")
        replies = await udp_exchange(h.port, raw, wait=0.6, count=300)
        assert 1 <= len(replies) <= 12
        assert sum(len(r) for r in replies) <= len(raw) * 300
        assert all(len(r) <= len(raw) for r in replies)

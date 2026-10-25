"""Wire-level shape of the answers (what a scanner fingerprints)."""

from __future__ import annotations

import json

from conftest import Harness


async def test_ping_header_block_matches_dockerd(harness: Harness) -> None:
    raw = await harness.raw(b"GET /_ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode().split("\r\n")
    names = [line.split(":")[0] for line in lines[1:]]
    assert lines[0] == "HTTP/1.1 200 OK"
    assert names == [
        "Api-Version", "Builder-Version", "Cache-Control", "Content-Type", "Docker-Experimental",
        "Ostype", "Pragma", "Server", "Swarm", "Date", "Content-Length", "Connection",
    ]  # fmt: skip
    assert body == b"OK"


async def test_json_header_block_and_trailing_newline(harness: Harness) -> None:
    raw = await harness.raw(b"GET /version HTTP/1.1\r\nHost: x\r\n\r\n", wait=0.5)
    head, _, body = raw.partition(b"\r\n\r\n")
    names = [line.split(":")[0] for line in head.decode().split("\r\n")[1:]]
    assert names == [
        "Api-Version", "Content-Type", "Docker-Experimental", "Ostype", "Server", "Date",
        "Content-Length",
    ]  # fmt: skip
    assert body.endswith(b"}\n") and int(
        head.split(b"Content-Length: ")[1].split(b"\r\n")[0]
    ) == len(body)
    assert json.loads(body)["Os"] == "linux"


async def test_go_style_bad_request(harness: Harness) -> None:
    raw = await harness.raw(b"BREW /pot HTTP/1.1\x00\r\n\r\n")
    assert raw.startswith(
        b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close"
    )
    assert raw.endswith(b"400 Bad Request")


async def test_no_giveaways_on_the_wire(harness: Harness) -> None:
    blobs = []
    for path in (
        "/_ping",
        "/version",
        "/info",
        "/containers/json",
        "/images/json",
        "/nope",
        "/swarm",
    ):
        blobs.append((await harness.http("GET", path))[2].lower())
    blobs.append(await harness.raw(b"\x00\x01\x02\r\n\r\n"))
    blob = b"".join(blobs).lower()
    for word in (b"honeypot", b"suckerpot", b"python", b"asyncio", b"starlette", b"traceback"):
        assert word not in blob


async def test_stream_pull_is_chunked_json_lines(harness: Harness) -> None:
    raw = await harness.raw(
        b"POST /v1.47/images/create?fromImage=alpine&tag=3.20 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    head, _, body = raw.partition(b"\r\n\r\n")
    assert b"Transfer-Encoding: chunked" in head and b"Content-Length" not in head
    assert body.endswith(b"0\r\n\r\n")
    assert b"Status: Downloaded newer image for alpine:3.20" in body

"""Generated static assets: small valid PNGs and plausible CSS/JS bodies."""

from __future__ import annotations

import struct
import zlib


def png(width: int, height: int, rgb: tuple[int, int, int]) -> bytes:
    """A valid solid-colour PNG."""

    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    row = b"\x00" + bytes(rgb) * width
    raw = row * height
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def css(name: str, size: int = 900) -> bytes:
    """A plausible stylesheet of roughly ``size`` bytes (content is not meant to be used)."""
    head = f"/*! {name} */\n"
    rules: list[str] = []
    i = 0
    while sum(len(r) for r in rules) < size:
        rules.append(
            f".{name.replace('.', '-')}-{i}{{margin:0;padding:{i % 7}px;color:#{(i * 2654435761) % 0xFFFFFF:06x}}}\n"
        )
        i += 1
    return (head + "".join(rules)).encode()


def js(name: str, size: int = 1200) -> bytes:
    head = f"/*! {name} */\n"
    body = "".join(f"function f{i}(a,b){{return a+b*{i}}}\n" for i in range(max(1, size // 32)))
    return (head + body).encode()


def jquery() -> bytes:
    return (
        b"/*! jQuery v3.7.1 | (c) OpenJS Foundation and other contributors | jquery.org/license */\n"
        + js("jquery", 4000)
    )

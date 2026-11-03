"""Strict, bounded parsing of the request head (request line plus headers)."""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_LINE = 512
MAX_HEADERS_BYTES = 4096
MAX_HEADER_COUNT = 32
HEAD_LIMIT = MAX_LINE + 2 + MAX_HEADERS_BYTES + 4

_TOKEN = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_VERSION = re.compile(rb"^HTTP/1\.[01]$")
_VALUE_OK = re.compile(rb"^[\x20-\x7e]*$")


class BadRequest(ValueError):
    """The head is malformed or exceeds a bound."""


@dataclass(frozen=True)
class Head:
    method: str
    target: str
    version: str
    headers: dict[str, str]


def parse_head(data: bytes) -> Head:
    """Parse ``data`` (ending in a blank line). Raises BadRequest on anything unusual."""
    if len(data) > HEAD_LIMIT or not data.endswith(b"\r\n\r\n"):
        raise BadRequest("framing")
    body = data[:-4]
    stripped = body.replace(b"\r\n", b"")
    if b"\n" in stripped or b"\r" in stripped:
        raise BadRequest("bare CR or LF")
    if not body.isascii() or b"\x00" in body:
        raise BadRequest("non-ascii")
    lines = body.split(b"\r\n")
    request_line = lines[0]
    if not request_line or len(request_line) > MAX_LINE:
        raise BadRequest("request line")
    parts = request_line.split(b" ")
    if len(parts) != 3 or not all(parts):
        raise BadRequest("request line shape")
    method, target, version = parts
    if not _TOKEN.match(method) or len(method) > 16:
        raise BadRequest("method")
    if not _VERSION.match(version):
        raise BadRequest("version")
    if not _VALUE_OK.match(target):
        raise BadRequest("target")
    header_lines = lines[1:]
    if len(header_lines) > MAX_HEADER_COUNT:
        raise BadRequest("too many headers")
    if sum(len(line) + 2 for line in header_lines) > MAX_HEADERS_BYTES:
        raise BadRequest("headers too large")
    headers: dict[str, str] = {}
    for line in header_lines:
        name, sep, value = line.partition(b":")
        if not sep or not _TOKEN.match(name):
            raise BadRequest("header shape")  # also rejects obs-fold (leading space)
        value = value.strip(b" \t")
        if not _VALUE_OK.match(value):
            raise BadRequest("header value")
        key = name.decode("ascii").lower()
        if key in headers:
            raise BadRequest("duplicate header")
        headers[key] = value.decode("ascii")
    return Head(method.decode("ascii"), target.decode("ascii"), version.decode("ascii"), headers)

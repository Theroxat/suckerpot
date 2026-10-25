"""Byte-for-byte comparison with responses captured from a real Apache 2.4.58 (Ubuntu 24.04).

``golden/apache_errors.json`` was produced by ``ref_compare.py`` (every case identical to the
reference). Dates and the server address are normalised.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import Harness
from ref_compare import normalise

from web_sensor.profile import build_profile

GOLDEN = json.loads((Path(__file__).parent / "golden" / "apache_errors.json").read_text())
REF_IP = "192.0.2.10"  # never appears: the goldens already contain <ip>
IP = build_profile(b"x" * 32, 1_790_000_000.0).server_ip


@pytest.mark.parametrize("name", sorted(GOLDEN))
async def test_matches_apache(harness: Harness, name: str) -> None:
    case = GOLDEN[name]
    got = await harness.raw(bytes.fromhex(case["request"]), wait=0.5)
    want = bytes.fromhex(case["response"])
    assert normalise(got, REF_IP, IP) == want

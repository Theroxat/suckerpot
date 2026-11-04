"""SuckerPot network protocol spn/1 (design M29): pure functions, no I/O.

Imported by the hub and by the node worker. The normative description is
``docs/network-protocol.md``; any wire change goes through that spec first.
"""

from __future__ import annotations

from . import blind, buckets, defaults, enums, models, pow, sign
from .errors import ERROR_STATUS, ProtoError
from .models import parse_body, parse_response

__all__ = [
    "ERROR_STATUS",
    "ProtoError",
    "blind",
    "buckets",
    "defaults",
    "enums",
    "models",
    "parse_body",
    "parse_response",
    "pow",
    "sign",
]

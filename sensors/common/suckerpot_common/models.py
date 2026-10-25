"""The shared Event schema.

Every sensor emits :class:`Event` objects and nothing else. On the wire an event is one
Redis Streams entry with two fields: ``v`` (schema version, currently ``"1"``) and
``event`` (the JSON document).

Recommended ``data`` keys per event type:

* ``login_attempt``: ``username``, ``password``, ``success`` (bool), ``method``
  (``password`` / ``publickey`` / ``keyboard-interactive``)
* ``command``: ``input`` (str), ``output_preview`` (str, optional)
* ``download_attempt``: ``url``, ``tool`` (``wget`` / ``curl`` / ``tftp`` ...), ``command``
* ``http_request``: ``method``, ``path``, ``query``, ``headers`` (dict), ``user_agent``,
  ``body_preview``, ``status``
* ``connect``: ``client_version`` (optional)
* ``disconnect``: ``duration_s``, ``reason``
* ``scan``: ``payload_preview`` (hex)

Sensors must run :func:`suckerpot_common.truncate_data` on attacker-controlled data before
building an event. Validation rejects anything whose serialized ``data`` exceeds 16 KiB.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator

STREAM_VERSION = "1"
MAX_DATA_BYTES = 16 * 1024
MAX_RAW_EVENT_BYTES = 64 * 1024


class SensorName(StrEnum):
    ssh = "ssh"
    telnet = "telnet"
    web = "web"
    rdp = "rdp"
    redis = "redis"
    docker = "docker"
    mysql = "mysql"
    adb = "adb"
    mssql = "mssql"
    smb = "smb"
    sip = "sip"


class EventType(StrEnum):
    connect = "connect"
    login_attempt = "login_attempt"
    command = "command"
    http_request = "http_request"
    download_attempt = "download_attempt"
    disconnect = "disconnect"
    scan = "scan"


class Event(BaseModel):
    """One thing an attacker did, as seen by a sensor."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ts: datetime
    sensor: SensorName
    session_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    src_ip: IPvAnyAddress
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    type: EventType
    data: dict[str, Any] = Field(default_factory=dict)

    @field_validator("ts")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("ts must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("data")
    @classmethod
    def _bounded(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"data must be JSON-serializable: {exc}") from exc
        if len(raw.encode("utf-8")) > MAX_DATA_BYTES:
            raise ValueError(f"data exceeds {MAX_DATA_BYTES} bytes once serialized")
        return value

    def to_stream_fields(self) -> dict[str, str]:
        return {"v": STREAM_VERSION, "event": self.model_dump_json()}

    @classmethod
    def from_stream_fields(cls, fields: Mapping[Any, bytes | str]) -> Self:
        """Parse the fields of a stream entry. Raises ValueError on any problem."""
        norm: dict[str, str] = {}
        for key, val in fields.items():
            k = key.decode("utf-8", "replace") if isinstance(key, bytes) else key
            norm[k] = val.decode("utf-8", "replace") if isinstance(val, bytes) else val
        version = norm.get("v")
        if version != STREAM_VERSION:
            raise ValueError(f"unsupported stream version: {version!r}")
        payload = norm.get("event")
        if payload is None:
            raise ValueError("missing 'event' field")
        if len(payload) > MAX_RAW_EVENT_BYTES:  # chars <= bytes: cheap pre-check
            raise ValueError("event field too large")
        if len(payload.encode("utf-8")) > MAX_RAW_EVENT_BYTES:
            raise ValueError("event field too large")
        return cls.model_validate_json(payload)

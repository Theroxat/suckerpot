"""SQLAlchemy 2 typed models for the ``events`` hypertable and ``sessions``."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Identity,
    Index,
    Integer,
    SmallInteger,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base."""


class EventRow(Base):
    """One raw event. Hypertable partitioned on ``ts`` (1-day chunks)."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=False), primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    sensor: Mapped[str] = mapped_column(Text)
    session_id: Mapped[str] = mapped_column(Text)
    type: Mapped[str] = mapped_column(Text)
    src_ip: Mapped[str] = mapped_column(INET)
    src_port: Mapped[int] = mapped_column(Integer)
    dst_port: Mapped[int] = mapped_column(Integer)
    data: Mapped[dict[str, Any]] = mapped_column(JSONB)
    country: Mapped[str | None] = mapped_column(Text)
    city: Mapped[str | None] = mapped_column(Text)
    asn: Mapped[int | None] = mapped_column(Integer)
    org: Mapped[str | None] = mapped_column(Text)
    abuse_score: Mapped[int | None] = mapped_column(SmallInteger)
    known_scanner: Mapped[bool | None] = mapped_column(Boolean)
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )

    __table_args__ = (
        Index("ix_events_session_id_ts", "session_id", "ts"),
        Index("ix_events_src_ip_ts", "src_ip", text("ts DESC")),
        Index("ix_events_sensor_ts", "sensor", text("ts DESC")),
        Index("ix_events_tags", "tags", postgresql_using="gin"),
    )


class SessionRow(Base):
    """One attacker connection (a story made of events)."""

    __tablename__ = "sessions"

    session_id: Mapped[str] = mapped_column(Text, primary_key=True)
    sensor: Mapped[str] = mapped_column(Text)
    src_ip: Mapped[str] = mapped_column(INET)
    src_port: Mapped[int] = mapped_column(Integer)
    dst_port: Mapped[int] = mapped_column(Integer)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event_count: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    login_attempts: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    login_success: Mapped[bool] = mapped_column(
        Boolean, server_default=text("false"), nullable=False
    )
    commands: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    downloads: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    http_requests: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    country: Mapped[str | None] = mapped_column(Text)
    city: Mapped[str | None] = mapped_column(Text)
    asn: Mapped[int | None] = mapped_column(Integer)
    org: Mapped[str | None] = mapped_column(Text)
    abuse_score: Mapped[int | None] = mapped_column(SmallInteger)
    known_scanner: Mapped[bool | None] = mapped_column(Boolean)
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )

    __table_args__ = (
        Index("ix_sessions_started_at", text("started_at DESC")),
        Index("ix_sessions_sensor_started_at", "sensor", text("started_at DESC")),
        Index("ix_sessions_src_ip", "src_ip"),
        Index("ix_sessions_tags", "tags", postgresql_using="gin"),
        Index("ix_sessions_country", "country"),
    )

"""SQLAlchemy 2 typed models for the ``events`` hypertable and ``sessions``."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
    DateTime,
    Identity,
    Index,
    Integer,
    LargeBinary,
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
        Index("ix_events_type_ts", "type", text("ts DESC")),
        Index(
            "ix_events_country_ts",
            "country",
            text("ts DESC"),
            postgresql_where=text("country IS NOT NULL"),
        ),
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
    client_tool: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("ix_sessions_started_at", text("started_at DESC")),
        Index("ix_sessions_sensor_started_at", "sensor", text("started_at DESC")),
        Index("ix_sessions_src_ip", "src_ip"),
        Index("ix_sessions_tags", "tags", postgresql_using="gin"),
        Index("ix_sessions_country", "country"),
        Index("ix_sessions_last_event_at", text("last_event_at DESC")),
        Index("ix_sessions_asn", "asn", postgresql_where=text("asn IS NOT NULL")),
    )


class IpReputationRow(Base):
    """24 h cache of reputation lookups, one row per source IP."""

    __tablename__ = "ip_reputation"

    ip: Mapped[str] = mapped_column(INET, primary_key=True)
    abuse_score: Mapped[int | None] = mapped_column(SmallInteger)
    abuse_reports: Mapped[int | None] = mapped_column(Integer)
    abuse_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    gn_noise: Mapped[bool | None] = mapped_column(Boolean)
    gn_riot: Mapped[bool | None] = mapped_column(Boolean)
    gn_classification: Mapped[str | None] = mapped_column(Text)
    gn_name: Mapped[str | None] = mapped_column(Text)
    gn_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )


class EnrichmentQuotaRow(Base):
    """Calls made to a provider per UTC day (survives restarts)."""

    __tablename__ = "enrichment_quota"

    provider: Mapped[str] = mapped_column(Text, primary_key=True)
    day: Mapped[date] = mapped_column(Date, primary_key=True)
    used: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)


class EnrichmentStatusRow(Base):
    """Provider and database status published by ingest for the settings page."""

    __tablename__ = "enrichment_status"

    name: Mapped[str] = mapped_column(Text, primary_key=True)
    detail: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=text("'{}'::jsonb"), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )


class ProviderSecretRow(Base):
    """An enrichment API key set from the Settings page, encrypted with AES-256-GCM."""

    __tablename__ = "provider_secrets"

    provider: Mapped[str] = mapped_column(Text, primary_key=True)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    last4: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )
    updated_by: Mapped[str] = mapped_column(Text, nullable=False)


class ProviderTestRequestRow(Base):
    """A "Test key" click: the API cannot reach the internet, so ingest performs the call."""

    __tablename__ = "provider_test_requests"

    provider: Mapped[str] = mapped_column(Text, primary_key=True)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )
    requested_by: Mapped[str] = mapped_column(Text, nullable=False)
    handled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Daily cap on requested tests (the API refuses more, atomically, in one upsert).
    tests_day: Mapped[date] = mapped_column(
        Date, server_default=text("current_date"), nullable=False
    )
    tests_today: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)

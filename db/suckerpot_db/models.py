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
    Numeric,
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
    techniques: Mapped[list[str] | None] = mapped_column(ARRAY(Text))  # ATT&CK ids (M15)
    benign: Mapped[bool | None] = mapped_column(Boolean)  # research scanner (M19), new rows only

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
    techniques: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    campaign_id: Mapped[int | None] = mapped_column(BigInteger)
    clustered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    benign: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    scanner_name: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("ix_sessions_started_at", text("started_at DESC")),
        Index("ix_sessions_sensor_started_at", "sensor", text("started_at DESC")),
        Index("ix_sessions_src_ip", "src_ip"),
        Index("ix_sessions_tags", "tags", postgresql_using="gin"),
        Index("ix_sessions_country", "country"),
        Index("ix_sessions_last_event_at", text("last_event_at DESC")),
        Index("ix_sessions_asn", "asn", postgresql_where=text("asn IS NOT NULL")),
        Index("ix_sessions_techniques", "techniques", postgresql_using="gin"),
        Index("ix_sessions_campaign_id", "campaign_id"),
        Index(
            "ix_sessions_unclustered",
            "last_event_at",
            postgresql_where=text("clustered_at IS NULL"),
        ),
        Index(
            "ix_sessions_not_benign", text("started_at DESC"), postgresql_where=text("NOT benign")
        ),
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


class CveRow(Base):
    """A vulnerability from CISA KEV, NVD and/or GitHub advisories (one row per CVE id)."""

    __tablename__ = "cve"

    cve_id: Mapped[str] = mapped_column(Text, primary_key=True)
    title: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    vendor: Mapped[str | None] = mapped_column(Text)
    product: Mapped[str | None] = mapped_column(Text)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cvss_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    cvss_severity: Mapped[str | None] = mapped_column(Text)
    cwes: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    ghsa_ids: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    refs: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    in_kev: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    kev_added_at: Mapped[date | None] = mapped_column(Date)
    kev_due_date: Mapped[date | None] = mapped_column(Date)
    kev_ransomware: Mapped[bool | None] = mapped_column(Boolean)
    kev_action: Mapped[str | None] = mapped_column(Text)
    cpes: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    relevance: Mapped[str] = mapped_column(Text, server_default=text("'none'"), nullable=False)
    matched_services: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    rank_score: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    sources: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )

    __table_args__ = (
        Index("ix_cve_published_at", text("published_at DESC")),
        Index("ix_cve_kev_added_at", text("kev_added_at DESC"), postgresql_where=text("in_kev")),
        Index("ix_cve_cvss_score", text("cvss_score DESC")),
        Index("ix_cve_rank", text("rank_score DESC"), text("cve_id DESC")),
    )


class CveSyncStateRow(Base):
    """Per-source state of the CVE watch job (last run, outcome, row count)."""

    __tablename__ = "cve_sync_state"

    source: Mapped[str] = mapped_column(Text, primary_key=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    items_last_run: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)


class IndicatorRow(Base):
    """A URL, domain, IP address or file hash seen in recorded events (never contacted)."""

    __tablename__ = "indicators"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    type: Mapped[str] = mapped_column(Text)  # url | domain | ip | hash
    value: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(Text)  # download_host | contacted_host | hash
    host: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    sightings: Mapped[int] = mapped_column(BigInteger, server_default=text("1"), nullable=False)
    sensors: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    # A hash computed by a sensor (not just a string in a command).
    trusted: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    # Seen only in demo events: never sent to an intel service.
    demo: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)


class IndicatorSessionRow(Base):
    """A bounded link from an indicator to a session that showed it."""

    __tablename__ = "indicator_sessions"

    indicator_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    session_id: Mapped[str] = mapped_column(Text, primary_key=True)
    src_ip: Mapped[str] = mapped_column(INET)
    sensor: Mapped[str] = mapped_column(Text)
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class IndicatorIntelRow(Base):
    """One threat-intel answer per indicator and source (24 h cache)."""

    __tablename__ = "indicator_intel"

    indicator_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    source: Mapped[str] = mapped_column(Text, primary_key=True)  # urlhaus | threatfox | virustotal
    known: Mapped[bool] = mapped_column(Boolean)
    family: Mapped[str | None] = mapped_column(Text)
    threat_type: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )
    first_seen_ext: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reference: Mapped[str | None] = mapped_column(Text)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )


class UserRow(Base):
    """An additional dashboard account. The owner account lives in ``.env`` and has no row."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    username: Mapped[str] = mapped_column(Text, nullable=False)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(Text, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, server_default=text("true"), nullable=False
    )
    disabled: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )
    created_by: Mapped[str] = mapped_column(Text, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    prev_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_logins: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    session_version: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    known_sources: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{}'::text[]"), nullable=False
    )


class AuditLogRow(Base):
    """One administrative action. ``details`` is bounded and never holds a secret."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )
    actor: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    target: Mapped[str | None] = mapped_column(Text)
    ip: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=text("'{}'::jsonb"), nullable=False
    )


def _now() -> Any:
    return text("now()")


def _empty_array() -> Any:
    return text("'{}'::text[]")


# ---- M15: campaigns and ATT&CK ---------------------------------------------------------------


class AttackTechniqueRow(Base):
    """The ATT&CK technique catalogue (upserted by ingest from YAML)."""

    __tablename__ = "attack_techniques"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    tactic: Mapped[str] = mapped_column(Text)
    stage: Mapped[str] = mapped_column(Text)
    url: Mapped[str] = mapped_column(Text)


class TechniqueDailyRow(Base):
    """Per-day technique counters, kept forever."""

    __tablename__ = "technique_daily"

    day: Mapped[date] = mapped_column(Date, primary_key=True)
    technique: Mapped[str] = mapped_column(Text, primary_key=True)
    sensor: Mapped[str] = mapped_column(Text, primary_key=True)
    sessions: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    events: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    sources: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)


class CampaignRow(Base):
    """A group of sessions that share infrastructure, tooling or a script."""

    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, server_default=text("'active'"), nullable=False)
    merged_into: Mapped[int | None] = mapped_column(BigInteger)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    sessions: Mapped[int] = mapped_column(BigInteger, server_default=text("0"), nullable=False)
    sources: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    countries: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=_empty_array(), nullable=False
    )
    asns: Mapped[list[int]] = mapped_column(
        ARRAY(Integer), server_default=text("'{}'::integer[]"), nullable=False
    )
    sensors: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=_empty_array(), nullable=False
    )
    techniques: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=_empty_array(), nullable=False
    )
    stages: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=_empty_array(), nullable=False
    )
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=_empty_array(), nullable=False
    )
    families: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=_empty_array(), nullable=False
    )
    severity: Mapped[str] = mapped_column(Text, server_default=text("'info'"), nullable=False)
    rep_session_id: Mapped[str | None] = mapped_column(Text)
    demo: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )


class CampaignKeyRow(Base):
    """A clustering key (script hash, payload host, ...) and the campaign it belongs to."""

    __tablename__ = "campaign_keys"

    kind: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[str] = mapped_column(Text, primary_key=True)
    campaign_id: Mapped[int | None] = mapped_column(BigInteger)
    sources: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CampaignSessionRow(Base):
    """A bounded link from a campaign to one of its sessions."""

    __tablename__ = "campaign_sessions"

    campaign_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    session_id: Mapped[str] = mapped_column(Text, primary_key=True)
    src_ip: Mapped[str] = mapped_column(INET)
    sensor: Mapped[str] = mapped_column(Text)
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


# ---- M16: defend ------------------------------------------------------------------------------


class BlocklistEntryRow(Base):
    """A scored indicator for the blocklists, recomputed by ingest."""

    __tablename__ = "blocklist_entries"

    kind: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[str] = mapped_column(Text, primary_key=True)
    score: Mapped[int] = mapped_column(SmallInteger)
    reasons: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=_empty_array(), nullable=False
    )
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    sessions: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    sources: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    campaign_ids: Mapped[list[int]] = mapped_column(
        ARRAY(BigInteger), server_default=text("'{}'::bigint[]"), nullable=False
    )
    benign: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    demo: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )


class BlocklistOverrideRow(Base):
    """An admin decision to always allow or always block an indicator."""

    __tablename__ = "blocklist_overrides"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    kind: Mapped[str] = mapped_column(Text)
    value: Mapped[str] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text)
    note: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class FeedTokenRow(Base):
    """A bearer token for the feeds. Only its sha256 is stored."""

    __tablename__ = "feed_tokens"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary)
    token_hint: Mapped[str] = mapped_column(Text)
    kinds: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("'{ip}'::text[]"), nullable=False
    )
    min_score: Mapped[int] = mapped_column(SmallInteger, server_default=text("50"), nullable=False)
    include_benign: Mapped[bool] = mapped_column(
        Boolean, server_default=text("false"), nullable=False
    )
    created_by: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_ip: Mapped[str | None] = mapped_column(Text)
    use_count: Mapped[int] = mapped_column(BigInteger, server_default=text("0"), nullable=False)


class InventoryServiceRow(Base):
    """A service the owner runs, compared with what attackers target."""

    __tablename__ = "inventory_services"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    service: Mapped[str] = mapped_column(Text)
    product: Mapped[str | None] = mapped_column(Text)
    version: Mapped[str | None] = mapped_column(Text)
    exposure: Mapped[str] = mapped_column(Text, server_default=text("'internal'"), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )


# ---- M17: script library ----------------------------------------------------------------------


class ScriptRow(Base):
    """One distinct normalised command sequence."""

    __tablename__ = "scripts"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    fingerprint: Mapped[bytes] = mapped_column(LargeBinary)
    normalized_text: Mapped[str] = mapped_column(Text)
    sample_text: Mapped[str] = mapped_column(Text)
    line_count: Mapped[int] = mapped_column(SmallInteger, server_default=text("0"), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    sessions: Mapped[int] = mapped_column(BigInteger, server_default=text("0"), nullable=False)
    sources: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    sensors: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=_empty_array(), nullable=False
    )
    campaign_id: Mapped[int | None] = mapped_column(BigInteger)
    techniques: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=_empty_array(), nullable=False
    )
    demo: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)


class ScriptSessionRow(Base):
    """A bounded link from a script to a session that ran it."""

    __tablename__ = "script_sessions"

    script_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    session_id: Mapped[str] = mapped_column(Text, primary_key=True)
    src_ip: Mapped[str] = mapped_column(INET)
    sensor: Mapped[str] = mapped_column(Text)
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ScriptExplanationRow(Base):
    """Per-line explanation of a script, from the annotations or from the LLM."""

    __tablename__ = "script_explanations"

    script_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    source: Mapped[str] = mapped_column(Text, primary_key=True)  # annotations | llm
    prompt_version: Mapped[int] = mapped_column(
        SmallInteger, server_default=text("1"), nullable=False
    )
    model: Mapped[str | None] = mapped_column(Text)
    lines: Mapped[Any] = mapped_column(JSONB)
    summary: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )


class LlmRequestRow(Base):
    """A request to explain a script with the LLM (the API inserts, ingest answers)."""

    __tablename__ = "llm_requests"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    script_id: Mapped[int] = mapped_column(BigInteger)
    requested_by: Mapped[str] = mapped_column(Text)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    state: Mapped[str] = mapped_column(Text, server_default=text("'queued'"), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)


# ---- M18: alerts and reports ------------------------------------------------------------------


class AlertChannelRow(Base):
    """Where alerts are sent. The target is encrypted (nonce followed by ciphertext)."""

    __tablename__ = "alert_channels"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    kind: Mapped[str] = mapped_column(Text)
    name: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)
    target_ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    target_hint: Mapped[str] = mapped_column(Text, server_default=text("''"), nullable=False)
    mask_ips: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)
    created_by: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )


class AlertRuleRow(Base):
    """One row per alert rule kind (seeded, all disabled)."""

    __tablename__ = "alert_rules"

    kind: Mapped[str] = mapped_column(Text, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    channel_ids: Mapped[list[int]] = mapped_column(
        ARRAY(BigInteger), server_default=text("'{}'::bigint[]"), nullable=False
    )
    min_severity: Mapped[str] = mapped_column(
        Text, server_default=text("'warning'"), nullable=False
    )
    settings: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=text("'{}'::jsonb"), nullable=False
    )


class WatchedCveRow(Base):
    """A CVE the owner wants an alert for."""

    __tablename__ = "watched_cves"

    cve_id: Mapped[str] = mapped_column(Text, primary_key=True)
    added_by: Mapped[str] = mapped_column(Text)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )


class AlertOutboxRow(Base):
    """A queued, sent, failed or suppressed alert. Unique per rule, key and channel."""

    __tablename__ = "alert_outbox"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    rule_kind: Mapped[str] = mapped_column(Text)
    dedupe_key: Mapped[str] = mapped_column(Text)
    channel_id: Mapped[int] = mapped_column(BigInteger)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    state: Mapped[str] = mapped_column(Text, server_default=text("'pending'"), nullable=False)
    attempts: Mapped[int] = mapped_column(SmallInteger, server_default=text("0"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(Text)


class AlertCursorRow(Base):
    """Ingest's progress per alert rule."""

    __tablename__ = "alert_cursors"

    rule_kind: Mapped[str] = mapped_column(Text, primary_key=True)
    cursor: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=text("'{}'::jsonb"), nullable=False
    )


class WeeklyReportRow(Base):
    """A rendered weekly report, kept for two years."""

    __tablename__ = "weekly_reports"

    week_start: Mapped[date] = mapped_column(Date, primary_key=True)
    html: Mapped[str] = mapped_column(Text)
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )


class AlertTestRequestRow(Base):
    """A request to send a test message to a channel (the API inserts, ingest answers)."""

    __tablename__ = "alert_test_requests"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    channel_id: Mapped[int] = mapped_column(BigInteger)
    requested_by: Mapped[str] = mapped_column(Text)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=_now(), nullable=False
    )
    state: Mapped[str] = mapped_column(Text, server_default=text("'queued'"), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)

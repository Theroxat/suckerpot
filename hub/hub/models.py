"""Hub tables (design M29 section 6.3, migration ``h0001_initial``).

No table has an address column about a client. ``nodes.pubkey`` is the only node identifier.
Additions to the design DDL, all privacy-neutral: ``nodes.pseudonym_changed_day``,
``observations.fetched`` / ``file_type``, ``targets.seq`` (a change cursor kept by a trigger) and
the ``network_summary`` cache written once a day by the worker.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import (
    ARRAY,
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Identity,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import CHAR, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Node(Base):
    __tablename__ = "nodes"
    __table_args__ = (CheckConstraint("length(pubkey) = 32", name="nodes_pubkey_len"),)

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    pubkey: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    pseudonym: Mapped[str | None] = mapped_column(Text)
    pseudonym_key: Mapped[str | None] = mapped_column(Text, unique=True)
    country: Mapped[str | None] = mapped_column(CHAR(2))
    show_country: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    enrolled_day: Mapped[date] = mapped_column(Date)
    last_active_day: Mapped[date] = mapped_column(Date)
    reputation: Mapped[float] = mapped_column(Float(24), server_default=text("0.6"))
    standing: Mapped[str] = mapped_column(Text, server_default=text("'active'"))
    protocol: Mapped[str] = mapped_column(Text)
    pseudonym_changed_day: Mapped[date | None] = mapped_column(Date)


class EnrolChallenge(Base):
    __tablename__ = "enrol_challenges"

    challenge: Mapped[bytes] = mapped_column(LargeBinary, primary_key=True)
    pubkey: Mapped[bytes] = mapped_column(LargeBinary, index=True)
    difficulty: Mapped[int] = mapped_column(Integer)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class Nonce(Base):
    __tablename__ = "nonces"

    node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True
    )
    nonce: Mapped[bytes] = mapped_column(LargeBinary, primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class Batch(Base):
    __tablename__ = "batches"

    node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True
    )
    day: Mapped[date] = mapped_column(Date, primary_key=True)
    batch_id: Mapped[bytes] = mapped_column(LargeBinary)
    items: Mapped[int] = mapped_column(Integer, server_default=text("0"))


class Observation(Base):
    __tablename__ = "observations"
    __table_args__ = (
        Index("observations_node_day_kind_value", "node_id", "day", "kind", "value", unique=True),
        Index("observations_kind_value_day", "kind", "value", "day"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("nodes.id", ondelete="CASCADE")
    )
    day: Mapped[date] = mapped_column(Date, index=True)
    kind: Mapped[str] = mapped_column(Text)
    value: Mapped[str] = mapped_column(Text)
    services: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    activity: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    families: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    sessions: Mapped[int | None] = mapped_column(SmallInteger)
    attempts: Mapped[int | None] = mapped_column(SmallInteger)
    fetched: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    file_type: Mapped[str | None] = mapped_column(Text)
    via: Mapped[str | None] = mapped_column(Text)


class Target(Base):
    __tablename__ = "targets"
    __table_args__ = (
        # The unique (kind, coalesce(value_b, value)) index is an expression index made by the
        # migration; the ORM does not need it.
        Index("targets_state", "state"),
    )

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    kind: Mapped[str] = mapped_column(Text)
    value: Mapped[str | None] = mapped_column(Text)
    value_b: Mapped[str | None] = mapped_column(Text)
    state: Mapped[str] = mapped_column(Text)
    node_count: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    weight: Mapped[float] = mapped_column(Float(24), server_default=text("0"))
    country_count: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    first_day: Mapped[date | None] = mapped_column(Date)
    last_day: Mapped[date | None] = mapped_column(Date)
    services: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    activity: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    families: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    confirmed_day: Mapped[date | None] = mapped_column(Date)
    reported_day: Mapped[date | None] = mapped_column(Date)
    taken_down_day: Mapped[date | None] = mapped_column(Date)
    report_id: Mapped[int | None] = mapped_column(BigInteger)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Change cursor: a trigger assigns the next value of targets_seq on every insert and update.
    seq: Mapped[int] = mapped_column(BigInteger, server_default=text("0"), index=True)


class TargetContributor(Base):
    __tablename__ = "target_contributors"

    target_id: Mapped[str] = mapped_column(
        Text, ForeignKey("targets.id", ondelete="CASCADE"), primary_key=True
    )
    node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True
    )


class TakedownVote(Base):
    __tablename__ = "takedown_votes"

    target_id: Mapped[str] = mapped_column(
        Text, ForeignKey("targets.id", ondelete="CASCADE"), primary_key=True
    )
    node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True
    )
    day: Mapped[date] = mapped_column(Date, primary_key=True)
    state: Mapped[str] = mapped_column(Text)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    recipient: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(Text)
    target_ids: Mapped[list[str]] = mapped_column(ARRAY(Text))
    state: Mapped[str] = mapped_column(Text)  # queued|approved|sent|failed|cancelled
    body_text: Mapped[str] = mapped_column(Text)
    xarf: Mapped[str | None] = mapped_column(Text)
    created_day: Mapped[date] = mapped_column(Date)
    approved_by: Mapped[str | None] = mapped_column(Text)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(Text)


class RecipientLog(Base):
    __tablename__ = "recipient_log"

    recipient: Mapped[str] = mapped_column(Text, primary_key=True)
    day: Mapped[date] = mapped_column(Date, primary_key=True)
    count: Mapped[int] = mapped_column(Integer)


class NodeStatsWeekly(Base):
    __tablename__ = "node_stats_weekly"

    node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True
    )
    week: Mapped[date] = mapped_column(Date, primary_key=True)
    active_days: Mapped[int] = mapped_column(SmallInteger)
    tier: Mapped[int] = mapped_column(SmallInteger)


class NetworkDaily(Base):
    __tablename__ = "network_daily"

    day: Mapped[date] = mapped_column(Date, primary_key=True)
    active_nodes: Mapped[int] = mapped_column(Integer)
    members: Mapped[int] = mapped_column(Integer)
    confirmed: Mapped[int] = mapped_column(Integer)
    reported: Mapped[int] = mapped_column(Integer)
    taken_down: Mapped[int] = mapped_column(Integer)


class NetworkSummaryRow(Base):
    __tablename__ = "network_summary"
    __table_args__ = (CheckConstraint("id = 1", name="network_summary_single"),)

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    generated_day: Mapped[date] = mapped_column(Date)
    data: Mapped[dict[str, object]] = mapped_column(JSONB)


class NeverList(Base):
    __tablename__ = "never_list"

    value: Mapped[str] = mapped_column(Text, primary_key=True)
    kind: Mapped[str] = mapped_column(Text)  # ip (address or cidr) | domain | asn | url
    note: Mapped[str | None] = mapped_column(String(200))


class HubAudit(Base):
    """Admin CLI actions. Never holds node data."""

    __tablename__ = "hub_audit"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    actor: Mapped[str] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text)
    detail: Mapped[dict[str, object] | None] = mapped_column(JSONB)


class WorkerState(Base):
    """Job markers of the worker (migration h0002). No node data."""

    __tablename__ = "worker_state"

    key: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[str] = mapped_column(Text)

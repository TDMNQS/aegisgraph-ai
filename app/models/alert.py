"""Fraud alert and analyst investigation persistence model."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, Enum, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.transaction import Transaction
    from app.models.user import User


class AlertSeverity(StrEnum):
    """Operational urgency derived from risk and business impact."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(StrEnum):
    """Investigation workflow states."""

    OPEN = "open"
    ASSIGNED = "assigned"
    INVESTIGATING = "investigating"
    CONFIRMED_FRAUD = "confirmed_fraud"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


class Alert(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Actionable fraud signal with complete analyst workflow context."""

    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint("risk_score >= 0 AND risk_score <= 1", name="alert_risk_range"),
        Index("ix_alerts_tenant_status_created", "tenant_id", "status", "created_at"),
        Index("ix_alerts_assignee_status", "assigned_to_id", "status"),
        Index("ix_alerts_severity_created", "severity", "created_at"),
    )

    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    transaction_id: Mapped[UUID] = mapped_column(
        ForeignKey("transactions.id", ondelete="CASCADE"),
        nullable=False,
    )
    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity, name="alert_severity", native_enum=False, length=16),
        nullable=False,
    )
    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus, name="alert_status", native_enum=False, length=32),
        default=AlertStatus.OPEN,
        nullable=False,
    )
    risk_score: Mapped[float] = mapped_column(nullable=False)
    title: Mapped[str] = mapped_column(String(180), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    reason_codes: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    assigned_to_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    assigned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolution: Mapped[str | None] = mapped_column(Text)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(default=1, nullable=False)

    transaction: Mapped[Transaction] = relationship(
        "Transaction",
        back_populates="alerts",
        lazy="joined",
    )
    assignee: Mapped[User | None] = relationship(
        "User",
        back_populates="assigned_alerts",
        foreign_keys=[assigned_to_id],
        lazy="raise",
    )

"""Privacy-aware payment transaction and fraud-decision model."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any, TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum,
    Index,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.alert import Alert


class PaymentStatus(StrEnum):
    """Processing state of a transaction event."""

    RECEIVED = "received"
    SCORING = "scoring"
    DECIDED = "decided"
    FAILED = "failed"


class PaymentDecision(StrEnum):
    """Final action returned to the payment processor."""

    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"
    ERROR = "error"


class Transaction(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Immutable payment facts plus versioned fraud-scoring output.

    Raw card, bank-account, email, and phone values are intentionally absent.
    Only irreversible or vault-issued tokens may be stored here.
    """

    __tablename__ = "transactions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "external_id", name="tenant_external_id"),
        UniqueConstraint("tenant_id", "idempotency_key", name="tenant_idempotency_key"),
        CheckConstraint("amount > 0", name="amount_positive"),
        CheckConstraint("length(currency) = 3", name="currency_iso_length"),
        CheckConstraint("risk_score >= 0 AND risk_score <= 1", name="risk_score_range"),
        CheckConstraint("rules_score >= 0 AND rules_score <= 1", name="rules_score_range"),
        CheckConstraint("ml_score >= 0 AND ml_score <= 1", name="ml_score_range"),
        CheckConstraint("graph_score >= 0 AND graph_score <= 1", name="graph_score_range"),
        CheckConstraint(
            "identity_score >= 0 AND identity_score <= 1",
            name="identity_score_range",
        ),
        Index("ix_transactions_tenant_occurred", "tenant_id", "occurred_at"),
        Index("ix_transactions_customer_occurred", "customer_token", "occurred_at"),
        Index("ix_transactions_decision_occurred", "decision", "occurred_at"),
        Index("ix_transactions_device_occurred", "device_token", "occurred_at"),
    )

    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    external_id: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    event_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    amount: Mapped[Decimal] = mapped_column(Numeric(19, 4), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    merchant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    merchant_category_code: Mapped[str | None] = mapped_column(String(4))
    channel: Mapped[str] = mapped_column(String(32), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    customer_token: Mapped[str] = mapped_column(String(128), nullable=False)
    account_token: Mapped[str] = mapped_column(String(128), nullable=False)
    device_token: Mapped[str | None] = mapped_column(String(128))
    ip_token: Mapped[str | None] = mapped_column(String(128))
    country_code: Mapped[str | None] = mapped_column(String(2))
    latitude: Mapped[Decimal | None] = mapped_column(Numeric(9, 6))
    longitude: Mapped[Decimal | None] = mapped_column(Numeric(9, 6))

    status: Mapped[PaymentStatus] = mapped_column(
        Enum(PaymentStatus, name="payment_status", native_enum=False, length=16),
        default=PaymentStatus.RECEIVED,
        nullable=False,
    )
    decision: Mapped[PaymentDecision | None] = mapped_column(
        Enum(PaymentDecision, name="payment_decision", native_enum=False, length=16)
    )
    risk_score: Mapped[Decimal] = mapped_column(Numeric(6, 5), default=Decimal("0"))
    rules_score: Mapped[Decimal] = mapped_column(Numeric(6, 5), default=Decimal("0"))
    ml_score: Mapped[Decimal] = mapped_column(Numeric(6, 5), default=Decimal("0"))
    graph_score: Mapped[Decimal] = mapped_column(Numeric(6, 5), default=Decimal("0"))
    identity_score: Mapped[Decimal] = mapped_column(Numeric(6, 5), default=Decimal("0"))
    confidence: Mapped[Decimal | None] = mapped_column(Numeric(6, 5))
    reason_codes: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    explanation: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    features: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    rules_version: Mapped[str | None] = mapped_column(String(64))
    model_version: Mapped[str | None] = mapped_column(String(64))
    graph_version: Mapped[str | None] = mapped_column(String(64))
    failure_code: Mapped[str | None] = mapped_column(String(64))
    failure_detail: Mapped[str | None] = mapped_column(Text)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    alerts: Mapped[list[Alert]] = relationship(
        back_populates="transaction",
        cascade="all, delete-orphan",
        lazy="raise",
    )

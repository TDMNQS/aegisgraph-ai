"""Strict payment ingestion and fraud-decision API contracts."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Any, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.transaction import PaymentDecision, PaymentStatus

Token = Annotated[str, Field(min_length=16, max_length=128, pattern=r"^[A-Za-z0-9:_-]+$")]
Score = Annotated[float, Field(ge=0.0, le=1.0)]
_ISO_CURRENCY = re.compile(r"^[A-Z]{3}$")
_COUNTRY_CODE = re.compile(r"^[A-Z]{2}$")
_MAX_ATTRIBUTES = 32
_MAX_ATTRIBUTE_KEY_LENGTH = 64


class FraudDemoScenario(StrEnum):
    """Server-controlled synthetic scenarios safe for local demonstrations."""

    NORMAL = "normal"
    ACCOUNT_TAKEOVER = "account_takeover"
    FRAUD_RING = "fraud_ring"


class FraudDemoRequest(BaseModel):
    """Select a synthetic scenario; no real customer data is accepted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario: FraudDemoScenario = FraudDemoScenario.ACCOUNT_TAKEOVER


class LocationInput(BaseModel):
    """Optional coarse location used for impossible-travel features."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    country_code: str | None = None
    latitude: Decimal | None = Field(default=None, ge=Decimal("-90"), le=Decimal("90"))
    longitude: Decimal | None = Field(default=None, ge=Decimal("-180"), le=Decimal("180"))

    @field_validator("country_code")
    @classmethod
    def validate_country_code(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.upper()
        if not _COUNTRY_CODE.fullmatch(normalized):
            raise ValueError("country_code must be an ISO 3166-1 alpha-2 code")
        return normalized

    @model_validator(mode="after")
    def require_coordinate_pair(self) -> Self:
        if (self.latitude is None) != (self.longitude is None):
            raise ValueError("latitude and longitude must be supplied together")
        return self


class TransactionCreate(BaseModel):
    """Canonical command accepted from an authenticated payment producer.

    Every identity-like field must already be tokenized. The schema intentionally
    contains no PAN, CVV, bank account, email, phone, or customer name field.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    external_id: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=16, max_length=128)
    amount: Decimal = Field(gt=0, max_digits=19, decimal_places=4)
    currency: str = Field(min_length=3, max_length=3)
    merchant_id: str = Field(min_length=1, max_length=128)
    merchant_category_code: str | None = Field(default=None, pattern=r"^\d{4}$")
    channel: Literal["web", "mobile", "pos", "atm", "api"]
    occurred_at: datetime
    customer_token: Token
    account_token: Token
    device_token: Token | None = None
    ip_token: Token | None = None
    location: LocationInput | None = None
    attributes: dict[str, str | int | float | bool] = Field(default_factory=dict)

    @field_validator("currency")
    @classmethod
    def normalize_currency(cls, value: str) -> str:
        normalized = value.upper()
        if not _ISO_CURRENCY.fullmatch(normalized):
            raise ValueError("currency must be a three-letter ISO 4217 code")
        return normalized

    @field_validator("occurred_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must include a timezone offset")
        normalized = value.astimezone(UTC)
        if normalized > datetime.now(UTC):
            raise ValueError("occurred_at cannot be in the future")
        return normalized

    @field_validator("attributes")
    @classmethod
    def bound_attributes(
        cls,
        value: dict[str, str | int | float | bool],
    ) -> dict[str, str | int | float | bool]:
        if len(value) > _MAX_ATTRIBUTES:
            raise ValueError("attributes cannot contain more than 32 entries")
        if any(len(key) > _MAX_ATTRIBUTE_KEY_LENGTH for key in value):
            raise ValueError("attribute keys cannot exceed 64 characters")
        return value


class ScoreBreakdown(BaseModel):
    """Normalized component scores used by the hybrid risk aggregator."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rules: Score
    ml: Score
    graph: Score
    identity: Score


class FraudDecisionResponse(BaseModel):
    """Low-latency decision returned after successful scoring."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    transaction_id: UUID
    external_id: str
    decision: PaymentDecision
    risk_score: Score
    confidence: Score
    scores: ScoreBreakdown
    reason_codes: list[str] = Field(max_length=32)
    explanation: dict[str, Any]
    degraded_components: list[Literal["rules", "ml", "graph", "identity"]]
    decided_at: datetime
    processing_time_ms: float = Field(ge=0)
    model_version: str | None = None
    rules_version: str | None = None


class TransactionRead(BaseModel):
    """Analyst-safe transaction representation loaded from PostgreSQL."""

    model_config = ConfigDict(from_attributes=True, extra="forbid", frozen=True)

    id: UUID
    tenant_id: str
    external_id: str
    amount: Decimal
    currency: str
    merchant_id: str
    merchant_category_code: str | None
    channel: str
    occurred_at: datetime
    customer_token: str
    device_token: str | None
    country_code: str | None
    status: PaymentStatus
    decision: PaymentDecision | None
    risk_score: Decimal
    reason_codes: list[str]
    explanation: dict[str, Any]
    created_at: datetime
    decided_at: datetime | None

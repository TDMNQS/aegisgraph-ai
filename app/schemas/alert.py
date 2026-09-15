"""Fraud-alert investigation API contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.alert import AlertSeverity, AlertStatus


class AlertRead(BaseModel):
    """Analyst-safe alert representation."""

    model_config = ConfigDict(from_attributes=True, extra="forbid", frozen=True)

    id: UUID
    tenant_id: str
    transaction_id: UUID
    severity: AlertSeverity
    status: AlertStatus
    risk_score: float
    title: str
    summary: str
    reason_codes: list[str]
    evidence: dict[str, Any]
    assigned_to_id: UUID | None
    assigned_at: datetime | None
    resolution: str | None
    resolved_at: datetime | None
    version: int
    created_at: datetime
    updated_at: datetime


class AlertStatusUpdate(BaseModel):
    """Optimistic-locking command for an investigation transition."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    status: AlertStatus
    expected_version: int = Field(ge=1)
    resolution: str | None = Field(default=None, min_length=3, max_length=4000)

    @model_validator(mode="after")
    def require_resolution_for_terminal_outcome(self) -> AlertStatusUpdate:
        terminal = {
            AlertStatus.CONFIRMED_FRAUD,
            AlertStatus.FALSE_POSITIVE,
            AlertStatus.CLOSED,
        }
        if self.status in terminal and not self.resolution:
            raise ValueError("resolution is required for a terminal alert status")
        return self


class AlertAssignment(BaseModel):
    """Assign an alert using optimistic concurrency control."""

    model_config = ConfigDict(extra="forbid")

    assigned_to_id: UUID
    expected_version: int = Field(ge=1)

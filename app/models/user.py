"""Tenant-scoped user and service-account persistence model."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, CheckConstraint, DateTime, Enum, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.security import Role
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.alert import Alert


class UserStatus(StrEnum):
    """Lifecycle state used to deny access without deleting audit history."""

    ACTIVE = "active"
    LOCKED = "locked"
    DISABLED = "disabled"


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Human analyst or machine producer authenticated by AegisGraph."""

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("tenant_id", "email", name="tenant_email"),
        CheckConstraint("failed_login_attempts >= 0", name="failed_login_attempts_nonnegative"),
        Index("ix_users_tenant_status", "tenant_id", "status"),
        Index("ix_users_tenant_role", "tenant_id", "role"),
    )

    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[Role] = mapped_column(
        Enum(Role, name="user_role", native_enum=False, length=32),
        default=Role.VIEWER,
        nullable=False,
    )
    status: Mapped[UserStatus] = mapped_column(
        Enum(UserStatus, name="user_status", native_enum=False, length=16),
        default=UserStatus.ACTIVE,
        nullable=False,
    )
    is_service_account: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    failed_login_attempts: Mapped[int] = mapped_column(default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    token_version: Mapped[int] = mapped_column(default=1, nullable=False)

    assigned_alerts: Mapped[list[Alert]] = relationship(
        back_populates="assignee",
        foreign_keys="Alert.assigned_to_id",
        lazy="raise",
    )

    @property
    def identity_key(self) -> str:
        """Return the normalized key used for tenant-local login lookup."""

        return f"{self.tenant_id}:{self.email.casefold()}"

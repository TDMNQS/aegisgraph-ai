"""Authentication and user-management request/response contracts."""

from __future__ import annotations

import re
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr, field_validator

from app.core.security import Role
from app.models.user import UserStatus

_TENANT_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{2,63}$")


class RegisterRequest(BaseModel):
    """Self-registration request; the first tenant member becomes its admin."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    tenant_id: str = Field(min_length=3, max_length=64)
    email: EmailStr
    display_name: str = Field(min_length=2, max_length=120)
    password: SecretStr = Field(min_length=12, max_length=128)

    @field_validator("tenant_id")
    @classmethod
    def normalize_tenant_id(cls, value: str) -> str:
        normalized = value.casefold()
        if not _TENANT_PATTERN.fullmatch(normalized):
            raise ValueError(
                "tenant_id must contain lowercase letters, digits, underscores, or hyphens"
            )
        return normalized


class LoginRequest(BaseModel):
    """Tenant-qualified credentials used to issue a token pair."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    tenant_id: str = Field(min_length=3, max_length=64)
    email: EmailStr
    password: SecretStr = Field(min_length=1, max_length=128)

    @field_validator("tenant_id")
    @classmethod
    def normalize_tenant_id(cls, value: str) -> str:
        return value.casefold()


class RefreshRequest(BaseModel):
    """Refresh token rotation request."""

    model_config = ConfigDict(extra="forbid")

    refresh_token: SecretStr = Field(min_length=32, max_length=4096)


class LogoutRequest(RefreshRequest):
    """Refresh token to revoke at logout."""


class UserRead(BaseModel):
    """Non-sensitive user representation returned by the API."""

    model_config = ConfigDict(from_attributes=True, extra="forbid", frozen=True)

    id: UUID
    tenant_id: str
    email: EmailStr
    display_name: str
    role: Role
    status: UserStatus
    is_service_account: bool
    created_at: datetime
    last_login_at: datetime | None

"""Authentication, password, token, and authorization security primitives.

The module keeps security decisions in one place so API routes never implement
their own password hashing, JWT parsing, or role checks. It maps directly to the
spoofing, repudiation, information-disclosure, and privilege-escalation controls
defined in the project threat model.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Literal

import jwt
from jwt import (
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidTokenError as JWTInvalidTokenError,
)
from pwdlib import PasswordHash
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.config import Settings, get_settings


class SecurityError(Exception):
    """Base class for security failures safe to translate into generic responses."""


class InvalidCredentialsError(SecurityError):
    """Raised when credentials cannot be authenticated."""


class InvalidTokenError(SecurityError):
    """Raised when a token is malformed, expired, or contextually invalid."""


class AuthorizationError(SecurityError):
    """Raised when an authenticated principal lacks a required permission."""


class PasswordPolicyError(SecurityError):
    """Raised when a new password does not satisfy the configured policy."""

    def __init__(self, violations: tuple[str, ...]) -> None:
        self.violations = violations
        super().__init__("password does not satisfy the security policy")


class TokenType(StrEnum):
    """JWT types accepted by AegisGraph."""

    ACCESS = "access"
    REFRESH = "refresh"


class Role(StrEnum):
    """Application roles ordered by responsibility, not implicit inheritance."""

    VIEWER = "viewer"
    ANALYST = "analyst"
    SENIOR_ANALYST = "senior_analyst"
    ADMIN = "admin"
    SERVICE = "service"


class Permission(StrEnum):
    """Fine-grained actions enforced by API dependencies."""

    TRANSACTION_CREATE = "transaction:create"
    TRANSACTION_READ = "transaction:read"
    ALERT_READ = "alert:read"
    ALERT_UPDATE = "alert:update"
    CASE_ASSIGN = "case:assign"
    CASE_REVIEW = "case:review"
    IDENTITY_DETOKENIZE = "identity:detokenize"
    RULE_MANAGE = "rule:manage"
    MODEL_MANAGE = "model:manage"
    USER_MANAGE = "user:manage"
    AUDIT_READ = "audit:read"


ROLE_PERMISSIONS: Mapping[Role, frozenset[Permission]] = MappingProxyType(
    {
        Role.VIEWER: frozenset(
            {
                Permission.TRANSACTION_READ,
                Permission.ALERT_READ,
            }
        ),
        Role.ANALYST: frozenset(
            {
                Permission.TRANSACTION_READ,
                Permission.ALERT_READ,
                Permission.ALERT_UPDATE,
                Permission.CASE_REVIEW,
            }
        ),
        Role.SENIOR_ANALYST: frozenset(
            {
                Permission.TRANSACTION_READ,
                Permission.ALERT_READ,
                Permission.ALERT_UPDATE,
                Permission.CASE_ASSIGN,
                Permission.CASE_REVIEW,
                Permission.IDENTITY_DETOKENIZE,
            }
        ),
        Role.ADMIN: frozenset(Permission),
        Role.SERVICE: frozenset(
            {
                Permission.TRANSACTION_CREATE,
                Permission.TRANSACTION_READ,
            }
        ),
    }
)


class TokenClaims(BaseModel):
    """Validated claims extracted from a signed JWT."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid", frozen=True)

    subject: str = Field(alias="sub", min_length=1, max_length=128)
    token_type: TokenType = Field(alias="type")
    role: Role
    tenant_id: str = Field(min_length=1, max_length=128)
    issued_at: datetime = Field(alias="iat")
    not_before: datetime = Field(alias="nbf")
    expires_at: datetime = Field(alias="exp")
    jwt_id: str = Field(alias="jti", min_length=16, max_length=128)
    issuer: str = Field(alias="iss")
    audience: str = Field(alias="aud")


class TokenPair(BaseModel):
    """Access and refresh credentials returned after authentication."""

    model_config = ConfigDict(frozen=True)

    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = Field(default="bearer")
    expires_in: int = Field(gt=0)


class PasswordVerification(BaseModel):
    """Password verification result with optional upgraded hash."""

    model_config = ConfigDict(frozen=True)

    valid: bool
    updated_hash: str | None = None


_PASSWORD_HASH = PasswordHash.recommended()
_SUPPORTED_JWT_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})
_SYMBOL_PATTERN = re.compile(r"[^A-Za-z0-9]")
_MIN_IDENTITY_FRAGMENT_LENGTH = 3
_MIN_OPAQUE_TOKEN_BYTES = 16
_MAX_OPAQUE_TOKEN_BYTES = 128


def validate_password_policy(
    password: str,
    *,
    settings: Settings | None = None,
    identity_fragments: tuple[str, ...] = (),
) -> None:
    """Validate a new password and raise a non-secret list of violations.

    Identity fragments may contain values such as a username or email local
    part. They are checked case-insensitively to discourage easily guessed
    account-specific passwords.
    """

    config = settings or get_settings()
    violations: list[str] = []

    if len(password) < config.password_min_length:
        violations.append(f"minimum length is {config.password_min_length}")
    if len(password) > config.password_max_length:
        violations.append(f"maximum length is {config.password_max_length}")
    if config.password_require_uppercase and not any(char.isupper() for char in password):
        violations.append("at least one uppercase character is required")
    if config.password_require_lowercase and not any(char.islower() for char in password):
        violations.append("at least one lowercase character is required")
    if config.password_require_digit and not any(char.isdigit() for char in password):
        violations.append("at least one digit is required")
    if config.password_require_symbol and _SYMBOL_PATTERN.search(password) is None:
        violations.append("at least one symbol is required")

    normalized_password = password.casefold()
    for fragment in identity_fragments:
        normalized_fragment = fragment.strip().casefold()
        if (
            len(normalized_fragment) >= _MIN_IDENTITY_FRAGMENT_LENGTH
            and normalized_fragment in normalized_password
        ):
            violations.append("password must not contain account identity information")
            break

    if violations:
        raise PasswordPolicyError(tuple(violations))


def hash_password(
    password: str,
    *,
    settings: Settings | None = None,
    identity_fragments: tuple[str, ...] = (),
) -> str:
    """Validate and hash a password using the recommended Argon2 profile."""

    validate_password_policy(
        password,
        settings=settings,
        identity_fragments=identity_fragments,
    )
    return _PASSWORD_HASH.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password without exposing library-specific exceptions."""

    try:
        return _PASSWORD_HASH.verify(password, password_hash)
    except (TypeError, ValueError):
        return False


def verify_password_and_update(password: str, password_hash: str) -> PasswordVerification:
    """Verify a password and return a stronger replacement hash when required."""

    try:
        valid, updated_hash = _PASSWORD_HASH.verify_and_update(password, password_hash)
    except (TypeError, ValueError):
        return PasswordVerification(valid=False)
    return PasswordVerification(valid=valid, updated_hash=updated_hash)


def create_access_token(
    *,
    subject: str,
    role: Role,
    tenant_id: str,
    settings: Settings | None = None,
    now: datetime | None = None,
) -> str:
    """Create a short-lived access JWT."""

    config = settings or get_settings()
    issued_at = _normalize_utc(now)
    return _encode_token(
        subject=subject,
        role=role,
        tenant_id=tenant_id,
        token_type=TokenType.ACCESS,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=config.access_token_expire_minutes),
        settings=config,
    )


def create_refresh_token(
    *,
    subject: str,
    role: Role,
    tenant_id: str,
    settings: Settings | None = None,
    now: datetime | None = None,
) -> str:
    """Create a refresh JWT intended for rotation and server-side revocation."""

    config = settings or get_settings()
    issued_at = _normalize_utc(now)
    return _encode_token(
        subject=subject,
        role=role,
        tenant_id=tenant_id,
        token_type=TokenType.REFRESH,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(days=config.refresh_token_expire_days),
        settings=config,
    )


def create_token_pair(
    *,
    subject: str,
    role: Role,
    tenant_id: str,
    settings: Settings | None = None,
    now: datetime | None = None,
) -> TokenPair:
    """Create access and refresh tokens from one consistent issue time."""

    config = settings or get_settings()
    issued_at = _normalize_utc(now)
    return TokenPair(
        access_token=create_access_token(
            subject=subject,
            role=role,
            tenant_id=tenant_id,
            settings=config,
            now=issued_at,
        ),
        refresh_token=create_refresh_token(
            subject=subject,
            role=role,
            tenant_id=tenant_id,
            settings=config,
            now=issued_at,
        ),
        expires_in=config.access_token_expire_minutes * 60,
    )


def decode_token(
    token: str,
    *,
    expected_type: TokenType,
    settings: Settings | None = None,
) -> TokenClaims:
    """Verify signature and registered claims, then enforce the token context."""

    config = settings or get_settings()
    _validate_jwt_algorithm(config.jwt_algorithm)

    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            key=config.jwt_secret_key.get_secret_value(),
            algorithms=[config.jwt_algorithm],
            audience=config.jwt_audience,
            issuer=config.jwt_issuer,
            leeway=config.clock_skew_seconds,
            options={
                "require": ["sub", "type", "role", "tenant_id", "iat", "nbf", "exp", "jti"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )
        claims = TokenClaims.model_validate(payload)
    except (
        ExpiredSignatureError,
        ImmatureSignatureError,
        InvalidAudienceError,
        InvalidIssuerError,
        JWTInvalidTokenError,
        ValidationError,
        ValueError,
    ) as exc:
        raise InvalidTokenError("token validation failed") from exc

    if claims.token_type is not expected_type:
        raise InvalidTokenError("token type is not valid for this operation")
    return claims


def require_permission(role: Role, permission: Permission) -> None:
    """Raise when a role does not explicitly contain a permission."""

    if permission not in ROLE_PERMISSIONS.get(role, frozenset()):
        raise AuthorizationError("permission denied")


def has_permission(role: Role, permission: Permission) -> bool:
    """Return whether the role explicitly grants a permission."""

    return permission in ROLE_PERMISSIONS.get(role, frozenset())


def hash_refresh_token(token: str) -> str:
    """Create a one-way digest for refresh-token revocation storage."""

    if not token:
        raise ValueError("refresh token cannot be empty")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def tokens_match(candidate_token: str, expected_digest: str) -> bool:
    """Compare a candidate token with a stored digest in constant time."""

    candidate_digest = hash_refresh_token(candidate_token)
    return hmac.compare_digest(candidate_digest, expected_digest)


def generate_opaque_token(byte_length: int = 32) -> str:
    """Generate a cryptographically secure token for CSRF or one-time actions."""

    if not _MIN_OPAQUE_TOKEN_BYTES <= byte_length <= _MAX_OPAQUE_TOKEN_BYTES:
        raise ValueError("byte_length must be between 16 and 128")
    return secrets.token_urlsafe(byte_length)


def _encode_token(
    *,
    subject: str,
    role: Role,
    tenant_id: str,
    token_type: TokenType,
    issued_at: datetime,
    expires_at: datetime,
    settings: Settings,
) -> str:
    """Encode a JWT after validating its identity and algorithm inputs."""

    if not subject.strip() or not tenant_id.strip():
        raise ValueError("subject and tenant_id are required")
    _validate_jwt_algorithm(settings.jwt_algorithm)

    claims = TokenClaims(
        subject=subject,
        token_type=token_type,
        role=role,
        tenant_id=tenant_id,
        issued_at=issued_at,
        not_before=issued_at,
        expires_at=expires_at,
        jwt_id=secrets.token_urlsafe(24),
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
    )
    payload = claims.model_dump(mode="python", by_alias=True)
    return jwt.encode(
        payload,
        key=settings.jwt_secret_key.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )


def _validate_jwt_algorithm(algorithm: str) -> None:
    """Prevent algorithm confusion through unexpected runtime configuration."""

    if algorithm not in _SUPPORTED_JWT_ALGORITHMS:
        raise ValueError(f"unsupported JWT algorithm: {algorithm}")


def _normalize_utc(value: datetime | None) -> datetime:
    """Return a timezone-aware UTC issue time."""

    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("token timestamps must be timezone-aware")
    return current.astimezone(UTC)

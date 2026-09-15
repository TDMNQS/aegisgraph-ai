"""Shared FastAPI dependencies for authentication, authorization, and services."""

from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.security import (
    ROLE_PERMISSIONS,
    InvalidTokenError,
    Permission,
    Role,
    TokenType,
    decode_token,
)
from app.db.base import get_db_session
from app.models.user import User, UserStatus


@dataclass(frozen=True, slots=True)
class Principal:
    """Authenticated request identity after JWT and database validation."""

    user_id: UUID
    tenant_id: str
    role: Role
    permissions: frozenset[Permission]


bearer_scheme = HTTPBearer(auto_error=False)
DBSession = Annotated[AsyncSession, Depends(get_db_session)]
AppSettings = Annotated[Settings, Depends(get_settings)]

_redis_state: dict[str, Redis] = {}


def get_redis_client(settings: Settings | None = None) -> Redis:
    """Return one lazily-created async Redis client per process."""

    client = _redis_state.get("client")
    if client is None:
        config = settings or get_settings()
        client = Redis.from_url(
            config.redis_url.get_secret_value(),
            encoding="utf-8",
            decode_responses=True,
            socket_timeout=config.redis_socket_timeout_seconds,
            socket_connect_timeout=config.redis_connect_timeout_seconds,
            max_connections=config.redis_max_connections,
            health_check_interval=30,
        )
        _redis_state["client"] = client
    return client


async def get_redis() -> AsyncGenerator[Redis]:
    """Expose the shared Redis client without closing it after each request."""

    yield get_redis_client()


RedisClient = Annotated[Redis, Depends(get_redis)]


async def close_redis_client() -> None:
    """Close Redis connections during application shutdown."""

    client = _redis_state.pop("client", None)
    if client is not None:
        await client.aclose()


async def get_current_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    session: DBSession,
    settings: AppSettings,
) -> Principal:
    """Validate an access token and re-check mutable account state."""

    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None or credentials.scheme.casefold() != "bearer":
        raise unauthorized

    try:
        claims = decode_token(
            credentials.credentials,
            expected_type=TokenType.ACCESS,
            settings=settings,
        )
        user_id = UUID(claims.subject)
    except (InvalidTokenError, ValueError) as exc:
        raise unauthorized from exc

    user = await session.scalar(
        select(User).where(
            User.id == user_id,
            User.tenant_id == claims.tenant_id,
        )
    )
    if user is None or user.status is not UserStatus.ACTIVE or user.role is not claims.role:
        raise unauthorized

    return Principal(
        user_id=user.id,
        tenant_id=user.tenant_id,
        role=user.role,
        permissions=ROLE_PERMISSIONS[user.role],
    )


CurrentPrincipal = Annotated[Principal, Depends(get_current_principal)]
PermissionDependency = Callable[..., Awaitable[Principal]]


def require_permissions(*required: Permission) -> PermissionDependency:
    """Build a dependency that requires every named permission."""

    required_set = frozenset(required)

    async def dependency(principal: CurrentPrincipal) -> Principal:
        if not required_set.issubset(principal.permissions):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action",
            )
        return principal

    return dependency

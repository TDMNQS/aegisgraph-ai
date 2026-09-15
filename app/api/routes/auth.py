"""Registration, login, refresh rotation, logout, and identity endpoints."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, HTTPException, Response, status
from redis.exceptions import RedisError
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError

from app.api.deps import AppSettings, CurrentPrincipal, DBSession, RedisClient
from app.core.security import (
    InvalidTokenError,
    PasswordPolicyError,
    Role,
    TokenPair,
    TokenType,
    create_token_pair,
    decode_token,
    hash_password,
    hash_refresh_token,
    verify_password_and_update,
)
from app.models.user import User, UserStatus
from app.schemas.auth import LoginRequest, LogoutRequest, RefreshRequest, RegisterRequest, UserRead

router = APIRouter(prefix="/auth", tags=["authentication"])


def _revocation_key(prefix: str, token: str) -> str:
    return f"{prefix}:auth:revoked:{hash_refresh_token(token)}"


async def _revoke_refresh_token(
    token: str,
    *,
    expires_at: datetime,
    redis: RedisClient,
    prefix: str,
) -> None:
    ttl_seconds = max(1, int((expires_at - datetime.now(UTC)).total_seconds()))
    try:
        await redis.set(_revocation_key(prefix, token), "1", ex=ttl_seconds, nx=True)
    except RedisError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication session store is unavailable",
        ) from exc


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def register(
    payload: RegisterRequest,
    session: DBSession,
    settings: AppSettings,
) -> User:
    """Create an account; bootstrap the first account in a tenant as admin."""

    normalized_email = str(payload.email).casefold()
    try:
        password_hash = hash_password(
            payload.password.get_secret_value(),
            settings=settings,
            identity_fragments=(normalized_email.partition("@")[0], payload.display_name),
        )
    except PasswordPolicyError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"message": "Password does not meet policy", "violations": exc.violations},
        ) from exc

    # PostgreSQL transaction-scoped lock prevents two concurrent first-admin accounts.
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:tenant_id))"),
        {"tenant_id": payload.tenant_id},
    )
    existing_count = await session.scalar(
        select(func.count(User.id)).where(User.tenant_id == payload.tenant_id)
    )
    user = User(
        tenant_id=payload.tenant_id,
        email=normalized_email,
        display_name=payload.display_name,
        password_hash=password_hash,
        role=Role.ADMIN if existing_count == 0 else Role.VIEWER,
        status=UserStatus.ACTIVE,
    )
    session.add(user)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists in the tenant",
        ) from exc
    await session.refresh(user)
    return user


@router.post("/login", response_model=TokenPair)
async def login(
    payload: LoginRequest,
    session: DBSession,
    settings: AppSettings,
) -> TokenPair:
    """Authenticate credentials and issue access/refresh JWTs."""

    now = datetime.now(UTC)
    user = await session.scalar(
        select(User)
        .where(
            User.tenant_id == payload.tenant_id,
            User.email == str(payload.email).casefold(),
        )
        .with_for_update()
    )
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid tenant, email, or password",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if user is None or user.status is UserStatus.DISABLED:
        raise unauthorized
    if user.locked_until is not None and user.locked_until > now:
        raise unauthorized

    verification = verify_password_and_update(
        payload.password.get_secret_value(),
        user.password_hash,
    )
    if not verification.valid:
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= settings.max_login_attempts:
            user.status = UserStatus.LOCKED
            user.locked_until = now + timedelta(minutes=settings.account_lock_minutes)
        await session.commit()
        raise unauthorized

    if user.status is UserStatus.LOCKED and user.locked_until is not None:
        user.status = UserStatus.ACTIVE
        user.locked_until = None
    user.failed_login_attempts = 0
    user.last_login_at = now
    if verification.updated_hash is not None:
        user.password_hash = verification.updated_hash
    await session.commit()
    return create_token_pair(
        subject=str(user.id),
        role=user.role,
        tenant_id=user.tenant_id,
        settings=settings,
        now=now,
    )


@router.post("/refresh", response_model=TokenPair)
async def refresh(
    payload: RefreshRequest,
    session: DBSession,
    redis: RedisClient,
    settings: AppSettings,
) -> TokenPair:
    """Rotate a valid refresh token and revoke the consumed credential."""

    raw_token = payload.refresh_token.get_secret_value()
    try:
        claims = decode_token(raw_token, expected_type=TokenType.REFRESH, settings=settings)
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        ) from exc

    try:
        revoked = await redis.exists(_revocation_key(settings.redis_prefix, raw_token))
    except RedisError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication session store is unavailable",
        ) from exc
    if revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    try:
        user_id = UUID(claims.subject)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        ) from exc
    user = await session.scalar(
        select(User).where(
            User.id == user_id,
            User.tenant_id == claims.tenant_id,
            User.status == UserStatus.ACTIVE,
        )
    )
    if user is None or user.role is not claims.role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    await _revoke_refresh_token(
        raw_token,
        expires_at=claims.expires_at,
        redis=redis,
        prefix=settings.redis_prefix,
    )
    return create_token_pair(
        subject=str(user.id),
        role=user.role,
        tenant_id=user.tenant_id,
        settings=settings,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    payload: LogoutRequest,
    redis: RedisClient,
    settings: AppSettings,
) -> Response:
    """Revoke a refresh token; invalid credentials remain idempotent."""

    raw_token = payload.refresh_token.get_secret_value()
    try:
        claims = decode_token(raw_token, expected_type=TokenType.REFRESH, settings=settings)
    except InvalidTokenError:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    await _revoke_refresh_token(
        raw_token,
        expires_at=claims.expires_at,
        redis=redis,
        prefix=settings.redis_prefix,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=UserRead)
async def read_current_user(principal: CurrentPrincipal, session: DBSession) -> User:
    """Return the currently authenticated database identity."""

    user = await session.get(User, principal.user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user

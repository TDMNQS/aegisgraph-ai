"""Tenant-isolated fraud-alert investigation endpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select

from app.api.deps import DBSession, Principal, require_permissions
from app.core.security import Permission
from app.models.alert import Alert, AlertStatus
from app.models.user import User, UserStatus
from app.schemas.alert import AlertAssignment, AlertRead, AlertStatusUpdate

router = APIRouter(prefix="/alerts", tags=["alerts"])
CanReadAlerts = Annotated[Principal, Depends(require_permissions(Permission.ALERT_READ))]
CanUpdateAlerts = Annotated[
    Principal,
    Depends(require_permissions(Permission.ALERT_UPDATE)),
]
CanAssignAlerts = Annotated[
    Principal,
    Depends(require_permissions(Permission.CASE_ASSIGN)),
]

_TRANSITIONS: dict[AlertStatus, frozenset[AlertStatus]] = {
    AlertStatus.OPEN: frozenset(
        {AlertStatus.ASSIGNED, AlertStatus.INVESTIGATING, AlertStatus.FALSE_POSITIVE}
    ),
    AlertStatus.ASSIGNED: frozenset({AlertStatus.OPEN, AlertStatus.INVESTIGATING}),
    AlertStatus.INVESTIGATING: frozenset(
        {AlertStatus.ASSIGNED, AlertStatus.CONFIRMED_FRAUD, AlertStatus.FALSE_POSITIVE}
    ),
    AlertStatus.CONFIRMED_FRAUD: frozenset({AlertStatus.INVESTIGATING, AlertStatus.CLOSED}),
    AlertStatus.FALSE_POSITIVE: frozenset({AlertStatus.INVESTIGATING, AlertStatus.CLOSED}),
    AlertStatus.CLOSED: frozenset(),
}


async def _locked_alert(alert_id: UUID, tenant_id: str, session: DBSession) -> Alert:
    alert = await session.scalar(
        select(Alert).where(Alert.id == alert_id, Alert.tenant_id == tenant_id).with_for_update()
    )
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert


@router.get("", response_model=list[AlertRead])
async def list_alerts(
    principal: CanReadAlerts,
    session: DBSession,
    alert_status: AlertStatus | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[Alert]:
    """List alerts for the authenticated tenant with bounded results."""

    statement = select(Alert).where(Alert.tenant_id == principal.tenant_id)
    if alert_status is not None:
        statement = statement.where(Alert.status == alert_status)
    result = await session.scalars(statement.order_by(Alert.created_at.desc()).limit(limit))
    return list(result.unique())


@router.get("/{alert_id}", response_model=AlertRead)
async def get_alert(alert_id: UUID, principal: CanReadAlerts, session: DBSession) -> Alert:
    """Retrieve one alert without revealing whether another tenant owns it."""

    alert = await session.scalar(
        select(Alert).where(Alert.id == alert_id, Alert.tenant_id == principal.tenant_id)
    )
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert


@router.patch("/{alert_id}/status", response_model=AlertRead)
async def update_alert_status(
    alert_id: UUID,
    payload: AlertStatusUpdate,
    principal: CanUpdateAlerts,
    session: DBSession,
) -> Alert:
    """Apply a valid state transition with optimistic concurrency control."""

    alert = await _locked_alert(alert_id, principal.tenant_id, session)
    if alert.version != payload.expected_version:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Alert was modified; reload it before updating",
        )
    if payload.status not in _TRANSITIONS[alert.status]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot transition alert from {alert.status} to {payload.status}",
        )

    alert.status = payload.status
    alert.resolution = payload.resolution
    alert.version += 1
    if payload.status is AlertStatus.CLOSED:
        alert.resolved_at = datetime.now(UTC)
    elif payload.status is AlertStatus.INVESTIGATING:
        alert.resolved_at = None
    await session.commit()
    await session.refresh(alert)
    return alert


@router.patch("/{alert_id}/assignment", response_model=AlertRead)
async def assign_alert(
    alert_id: UUID,
    payload: AlertAssignment,
    principal: CanAssignAlerts,
    session: DBSession,
) -> Alert:
    """Assign an active same-tenant analyst to an alert."""

    alert = await _locked_alert(alert_id, principal.tenant_id, session)
    if alert.version != payload.expected_version:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Alert was modified; reload it before assigning",
        )
    assignee = await session.scalar(
        select(User).where(
            User.id == payload.assigned_to_id,
            User.tenant_id == principal.tenant_id,
            User.status == UserStatus.ACTIVE,
        )
    )
    if assignee is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assignee not found")

    alert.assigned_to_id = assignee.id
    alert.assigned_at = datetime.now(UTC)
    alert.status = AlertStatus.ASSIGNED
    alert.version += 1
    await session.commit()
    await session.refresh(alert)
    return alert

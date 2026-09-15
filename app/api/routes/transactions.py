"""Tenant-isolated transaction ingestion and query endpoints."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.api.deps import DBSession, Principal, require_permissions
from app.core.security import Permission
from app.models.transaction import Transaction
from app.schemas.transaction import TransactionCreate, TransactionRead

router = APIRouter(prefix="/transactions", tags=["transactions"])
CanCreateTransaction = Annotated[
    Principal,
    Depends(require_permissions(Permission.TRANSACTION_CREATE)),
]
CanReadTransaction = Annotated[
    Principal,
    Depends(require_permissions(Permission.TRANSACTION_READ)),
]


def _event_fingerprint(payload: TransactionCreate, tenant_id: str) -> str:
    canonical = json.dumps(
        {"tenant_id": tenant_id, **payload.model_dump(mode="json")},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@router.post("", response_model=TransactionRead, status_code=status.HTTP_202_ACCEPTED)
async def create_transaction(
    payload: TransactionCreate,
    response: Response,
    principal: CanCreateTransaction,
    session: DBSession,
) -> Transaction:
    """Persist a tokenized event exactly once and queue it for later scoring."""

    existing = await session.scalar(
        select(Transaction).where(
            Transaction.tenant_id == principal.tenant_id,
            Transaction.idempotency_key == payload.idempotency_key,
        )
    )
    if existing is not None:
        response.status_code = status.HTTP_200_OK
        return existing

    location = payload.location
    transaction = Transaction(
        tenant_id=principal.tenant_id,
        external_id=payload.external_id,
        idempotency_key=payload.idempotency_key,
        event_fingerprint=_event_fingerprint(payload, principal.tenant_id),
        amount=payload.amount,
        currency=payload.currency,
        merchant_id=payload.merchant_id,
        merchant_category_code=payload.merchant_category_code,
        channel=payload.channel,
        occurred_at=payload.occurred_at,
        customer_token=payload.customer_token,
        account_token=payload.account_token,
        device_token=payload.device_token,
        ip_token=payload.ip_token,
        country_code=location.country_code if location else None,
        latitude=location.latitude if location else None,
        longitude=location.longitude if location else None,
        features={"producer_attributes": payload.attributes},
    )
    session.add(transaction)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        duplicate = await session.scalar(
            select(Transaction).where(
                Transaction.tenant_id == principal.tenant_id,
                Transaction.idempotency_key == payload.idempotency_key,
            )
        )
        if duplicate is not None:
            response.status_code = status.HTTP_200_OK
            return duplicate
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Transaction external_id already exists for this tenant",
        ) from exc
    await session.refresh(transaction)
    return transaction


@router.get("", response_model=list[TransactionRead])
async def list_transactions(
    principal: CanReadTransaction,
    session: DBSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    before: datetime | None = None,
) -> list[Transaction]:
    """List newest tenant transactions using bounded keyset pagination."""

    statement = select(Transaction).where(Transaction.tenant_id == principal.tenant_id)
    if before is not None:
        statement = statement.where(Transaction.occurred_at < before)
    result = await session.scalars(
        statement.order_by(Transaction.occurred_at.desc(), Transaction.id.desc()).limit(limit)
    )
    return list(result)


@router.get("/{transaction_id}", response_model=TransactionRead)
async def get_transaction(
    transaction_id: UUID,
    principal: CanReadTransaction,
    session: DBSession,
) -> Transaction:
    """Retrieve one transaction without allowing cross-tenant discovery."""

    transaction = await session.scalar(
        select(Transaction).where(
            Transaction.id == transaction_id,
            Transaction.tenant_id == principal.tenant_id,
        )
    )
    if transaction is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transaction not found")
    return transaction

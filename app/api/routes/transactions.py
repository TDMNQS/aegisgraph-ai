"""Tenant-isolated transaction ingestion, scoring, and query endpoints."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.api.deps import AppSettings, DBSession, Principal, require_permissions
from app.core.security import Permission
from app.models.transaction import Transaction
from app.schemas.transaction import (
    FraudDemoRequest,
    FraudDemoScenario,
    LocationInput,
    TransactionCreate,
    TransactionRead,
)
from app.services.scoring import FraudScoringService, RiskFeatures

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


def _new_transaction(payload: TransactionCreate, tenant_id: str) -> Transaction:
    location = payload.location
    return Transaction(
        tenant_id=tenant_id,
        external_id=payload.external_id,
        idempotency_key=payload.idempotency_key,
        event_fingerprint=_event_fingerprint(payload, tenant_id),
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


async def _persist_and_score(
    payload: TransactionCreate,
    *,
    tenant_id: str,
    session: DBSession,
    settings: AppSettings,
    feature_overrides: RiskFeatures | None = None,
) -> Transaction:
    transaction = _new_transaction(payload, tenant_id)
    session.add(transaction)
    try:
        await session.flush()
        await FraudScoringService(settings).score_transaction(
            session,
            transaction,
            feature_overrides=feature_overrides,
        )
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        duplicate = await session.scalar(
            select(Transaction).where(
                Transaction.tenant_id == tenant_id,
                Transaction.idempotency_key == payload.idempotency_key,
            )
        )
        if duplicate is not None:
            return duplicate
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Transaction external_id already exists for this tenant",
        ) from exc
    await session.refresh(transaction)
    return transaction


@router.post("", response_model=TransactionRead, status_code=status.HTTP_201_CREATED)
async def create_transaction(
    payload: TransactionCreate,
    response: Response,
    principal: CanCreateTransaction,
    session: DBSession,
    settings: AppSettings,
) -> Transaction:
    """Persist, score, and explain a tokenized event atomically."""

    existing = await session.scalar(
        select(Transaction).where(
            Transaction.tenant_id == principal.tenant_id,
            Transaction.idempotency_key == payload.idempotency_key,
        )
    )
    if existing is not None:
        response.status_code = status.HTTP_200_OK
        return existing
    return await _persist_and_score(
        payload,
        tenant_id=principal.tenant_id,
        session=session,
        settings=settings,
    )


@router.post("/demo", response_model=TransactionRead, status_code=status.HTTP_201_CREATED)
async def simulate_transaction(
    payload: FraudDemoRequest,
    principal: CanCreateTransaction,
    session: DBSession,
    settings: AppSettings,
) -> Transaction:
    """Create a fully synthetic payment to demonstrate an end-to-end decision."""

    now = datetime.now(UTC)
    unique = uuid4().hex
    scenario = payload.scenario
    amount = Decimal("1200") if scenario is FraudDemoScenario.NORMAL else Decimal("150000")
    transaction = TransactionCreate(
        external_id=f"demo-{scenario.value}-{unique[:12]}",
        idempotency_key=f"demo-idempotency-{unique}",
        amount=amount,
        currency="INR",
        merchant_id=f"demo-merchant-{scenario.value}",
        merchant_category_code="5734",
        channel="api",
        occurred_at=now,
        customer_token=f"customer_demo_{unique}",
        account_token=f"account_demo_{unique}",
        device_token=f"device_demo_{unique}",
        ip_token=f"ip_demo_{unique}",
        location=LocationInput(
            country_code="IN",
            latitude=Decimal("19.076"),
            longitude=Decimal("72.8777"),
        ),
        attributes={"synthetic_demo": True, "scenario": scenario.value},
    )
    overrides: RiskFeatures | None = None
    if scenario is FraudDemoScenario.ACCOUNT_TAKEOVER:
        overrides = RiskFeatures(
            transactions_in_velocity_window=15,
            customer_average_amount_30d=Decimal("5000"),
            device_first_seen_at=now - timedelta(minutes=15),
            travel_speed_kmh=1600,
            merchant_risk_score=0.91,
            failed_attempts_1h=6,
            account_denylisted=True,
        )
    elif scenario is FraudDemoScenario.FRAUD_RING:
        overrides = RiskFeatures(
            transactions_in_velocity_window=20,
            customer_average_amount_30d=Decimal("2500"),
            device_first_seen_at=now - timedelta(minutes=5),
            merchant_risk_score=0.98,
            device_denylisted=True,
        )
    return await _persist_and_score(
        transaction,
        tenant_id=principal.tenant_id,
        session=session,
        settings=settings,
        feature_overrides=overrides,
    )


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

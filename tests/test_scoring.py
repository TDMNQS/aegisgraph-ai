"""Focused tests for API-to-alert scoring integration."""

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from app.core.config import Settings
from app.models.transaction import PaymentDecision, Transaction
from app.services.scoring import FraudScoringService, RiskFeatures

NOW = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
MINIMUM_DEMO_RISK = 0.79


def transaction(amount: str = "1000") -> Transaction:
    return Transaction(
        tenant_id="test-tenant",
        external_id="payment-001",
        idempotency_key="idempotency-0001",
        event_fingerprint="a" * 64,
        amount=Decimal(amount),
        currency="INR",
        merchant_id="merchant-001",
        channel="api",
        occurred_at=NOW,
        customer_token="customer_token_001",  # noqa: S106 - synthetic irreversible token
        account_token="account_token_001",  # noqa: S106 - synthetic irreversible token
    )


def service() -> FraudScoringService:
    return FraudScoringService(Settings(enforce_secure_configuration=False))


def test_normal_transaction_is_allowed_without_alert() -> None:
    outcome = service().evaluate(transaction(), RiskFeatures())

    assert outcome.decision is PaymentDecision.ALLOW
    assert outcome.risk_score == 0
    assert outcome.alert is None


def test_high_risk_simulation_creates_explainable_alert() -> None:
    item = transaction("150000")
    outcome = service().evaluate(
        item,
        RiskFeatures(
            transactions_in_velocity_window=15,
            customer_average_amount_30d=Decimal("5000"),
            device_first_seen_at=NOW - timedelta(minutes=20),
            travel_speed_kmh=1600,
            merchant_risk_score=0.95,
            failed_attempts_1h=6,
            account_denylisted=True,
        ),
    )

    assert outcome.decision is PaymentDecision.REVIEW
    assert outcome.risk_score >= MINIMUM_DEMO_RISK
    assert outcome.alert is not None
    assert "ACCOUNT_DENYLISTED" in outcome.reason_codes
    assert outcome.explanation["rules"]

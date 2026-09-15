"""Focused tests for deterministic and explainable fraud rules."""

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from app.services.rules_engine import RuleCode, RuleContext, RulesEngine, RulesPolicy


NOW = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)


def context(**overrides: object) -> RuleContext:
    values: dict[str, object] = {"amount": Decimal("1000"), "occurred_at": NOW}
    values.update(overrides)
    return RuleContext(**values)  # type: ignore[arg-type]


def test_normal_transaction_has_zero_score() -> None:
    result = RulesEngine(RulesPolicy()).evaluate(context())

    assert result.score == 0
    assert result.reason_codes == ()
    assert result.confidence == 0.75


def test_denylisted_account_is_near_certain_risk() -> None:
    result = RulesEngine(RulesPolicy()).evaluate(context(account_denylisted=True))

    assert result.score == pytest.approx(0.99)
    assert result.reason_codes == (RuleCode.ACCOUNT_DENYLISTED.value,)


def test_combined_signals_increase_risk_and_are_ordered() -> None:
    result = RulesEngine(RulesPolicy()).evaluate(
        context(
            amount=Decimal("100000"),
            transactions_in_velocity_window=12,
            device_first_seen_at=NOW - timedelta(hours=1),
            travel_speed_kmh=1300.0,
        )
    )

    assert result.score > 0.95
    assert result.reason_codes[0] == RuleCode.RAPID_VELOCITY.value
    assert set(result.reason_codes) == {
        RuleCode.HIGH_VALUE.value,
        RuleCode.RAPID_VELOCITY.value,
        RuleCode.NEW_DEVICE.value,
        RuleCode.IMPOSSIBLE_TRAVEL.value,
    }


def test_amount_spike_uses_customer_baseline() -> None:
    result = RulesEngine(RulesPolicy()).evaluate(
        context(
            amount=Decimal("6000"),
            customer_average_amount_30d=Decimal("1000"),
        )
    )

    assert result.reason_codes == (RuleCode.AMOUNT_SPIKE.value,)
    assert result.signals[0].evidence["multiple_of_average"] == 6.0


def test_optional_features_raise_confidence() -> None:
    result = RulesEngine(RulesPolicy()).evaluate(
        context(
            customer_average_amount_30d=Decimal("1000"),
            device_first_seen_at=NOW - timedelta(days=30),
            travel_speed_kmh=10.0,
            merchant_risk_score=0.1,
        )
    )

    assert result.confidence == 1.0


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"amount": Decimal("0")}, "amount must be positive"),
        ({"transactions_in_velocity_window": -1}, "counter features cannot be negative"),
        ({"merchant_risk_score": 1.1}, "merchant_risk_score"),
    ],
)
def test_invalid_context_is_rejected(override: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        context(**override)

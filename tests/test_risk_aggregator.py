"""Decision-boundary and degraded-mode tests for hybrid risk aggregation."""

import pytest

from app.models.transaction import PaymentDecision
from app.services.risk_aggregator import (
    ComponentName,
    ComponentScore,
    RiskAggregator,
    RiskPolicy,
)

DEGRADED_SCORE_CAP = 0.8


def all_components(score: float, confidence: float = 1.0) -> dict[ComponentName, ComponentScore]:
    return {
        name: ComponentScore(
            score=score,
            confidence=confidence,
            reason_codes=(f"{name.value.upper()}_SIGNAL",),
            version="1.0",
            latency_ms=2.5,
        )
        for name in ComponentName
    }


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.20, PaymentDecision.ALLOW),
        (0.55, PaymentDecision.REVIEW),
        (0.82, PaymentDecision.BLOCK),
    ],
)
def test_decision_thresholds(score: float, expected: PaymentDecision) -> None:
    result = RiskAggregator(RiskPolicy()).aggregate(all_components(score))

    assert result.decision is expected
    assert result.risk_score == pytest.approx(score)


def test_weights_are_applied_exactly() -> None:
    components = all_components(0.0)
    components[ComponentName.RULES] = ComponentScore(score=1.0, confidence=1.0)

    result = RiskAggregator(RiskPolicy()).aggregate(components)

    assert result.risk_score == pytest.approx(0.35)
    assert result.decision is PaymentDecision.ALLOW


def test_missing_component_is_reported_and_available_weights_are_normalized() -> None:
    components = all_components(0.8)
    components.pop(ComponentName.GRAPH)

    result = RiskAggregator(RiskPolicy()).aggregate(components)

    assert result.risk_score == pytest.approx(0.8)
    assert result.confidence == pytest.approx(1.0)
    assert result.degraded_components == (ComponentName.GRAPH,)
    assert result.decision is PaymentDecision.REVIEW


def test_degraded_score_is_capped_to_prevent_unsupported_auto_block() -> None:
    components = {
        ComponentName.RULES: ComponentScore(score=1.0, confidence=1.0),
    }

    result = RiskAggregator(RiskPolicy(degraded_score_cap=DEGRADED_SCORE_CAP)).aggregate(components)

    assert result.risk_score == DEGRADED_SCORE_CAP
    assert result.decision is PaymentDecision.REVIEW


def test_degraded_confidence_is_normalized_over_available_weights() -> None:
    components = {
        ComponentName.RULES: ComponentScore(score=0.1, confidence=0.9),
        ComponentName.IDENTITY: ComponentScore(score=0.0, confidence=0.9),
    }

    result = RiskAggregator(RiskPolicy()).aggregate(components)

    assert result.confidence == pytest.approx(0.9)
    assert result.decision is PaymentDecision.ALLOW


def test_fail_closed_policy_returns_error_when_component_is_missing() -> None:
    components = all_components(0.2)
    components[ComponentName.ML] = ComponentScore.unavailable("MODEL_TIMEOUT")

    result = RiskAggregator(RiskPolicy(allow_degraded_scoring=False)).aggregate(components)

    assert result.decision is PaymentDecision.ERROR
    assert result.risk_score == 1.0
    assert "SCORING_UNAVAILABLE" in result.reason_codes


def test_no_available_components_returns_error() -> None:
    components = {
        name: ComponentScore.unavailable(f"{name.value.upper()}_UNAVAILABLE")
        for name in ComponentName
    }

    result = RiskAggregator(RiskPolicy()).aggregate(components)

    assert result.decision is PaymentDecision.ERROR
    assert set(result.degraded_components) == set(ComponentName)


def test_low_confidence_is_escalated_to_review() -> None:
    result = RiskAggregator(RiskPolicy()).aggregate(all_components(0.1, confidence=0.4))

    assert result.decision is PaymentDecision.REVIEW
    assert result.confidence == pytest.approx(0.4)


def test_invalid_weight_policy_is_rejected() -> None:
    with pytest.raises(ValueError, match="sum to one"):
        RiskPolicy(
            weights={
                ComponentName.RULES: 0.5,
                ComponentName.ML: 0.5,
                ComponentName.GRAPH: 0.5,
                ComponentName.IDENTITY: 0.5,
            }
        )

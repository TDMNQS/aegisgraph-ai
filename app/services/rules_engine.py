"""Deterministic and explainable payment-fraud rules.

The engine is deliberately pure: it receives a feature context and returns a
decision signal without database, cache, or network access. Feature collection
belongs to the ingestion pipeline, making the rules easy to audit and test.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from typing import Any

from app.core.config import Settings


class RuleCode(StrEnum):
    """Stable reason codes stored with a fraud decision."""

    ACCOUNT_DENYLISTED = "ACCOUNT_DENYLISTED"
    DEVICE_DENYLISTED = "DEVICE_DENYLISTED"
    HIGH_VALUE = "HIGH_VALUE"
    RAPID_VELOCITY = "RAPID_VELOCITY"
    AMOUNT_SPIKE = "AMOUNT_SPIKE"
    IMPOSSIBLE_TRAVEL = "IMPOSSIBLE_TRAVEL"
    NEW_DEVICE = "NEW_DEVICE"
    RISKY_MERCHANT = "RISKY_MERCHANT"
    REPEATED_FAILURES = "REPEATED_FAILURES"


@dataclass(frozen=True, slots=True)
class RulesPolicy:
    """Versioned rule thresholds independent of infrastructure configuration."""

    high_value_amount: Decimal = Decimal("50000")
    velocity_max_transactions: int = 8
    impossible_speed_kmh: float = 900.0
    new_device_window: timedelta = timedelta(hours=24)
    amount_spike_multiplier: Decimal = Decimal("5")
    risky_merchant_threshold: float = 0.75
    repeated_failures_threshold: int = 3
    version: str = "rules-1.0.0"

    def __post_init__(self) -> None:
        if self.high_value_amount <= 0:
            raise ValueError("high_value_amount must be positive")
        if self.velocity_max_transactions < 1:
            raise ValueError("velocity_max_transactions must be at least one")
        if self.impossible_speed_kmh <= 0:
            raise ValueError("impossible_speed_kmh must be positive")
        if self.new_device_window <= timedelta(0):
            raise ValueError("new_device_window must be positive")
        if self.amount_spike_multiplier <= 1:
            raise ValueError("amount_spike_multiplier must be greater than one")
        if not 0 <= self.risky_merchant_threshold <= 1:
            raise ValueError("risky_merchant_threshold must be between zero and one")

    @classmethod
    def from_settings(cls, settings: Settings) -> RulesPolicy:
        """Create policy from validated runtime settings."""

        return cls(
            high_value_amount=Decimal(str(settings.high_value_amount)),
            velocity_max_transactions=settings.velocity_max_transactions,
            impossible_speed_kmh=settings.distance_impossible_speed_kmh,
            new_device_window=timedelta(hours=settings.new_device_risk_window_hours),
        )


@dataclass(frozen=True, slots=True)
class RuleContext:
    """Privacy-safe features required by deterministic rules."""

    amount: Decimal
    occurred_at: datetime
    transactions_in_velocity_window: int = 0
    customer_average_amount_30d: Decimal | None = None
    device_first_seen_at: datetime | None = None
    travel_speed_kmh: float | None = None
    merchant_risk_score: float | None = None
    failed_attempts_1h: int = 0
    account_denylisted: bool = False
    device_denylisted: bool = False

    def __post_init__(self) -> None:
        if self.amount <= 0:
            raise ValueError("amount must be positive")
        if self.occurred_at.tzinfo is None:
            raise ValueError("occurred_at must be timezone-aware")
        if self.transactions_in_velocity_window < 0 or self.failed_attempts_1h < 0:
            raise ValueError("counter features cannot be negative")
        if self.customer_average_amount_30d is not None:
            if self.customer_average_amount_30d < 0:
                raise ValueError("customer_average_amount_30d cannot be negative")
        if self.travel_speed_kmh is not None and self.travel_speed_kmh < 0:
            raise ValueError("travel_speed_kmh cannot be negative")
        if self.merchant_risk_score is not None:
            if not 0 <= self.merchant_risk_score <= 1:
                raise ValueError("merchant_risk_score must be between zero and one")


@dataclass(frozen=True, slots=True)
class RuleSignal:
    """One triggered rule with safe, explainable evidence."""

    code: RuleCode
    score: float
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0 <= self.score <= 1:
            raise ValueError("rule signal score must be between zero and one")


@dataclass(frozen=True, slots=True)
class RuleEvaluation:
    """Combined deterministic score and ordered triggered signals."""

    score: float
    confidence: float
    signals: tuple[RuleSignal, ...]
    version: str

    @property
    def reason_codes(self) -> tuple[str, ...]:
        return tuple(signal.code.value for signal in self.signals)


class RulesEngine:
    """Evaluate a payment context with deterministic, versioned rules."""

    def __init__(self, policy: RulesPolicy) -> None:
        self._policy = policy

    def evaluate(self, context: RuleContext) -> RuleEvaluation:
        """Run every rule and combine independent signals using noisy-OR."""

        signals = tuple(
            sorted(
                self._evaluate_signals(context),
                key=lambda signal: (-signal.score, signal.code.value),
            )
        )
        complement = math.prod(1.0 - signal.score for signal in signals)
        score = round(1.0 - complement, 6)

        optional_features = (
            context.customer_average_amount_30d,
            context.device_first_seen_at,
            context.travel_speed_kmh,
            context.merchant_risk_score,
        )
        observed = sum(feature is not None for feature in optional_features)
        confidence = round(0.75 + (observed / len(optional_features)) * 0.25, 6)
        return RuleEvaluation(
            score=score,
            confidence=confidence,
            signals=signals,
            version=self._policy.version,
        )

    def _evaluate_signals(self, context: RuleContext) -> list[RuleSignal]:
        signals: list[RuleSignal] = []
        policy = self._policy

        if context.account_denylisted:
            signals.append(
                RuleSignal(
                    RuleCode.ACCOUNT_DENYLISTED,
                    0.99,
                    "Account token matched a configured denylist.",
                )
            )
        if context.device_denylisted:
            signals.append(
                RuleSignal(
                    RuleCode.DEVICE_DENYLISTED,
                    0.98,
                    "Device token matched a configured denylist.",
                )
            )
        if context.amount >= policy.high_value_amount:
            ratio = float(context.amount / policy.high_value_amount)
            score = min(0.85, 0.45 + 0.1 * math.log2(max(1.0, ratio)))
            signals.append(
                RuleSignal(
                    RuleCode.HIGH_VALUE,
                    round(score, 6),
                    "Transaction amount exceeded the high-value threshold.",
                    {"threshold": str(policy.high_value_amount), "ratio": round(ratio, 2)},
                )
            )
        if context.transactions_in_velocity_window > policy.velocity_max_transactions:
            excess = context.transactions_in_velocity_window - policy.velocity_max_transactions
            score = min(0.92, 0.6 + excess * 0.04)
            signals.append(
                RuleSignal(
                    RuleCode.RAPID_VELOCITY,
                    round(score, 6),
                    "Customer transaction velocity exceeded the configured limit.",
                    {
                        "observed": context.transactions_in_velocity_window,
                        "limit": policy.velocity_max_transactions,
                    },
                )
            )
        average = context.customer_average_amount_30d
        if average is not None and average > 0:
            amount_ratio = context.amount / average
            if amount_ratio >= policy.amount_spike_multiplier:
                signals.append(
                    RuleSignal(
                        RuleCode.AMOUNT_SPIKE,
                        min(
                            0.88,
                            0.5
                            + float(amount_ratio - policy.amount_spike_multiplier) * 0.03,
                        ),
                        "Amount was unusually large for this customer's recent history.",
                        {"multiple_of_average": round(float(amount_ratio), 2)},
                    )
                )
        if context.travel_speed_kmh is not None:
            if context.travel_speed_kmh > policy.impossible_speed_kmh:
                ratio = context.travel_speed_kmh / policy.impossible_speed_kmh
                signals.append(
                    RuleSignal(
                        RuleCode.IMPOSSIBLE_TRAVEL,
                        min(0.96, 0.72 + (ratio - 1.0) * 0.08),
                        "Recent transaction locations imply impossible travel speed.",
                        {
                            "speed_kmh": round(context.travel_speed_kmh, 1),
                            "threshold_kmh": policy.impossible_speed_kmh,
                        },
                    )
                )
        first_seen = context.device_first_seen_at
        if first_seen is not None:
            age = context.occurred_at.astimezone(UTC) - first_seen.astimezone(UTC)
            if timedelta(0) <= age <= policy.new_device_window:
                signals.append(
                    RuleSignal(
                        RuleCode.NEW_DEVICE,
                        0.35,
                        "Transaction originated from a recently observed device.",
                        {"device_age_hours": round(age.total_seconds() / 3600, 2)},
                    )
                )
        if context.merchant_risk_score is not None:
            if context.merchant_risk_score >= policy.risky_merchant_threshold:
                signals.append(
                    RuleSignal(
                        RuleCode.RISKY_MERCHANT,
                        round(context.merchant_risk_score * 0.8, 6),
                        "Merchant risk exceeded the configured threshold.",
                        {"merchant_risk": round(context.merchant_risk_score, 4)},
                    )
                )
        if context.failed_attempts_1h >= policy.repeated_failures_threshold:
            signals.append(
                RuleSignal(
                    RuleCode.REPEATED_FAILURES,
                    min(0.9, 0.5 + context.failed_attempts_1h * 0.05),
                    "Multiple recent failed payment attempts were observed.",
                    {"failed_attempts": context.failed_attempts_1h},
                )
            )
        return signals

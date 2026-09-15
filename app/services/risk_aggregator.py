"""Hybrid fraud-risk aggregation with explicit degraded-mode semantics."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Mapping

from app.core.config import Settings
from app.models.transaction import PaymentDecision


_WEIGHT_TOLERANCE = 1e-9


class ComponentName(StrEnum):
    """Fraud intelligence components supported by the platform."""

    RULES = "rules"
    ML = "ml"
    GRAPH = "graph"
    IDENTITY = "identity"


@dataclass(frozen=True, slots=True)
class ComponentScore:
    """Normalized output from one fraud intelligence component."""

    score: float = 0.0
    confidence: float = 0.0
    available: bool = True
    reason_codes: tuple[str, ...] = ()
    version: str | None = None
    latency_ms: float = 0.0
    error_code: str | None = None

    def __post_init__(self) -> None:
        if not 0 <= self.score <= 1:
            raise ValueError("component score must be between zero and one")
        if not 0 <= self.confidence <= 1:
            raise ValueError("component confidence must be between zero and one")
        if self.latency_ms < 0:
            raise ValueError("component latency cannot be negative")
        if self.available and self.error_code is not None:
            raise ValueError("available components cannot include an error_code")

    @classmethod
    def unavailable(cls, error_code: str) -> ComponentScore:
        """Construct a safe unavailable-component result."""

        if not error_code:
            raise ValueError("error_code is required")
        return cls(available=False, error_code=error_code)


@dataclass(frozen=True, slots=True)
class RiskPolicy:
    """Validated aggregation weights and decision thresholds."""

    weights: Mapping[ComponentName, float] = field(
        default_factory=lambda: {
            ComponentName.RULES: 0.35,
            ComponentName.ML: 0.30,
            ComponentName.GRAPH: 0.25,
            ComponentName.IDENTITY: 0.10,
        }
    )
    review_threshold: float = 0.55
    block_threshold: float = 0.82
    minimum_confidence: float = 0.60
    allow_degraded_scoring: bool = True
    degraded_score_cap: float = 0.80

    def __post_init__(self) -> None:
        if set(self.weights) != set(ComponentName):
            raise ValueError("weights must define every fraud component")
        if any(weight < 0 or weight > 1 for weight in self.weights.values()):
            raise ValueError("weights must be between zero and one")
        if abs(sum(self.weights.values()) - 1.0) > _WEIGHT_TOLERANCE:
            raise ValueError("component weights must sum to one")
        if not 0 <= self.review_threshold < self.block_threshold <= 1:
            raise ValueError("decision thresholds are invalid")
        if not 0 <= self.minimum_confidence <= 1:
            raise ValueError("minimum_confidence must be between zero and one")
        if not 0 <= self.degraded_score_cap <= 1:
            raise ValueError("degraded_score_cap must be between zero and one")

    @classmethod
    def from_settings(cls, settings: Settings) -> RiskPolicy:
        """Create a risk policy from application configuration."""

        return cls(
            weights={
                ComponentName.RULES: settings.rules_score_weight,
                ComponentName.ML: settings.ml_score_weight,
                ComponentName.GRAPH: settings.graph_score_weight,
                ComponentName.IDENTITY: settings.identity_score_weight,
            },
            review_threshold=settings.review_threshold,
            block_threshold=settings.block_threshold,
            minimum_confidence=settings.min_decision_confidence,
            allow_degraded_scoring=settings.allow_degraded_scoring,
            degraded_score_cap=settings.degraded_scoring_max_risk,
        )


@dataclass(frozen=True, slots=True)
class AggregatedRisk:
    """Final decision with complete component provenance."""

    decision: PaymentDecision
    risk_score: float
    confidence: float
    component_scores: Mapping[ComponentName, float]
    reason_codes: tuple[str, ...]
    degraded_components: tuple[ComponentName, ...]
    versions: Mapping[ComponentName, str | None]
    total_latency_ms: float


class RiskAggregator:
    """Combine component scores without hiding failures or uncertainty."""

    def __init__(self, policy: RiskPolicy) -> None:
        self._policy = policy

    def aggregate(
        self,
        components: Mapping[ComponentName, ComponentScore],
    ) -> AggregatedRisk:
        """Aggregate available signals and apply deterministic decision policy."""

        normalized = {
            name: components.get(name, ComponentScore.unavailable("MISSING_COMPONENT"))
            for name in ComponentName
        }
        available = {name: item for name, item in normalized.items() if item.available}
        degraded = tuple(name for name in ComponentName if not normalized[name].available)
        scores = {name: item.score for name, item in normalized.items()}
        versions = {name: item.version for name, item in normalized.items()}
        reason_codes = tuple(
            sorted({code for item in normalized.values() for code in item.reason_codes})
        )
        total_latency = round(sum(item.latency_ms for item in normalized.values()), 3)

        if not available or (degraded and not self._policy.allow_degraded_scoring):
            return AggregatedRisk(
                decision=PaymentDecision.ERROR,
                risk_score=1.0,
                confidence=0.0,
                component_scores=scores,
                reason_codes=reason_codes + ("SCORING_UNAVAILABLE",),
                degraded_components=degraded,
                versions=versions,
                total_latency_ms=total_latency,
            )

        available_weight = sum(self._policy.weights[name] for name in available)
        weighted_score = sum(
            item.score * self._policy.weights[name] for name, item in available.items()
        )
        weighted_confidence = sum(
            item.confidence * self._policy.weights[name]
            for name, item in available.items()
        )
        risk_score = weighted_score / available_weight
        confidence = weighted_confidence
        if degraded:
            risk_score = min(risk_score, self._policy.degraded_score_cap)

        risk_score = round(max(0.0, min(1.0, risk_score)), 6)
        confidence = round(max(0.0, min(1.0, confidence)), 6)
        decision = self._decision(risk_score, confidence)
        return AggregatedRisk(
            decision=decision,
            risk_score=risk_score,
            confidence=confidence,
            component_scores=scores,
            reason_codes=reason_codes,
            degraded_components=degraded,
            versions=versions,
            total_latency_ms=total_latency,
        )

    def _decision(self, score: float, confidence: float) -> PaymentDecision:
        if score >= self._policy.block_threshold:
            return PaymentDecision.BLOCK
        if score >= self._policy.review_threshold:
            return PaymentDecision.REVIEW
        if confidence < self._policy.minimum_confidence:
            return PaymentDecision.REVIEW
        return PaymentDecision.ALLOW

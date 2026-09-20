"""Transactional fraud scoring that connects API ingestion to analyst alerts.

The production architecture can replace feature collection with Redis/Kafka
materialized features without changing the deterministic scoring contract. The
local prototype deliberately scores synchronously so a newly submitted payment
is immediately visible in the dashboard with a traceable decision.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.alert import Alert, AlertSeverity
from app.models.transaction import PaymentDecision, PaymentStatus, Transaction
from app.services.risk_aggregator import (
    ComponentName,
    ComponentScore,
    RiskAggregator,
    RiskPolicy,
)
from app.services.rules_engine import RuleContext, RulesEngine, RulesPolicy


@dataclass(frozen=True, slots=True)
class RiskFeatures:
    """Privacy-safe online features consumed by the scoring pipeline."""

    transactions_in_velocity_window: int = 0
    customer_average_amount_30d: Decimal | None = None
    device_first_seen_at: datetime | None = None
    travel_speed_kmh: float | None = None
    merchant_risk_score: float | None = None
    failed_attempts_1h: int = 0
    account_denylisted: bool = False
    device_denylisted: bool = False


@dataclass(frozen=True, slots=True)
class ScoringOutcome:
    """Persistable decision and optional analyst work item."""

    decision: PaymentDecision
    risk_score: float
    confidence: float
    reason_codes: tuple[str, ...]
    explanation: dict[str, object]
    component_scores: dict[str, float]
    alert: Alert | None


class FraudScoringService:
    """Collect relational features and apply the hybrid scoring policy."""

    def __init__(self, settings: Settings) -> None:
        self._rules = RulesEngine(RulesPolicy.from_settings(settings))
        self._aggregator = RiskAggregator(RiskPolicy.from_settings(settings))

    async def score_transaction(
        self,
        session: AsyncSession,
        transaction: Transaction,
        *,
        feature_overrides: RiskFeatures | None = None,
    ) -> ScoringOutcome:
        """Score and mutate a transaction inside its caller-owned DB transaction."""

        features = await self._collect_features(session, transaction)
        if feature_overrides is not None:
            features = self._merge_features(features, feature_overrides)
        outcome = self.evaluate(transaction, features)
        self._apply(transaction, outcome)
        if outcome.alert is not None:
            session.add(outcome.alert)
        return outcome

    def evaluate(self, transaction: Transaction, features: RiskFeatures) -> ScoringOutcome:
        """Evaluate already-collected features without infrastructure access."""

        rule_result = self._rules.evaluate(
            RuleContext(
                amount=transaction.amount,
                occurred_at=transaction.occurred_at,
                transactions_in_velocity_window=features.transactions_in_velocity_window,
                customer_average_amount_30d=features.customer_average_amount_30d,
                device_first_seen_at=features.device_first_seen_at,
                travel_speed_kmh=features.travel_speed_kmh,
                merchant_risk_score=features.merchant_risk_score,
                failed_attempts_1h=features.failed_attempts_1h,
                account_denylisted=features.account_denylisted,
                device_denylisted=features.device_denylisted,
            )
        )
        identity_score = 0.99 if features.account_denylisted else 0.0
        if features.device_denylisted:
            identity_score = max(identity_score, 0.98)
        identity_reasons = tuple(
            code
            for code, matched in (
                ("IDENTITY_ACCOUNT_DENYLISTED", features.account_denylisted),
                ("IDENTITY_DEVICE_DENYLISTED", features.device_denylisted),
            )
            if matched
        )
        components = {
            ComponentName.RULES: ComponentScore(
                score=rule_result.score,
                confidence=rule_result.confidence,
                reason_codes=rule_result.reason_codes,
                version=rule_result.version,
            ),
            ComponentName.ML: ComponentScore.unavailable("ML_ARTIFACT_NOT_CONFIGURED"),
            ComponentName.GRAPH: ComponentScore.unavailable("GRAPH_ASYNC_ENRICHMENT_PENDING"),
            ComponentName.IDENTITY: ComponentScore(
                score=identity_score,
                confidence=0.95,
                reason_codes=identity_reasons,
                version="identity-risk-v1",
            ),
        }
        risk = self._aggregator.aggregate(components)
        component_scores = {name.value: score for name, score in risk.component_scores.items()}
        explanation: dict[str, object] = {
            "summary": self._summary(risk.decision, risk.risk_score),
            "component_scores": component_scores,
            "degraded_components": [name.value for name in risk.degraded_components],
            "rules": [
                {
                    "code": signal.code.value,
                    "description": signal.description,
                    "score": signal.score,
                    "evidence": signal.evidence,
                }
                for signal in rule_result.signals
            ],
            "versions": {name.value: version for name, version in risk.versions.items()},
        }
        alert = self._build_alert(
            transaction,
            risk.decision,
            risk.risk_score,
            risk.reason_codes,
            explanation,
        )
        return ScoringOutcome(
            decision=risk.decision,
            risk_score=risk.risk_score,
            confidence=risk.confidence,
            reason_codes=risk.reason_codes,
            explanation=explanation,
            component_scores=component_scores,
            alert=alert,
        )

    async def _collect_features(
        self,
        session: AsyncSession,
        transaction: Transaction,
    ) -> RiskFeatures:
        occurred_at = transaction.occurred_at.astimezone(UTC)
        common = (
            Transaction.tenant_id == transaction.tenant_id,
            Transaction.customer_token == transaction.customer_token,
            Transaction.id != transaction.id,
        )
        velocity = await session.scalar(
            select(func.count(Transaction.id)).where(
                *common,
                Transaction.occurred_at >= occurred_at - timedelta(minutes=10),
                Transaction.occurred_at <= occurred_at,
            )
        )
        average = await session.scalar(
            select(func.avg(Transaction.amount)).where(
                *common,
                Transaction.occurred_at >= occurred_at - timedelta(days=30),
                Transaction.occurred_at <= occurred_at,
            )
        )
        first_seen: datetime | None = None
        if transaction.device_token:
            first_seen = await session.scalar(
                select(func.min(Transaction.occurred_at)).where(
                    Transaction.tenant_id == transaction.tenant_id,
                    Transaction.device_token == transaction.device_token,
                    Transaction.id != transaction.id,
                )
            )
            if first_seen is None:
                first_seen = occurred_at
        return RiskFeatures(
            transactions_in_velocity_window=int(velocity or 0),
            customer_average_amount_30d=Decimal(str(average)) if average is not None else None,
            device_first_seen_at=first_seen,
        )

    @staticmethod
    def _merge_features(base: RiskFeatures, override: RiskFeatures) -> RiskFeatures:
        """Merge trusted, server-generated simulation features into collected data."""

        return replace(
            base,
            transactions_in_velocity_window=max(
                base.transactions_in_velocity_window,
                override.transactions_in_velocity_window,
            ),
            customer_average_amount_30d=(
                override.customer_average_amount_30d
                if override.customer_average_amount_30d is not None
                else base.customer_average_amount_30d
            ),
            device_first_seen_at=override.device_first_seen_at or base.device_first_seen_at,
            travel_speed_kmh=override.travel_speed_kmh,
            merchant_risk_score=override.merchant_risk_score,
            failed_attempts_1h=max(base.failed_attempts_1h, override.failed_attempts_1h),
            account_denylisted=override.account_denylisted,
            device_denylisted=override.device_denylisted,
        )

    @staticmethod
    def _apply(transaction: Transaction, outcome: ScoringOutcome) -> None:
        transaction.status = PaymentStatus.DECIDED
        transaction.decision = outcome.decision
        transaction.risk_score = Decimal(str(outcome.risk_score))
        transaction.rules_score = Decimal(str(outcome.component_scores["rules"]))
        transaction.ml_score = Decimal(str(outcome.component_scores["ml"]))
        transaction.graph_score = Decimal(str(outcome.component_scores["graph"]))
        transaction.identity_score = Decimal(str(outcome.component_scores["identity"]))
        transaction.confidence = Decimal(str(outcome.confidence))
        transaction.reason_codes = list(outcome.reason_codes)
        transaction.explanation = outcome.explanation
        transaction.rules_version = "rules-1.0.0"
        transaction.decided_at = datetime.now(UTC)

    @staticmethod
    def _build_alert(
        transaction: Transaction,
        decision: PaymentDecision,
        score: float,
        reasons: tuple[str, ...],
        explanation: dict[str, object],
    ) -> Alert | None:
        if decision not in {PaymentDecision.REVIEW, PaymentDecision.BLOCK}:
            return None
        severity = (
            AlertSeverity.CRITICAL if decision is PaymentDecision.BLOCK else AlertSeverity.HIGH
        )
        return Alert(
            tenant_id=transaction.tenant_id,
            transaction_id=transaction.id,
            severity=severity,
            risk_score=score,
            title=f"{decision.value.title()} payment: {transaction.external_id}",
            summary=f"Hybrid scoring produced {score:.0%} risk from {len(reasons)} signals.",
            reason_codes=list(reasons),
            evidence={
                "decision": decision.value,
                "component_scores": explanation["component_scores"],
                "degraded_components": explanation["degraded_components"],
            },
        )

    @staticmethod
    def _summary(decision: PaymentDecision, score: float) -> str:
        return f"Payment decision {decision.value.upper()} at {score:.1%} aggregate risk."

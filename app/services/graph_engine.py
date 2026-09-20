"""Tenant-isolated Neo4j graph ingestion and bounded fraud-risk analysis."""

from __future__ import annotations

import math
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from app.services.risk_aggregator import ComponentScore

MIN_TIMEOUT_SECONDS = 0.1
MAX_TIMEOUT_SECONDS = 30.0
MAX_TRAVERSAL_DEPTH = 6
MAX_RESULT_RECORDS = 1_000
MAX_IDENTIFIER_LENGTH = 128
CURRENCY_CODE_LENGTH = 3
SHARED_DEVICE_THRESHOLD = 4
DEVICE_CHURN_THRESHOLD = 4
RISKY_MERCHANT_THRESHOLD = 3
RAPID_TRANSACTION_THRESHOLD = 6


class AsyncResult(Protocol):
    async def single(self, *, strict: bool = False) -> Mapping[str, Any] | None: ...
    async def data(self) -> list[dict[str, Any]]: ...
    async def consume(self) -> Any: ...


class AsyncSession(Protocol):
    async def __aenter__(self) -> AsyncSession: ...
    async def __aexit__(self, *args: object) -> None: ...
    async def run(
        self, query: str, parameters: Mapping[str, object], **kwargs: object
    ) -> AsyncResult: ...


class AsyncDriver(Protocol):
    def session(self, *, database: str) -> AsyncSession: ...
    async def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class GraphPolicy:
    database: str = "neo4j"
    timeout_seconds: float = 2.0
    lookback_hours: int = 24
    maximum_depth: int = 4
    maximum_records: int = 200
    version: str = "graph-risk-v1"

    def __post_init__(self) -> None:
        if not MIN_TIMEOUT_SECONDS <= self.timeout_seconds <= MAX_TIMEOUT_SECONDS:
            raise ValueError("timeout_seconds must be between 0.1 and 30")
        if not 1 <= self.maximum_depth <= MAX_TRAVERSAL_DEPTH:
            raise ValueError("maximum_depth must be between 1 and 6")
        if not 1 <= self.maximum_records <= MAX_RESULT_RECORDS:
            raise ValueError("maximum_records must be between 1 and 1,000")


@dataclass(frozen=True, slots=True)
class GraphTransaction:
    tenant_id: str
    transaction_id: str
    customer_token: str
    account_token: str
    device_token: str | None
    merchant_id: str
    amount: float
    currency: str
    occurred_at: datetime
    decision: str | None = None

    def __post_init__(self) -> None:
        values = (self.tenant_id, self.transaction_id, self.customer_token, self.account_token)
        if any(not value or len(value) > MAX_IDENTIFIER_LENGTH for value in values):
            raise ValueError("tenant, transaction, customer, and account identifiers are required")
        if not math.isfinite(self.amount) or self.amount <= 0:
            raise ValueError("amount must be finite and positive")
        if len(self.currency) != CURRENCY_CODE_LENGTH:
            raise ValueError("currency must be a three-letter code")
        if self.occurred_at.tzinfo is None:
            raise ValueError("occurred_at must be timezone-aware")


@dataclass(frozen=True, slots=True)
class GraphRiskEvidence:
    device_customer_count: int
    account_device_count: int
    merchant_fraud_count: int
    rapid_transaction_count: int


_INGEST_QUERY = """
MERGE (customer:Customer {tenant_id: $tenant_id, token: $customer_token})
  ON CREATE SET customer.first_seen_at = $occurred_at
  SET customer.last_seen_at = $occurred_at
MERGE (account:Account {tenant_id: $tenant_id, token: $account_token})
  ON CREATE SET account.first_seen_at = $occurred_at
  SET account.last_seen_at = $occurred_at
MERGE (merchant:Merchant {tenant_id: $tenant_id, merchant_id: $merchant_id})
  ON CREATE SET merchant.first_seen_at = $occurred_at
  SET merchant.last_seen_at = $occurred_at
MERGE (transaction:Transaction {tenant_id: $tenant_id, transaction_id: $transaction_id})
  ON CREATE SET transaction.amount = $amount,
                transaction.currency = $currency,
                transaction.occurred_at = $occurred_at,
                transaction.decision = $decision
MERGE (customer)-[:OWNS]->(account)
MERGE (customer)-[:INITIATED]->(transaction)
MERGE (account)-[:FUNDED]->(transaction)
MERGE (transaction)-[:PAID]->(merchant)
FOREACH (_ IN CASE WHEN $device_token IS NULL THEN [] ELSE [1] END |
  MERGE (device:Device {tenant_id: $tenant_id, token: $device_token})
    ON CREATE SET device.first_seen_at = $occurred_at
    SET device.last_seen_at = $occurred_at
  MERGE (transaction)-[:USED_DEVICE]->(device)
)
RETURN transaction.transaction_id AS transaction_id
"""

_RISK_QUERY = """
MATCH (target:Transaction {tenant_id: $tenant_id, transaction_id: $transaction_id})
CALL (target) {
  OPTIONAL MATCH (target)-[:USED_DEVICE]->(device)<-[:USED_DEVICE]-(other:Transaction)
                 <-[:INITIATED]-(customer:Customer)
  WHERE other.tenant_id = target.tenant_id AND other.occurred_at >= $since
  RETURN count(DISTINCT customer.token) AS device_customer_count
}
CALL (target) {
  OPTIONAL MATCH (target)<-[:FUNDED]-(account:Account)-[:FUNDED]->(other:Transaction)
                 -[:USED_DEVICE]->(device:Device)
  WHERE other.tenant_id = target.tenant_id AND other.occurred_at >= $since
  RETURN count(DISTINCT device.token) AS account_device_count
}
CALL (target) {
  OPTIONAL MATCH (target)-[:PAID]->(merchant:Merchant)<-[:PAID]-(other:Transaction)
  WHERE other.tenant_id = target.tenant_id AND other.decision = 'block'
        AND other.occurred_at >= $since
  RETURN count(DISTINCT other.transaction_id) AS merchant_fraud_count
}
CALL (target) {
  OPTIONAL MATCH (target)<-[:INITIATED]-(customer:Customer)-[:INITIATED]->(other:Transaction)
  WHERE other.tenant_id = target.tenant_id AND other.occurred_at >= $rapid_since
  RETURN count(DISTINCT other.transaction_id) AS rapid_transaction_count
}
RETURN device_customer_count, account_device_count, merchant_fraud_count,
       rapid_transaction_count
"""


class GraphEngine:
    """Store tokenized relationships and calculate explainable graph risk."""

    def __init__(self, driver: AsyncDriver, policy: GraphPolicy) -> None:
        self._driver = driver
        self._policy = policy

    async def record_transaction(self, transaction: GraphTransaction) -> None:
        parameters: dict[str, object] = {
            "tenant_id": transaction.tenant_id,
            "transaction_id": transaction.transaction_id,
            "customer_token": transaction.customer_token,
            "account_token": transaction.account_token,
            "device_token": transaction.device_token,
            "merchant_id": transaction.merchant_id,
            "amount": transaction.amount,
            "currency": transaction.currency.upper(),
            "occurred_at": transaction.occurred_at.astimezone(UTC),
            "decision": transaction.decision,
        }
        async with self._driver.session(database=self._policy.database) as session:
            result = await session.run(
                _INGEST_QUERY, parameters, timeout=self._policy.timeout_seconds
            )
            await result.consume()

    async def score(self, tenant_id: str, transaction_id: str) -> ComponentScore:
        started = time.perf_counter()
        if not tenant_id or not transaction_id:
            raise ValueError("tenant_id and transaction_id are required")
        now = datetime.now(UTC)
        parameters: dict[str, object] = {
            "tenant_id": tenant_id,
            "transaction_id": transaction_id,
            "since": now - timedelta(hours=self._policy.lookback_hours),
            "rapid_since": now - timedelta(minutes=10),
        }
        try:
            async with self._driver.session(database=self._policy.database) as session:
                result = await session.run(
                    _RISK_QUERY, parameters, timeout=self._policy.timeout_seconds
                )
                record = await result.single(strict=False)
        except Exception:
            return ComponentScore.unavailable("GRAPH_UNAVAILABLE")
        if record is None:
            return ComponentScore.unavailable("GRAPH_TRANSACTION_NOT_FOUND")
        evidence = GraphRiskEvidence(
            device_customer_count=int(record.get("device_customer_count", 0)),
            account_device_count=int(record.get("account_device_count", 0)),
            merchant_fraud_count=int(record.get("merchant_fraud_count", 0)),
            rapid_transaction_count=int(record.get("rapid_transaction_count", 0)),
        )
        score, reasons = self._calculate(evidence)
        latency = round((time.perf_counter() - started) * 1_000, 3)
        return ComponentScore(
            score=score,
            confidence=0.85,
            reason_codes=reasons,
            version=self._policy.version,
            latency_ms=latency,
        )

    async def investigation_neighborhood(
        self, tenant_id: str, transaction_id: str
    ) -> Sequence[Mapping[str, Any]]:
        """Return a strictly bounded tenant-local graph neighborhood."""
        depth = self._policy.maximum_depth  # Validated integer; never user-controlled.
        query = f"""
        MATCH (target:Transaction {{tenant_id: $tenant_id, transaction_id: $transaction_id}})
        MATCH path=(target)-[*1..{depth}]-(related)
        WHERE all(node IN nodes(path) WHERE node.tenant_id = $tenant_id)
        RETURN DISTINCT labels(related) AS labels, properties(related) AS properties,
               length(path) AS distance
        ORDER BY distance ASC
        LIMIT $limit
        """
        async with self._driver.session(database=self._policy.database) as session:
            result = await session.run(
                query,
                {
                    "tenant_id": tenant_id,
                    "transaction_id": transaction_id,
                    "limit": self._policy.maximum_records,
                },
                timeout=self._policy.timeout_seconds,
            )
            return await result.data()

    async def close(self) -> None:
        await self._driver.close()

    @staticmethod
    def _calculate(evidence: GraphRiskEvidence) -> tuple[float, tuple[str, ...]]:
        reasons: list[str] = []
        score = 0.05
        if evidence.device_customer_count >= SHARED_DEVICE_THRESHOLD:
            score += min(0.35, evidence.device_customer_count * 0.045)
            reasons.append("GRAPH_SHARED_DEVICE")
        if evidence.account_device_count >= DEVICE_CHURN_THRESHOLD:
            score += min(0.20, evidence.account_device_count * 0.03)
            reasons.append("GRAPH_DEVICE_CHURN")
        if evidence.merchant_fraud_count >= RISKY_MERCHANT_THRESHOLD:
            score += min(0.30, evidence.merchant_fraud_count * 0.035)
            reasons.append("GRAPH_RISKY_MERCHANT_CLUSTER")
        if evidence.rapid_transaction_count >= RAPID_TRANSACTION_THRESHOLD:
            score += min(0.20, evidence.rapid_transaction_count * 0.015)
            reasons.append("GRAPH_RAPID_FAN_OUT")
        return round(min(score, 1.0), 6), tuple(reasons)

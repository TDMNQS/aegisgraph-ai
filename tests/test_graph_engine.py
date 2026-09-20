"""Tests for parameterized ingestion, graph scoring, and traversal bounds."""

# Test fixtures use opaque dummy tokens and concrete policy boundaries.
# ruff: noqa: PLR2004, S106

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from app.services.graph_engine import GraphEngine, GraphPolicy, GraphTransaction


class FakeResult:
    def __init__(self, record: dict[str, Any] | None = None) -> None:
        self.record = record
        self.consumed = False

    async def single(self, *, strict: bool = False) -> dict[str, Any] | None:
        return self.record

    async def data(self) -> list[dict[str, Any]]:
        return [{"labels": ["Device"], "properties": {"token": "opaque"}, "distance": 1}]

    async def consume(self) -> None:
        self.consumed = True


class FakeSession:
    def __init__(self, response: dict[str, Any] | None) -> None:
        self.response = response
        self.calls: list[tuple[str, dict[str, object], dict[str, object]]] = []

    async def __aenter__(self) -> FakeSession:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def run(self, query: str, parameters: dict[str, object], **kwargs: object) -> FakeResult:
        self.calls.append((query, parameters, kwargs))
        return FakeResult(self.response)


class FakeDriver:
    def __init__(self, response: dict[str, Any] | None = None) -> None:
        self.fake_session = FakeSession(response)
        self.database: str | None = None
        self.closed = False

    def session(self, *, database: str) -> FakeSession:
        self.database = database
        return self.fake_session

    async def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_ingestion_uses_parameters_and_tenant_scope() -> None:
    driver = FakeDriver()
    engine = GraphEngine(driver, GraphPolicy())
    event = GraphTransaction(
        tenant_id="demo-bank",
        transaction_id="txn-secret-value",
        customer_token="customer-token",
        account_token="account-token",
        device_token="device-token",
        merchant_id="merchant-42",
        amount=1250.0,
        currency="inr",
        occurred_at=datetime.now(UTC),
    )

    await engine.record_transaction(event)

    query, parameters, options = driver.fake_session.calls[0]
    assert "$tenant_id" in query
    assert "txn-secret-value" not in query
    assert parameters["transaction_id"] == "txn-secret-value"
    assert parameters["currency"] == "INR"
    assert options["timeout"] == 2.0


@pytest.mark.asyncio
async def test_graph_score_returns_explainable_high_risk_component() -> None:
    driver = FakeDriver(
        {
            "device_customer_count": 9,
            "account_device_count": 8,
            "merchant_fraud_count": 7,
            "rapid_transaction_count": 12,
        }
    )
    engine = GraphEngine(driver, GraphPolicy(version="graph-test-v1"))

    result = await engine.score("demo-bank", "txn-1")

    assert result.available is True
    assert result.score >= 0.8
    assert result.version == "graph-test-v1"
    assert "GRAPH_SHARED_DEVICE" in result.reason_codes
    assert "GRAPH_RISKY_MERCHANT_CLUSTER" in result.reason_codes


@pytest.mark.asyncio
async def test_investigation_query_is_tenant_isolated_and_bounded() -> None:
    driver = FakeDriver()
    policy = GraphPolicy(maximum_depth=3, maximum_records=25)
    rows = await GraphEngine(driver, policy).investigation_neighborhood("demo-bank", "txn-1")

    query, parameters, _ = driver.fake_session.calls[0]
    assert "[*1..3]" in query
    assert "node.tenant_id = $tenant_id" in query
    assert parameters["limit"] == 25
    assert rows[0]["distance"] == 1


@pytest.mark.asyncio
async def test_missing_graph_transaction_degrades_safely() -> None:
    result = await GraphEngine(FakeDriver(None), GraphPolicy()).score("demo-bank", "missing")
    assert result.available is False
    assert result.error_code == "GRAPH_TRANSACTION_NOT_FOUND"

"""Locust scenario for authenticated ingestion and analyst reads.

Run with::

    locust -f tests/load_test.py --host http://localhost:8000

The scenario expects an existing service account by default. Configure it with
AEGIS_LOAD_TENANT, AEGIS_LOAD_EMAIL, and AEGIS_LOAD_PASSWORD. It never sends
raw payment identities: all identity-like fields are deterministic test tokens.
"""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from itertools import count
from typing import Any
from uuid import uuid4

from locust import HttpUser, between, task

HTTP_OK = 200


def _token(namespace: str, value: str) -> str:
    digest = hashlib.sha256(f"load:{namespace}:{value}".encode()).hexdigest()
    return f"tok_{namespace}_{digest[:40]}"


class FraudApiUser(HttpUser):
    """Model a payment producer that also performs bounded analyst reads."""

    wait_time = between(0.05, 0.4)
    abstract = False

    def on_start(self) -> None:
        self._sequence = count()
        payload = {
            "tenant_id": os.getenv("AEGIS_LOAD_TENANT", "load-test"),
            "email": os.getenv("AEGIS_LOAD_EMAIL", "load-service@example.test"),
            "password": os.getenv("AEGIS_LOAD_PASSWORD", "LoadTestOnly!ChangeMe123"),
        }
        with self.client.post(
            "/api/v1/auth/login",
            json=payload,
            name="POST /api/v1/auth/login",
            catch_response=True,
        ) as response:
            if response.status_code != HTTP_OK:
                response.failure(
                    "Load-test account unavailable. Create the configured account first."
                )
                return
            token = response.json().get("access_token")
            if not token:
                response.failure("Login response did not contain access_token")
                return
            self.client.headers.update({"Authorization": f"Bearer {token}"})

    def _transaction(self) -> dict[str, Any]:
        serial = f"{self.environment.runner.user_count}:{next(self._sequence)}:{uuid4()}"
        return {
            "external_id": f"load-{serial}",
            "idempotency_key": f"load-idempotency-{serial}",
            "amount": "149.95",
            "currency": "INR",
            "merchant_id": "load-merchant-001",
            "merchant_category_code": "5734",
            "channel": "api",
            "occurred_at": datetime.now(UTC).isoformat(),
            "customer_token": _token("customer", serial),
            "account_token": _token("account", serial),
            "device_token": _token("device", serial),
            "ip_token": _token("ip", serial),
            "location": {"country_code": "IN", "latitude": 19.076, "longitude": 72.8777},
            "attributes": {"load_test": True, "scenario": "steady_ingestion"},
        }

    @task(8)
    def ingest_transaction(self) -> None:
        with self.client.post(
            "/api/v1/transactions",
            json=self._transaction(),
            name="POST /api/v1/transactions",
            catch_response=True,
        ) as response:
            if response.status_code not in {200, 202}:
                response.failure(f"unexpected status {response.status_code}")

    @task(2)
    def list_transactions(self) -> None:
        self.client.get(
            "/api/v1/transactions?limit=25",
            name="GET /api/v1/transactions",
        )

    @task(1)
    def list_alerts(self) -> None:
        self.client.get(
            "/api/v1/alerts?limit=25",
            name="GET /api/v1/alerts",
        )

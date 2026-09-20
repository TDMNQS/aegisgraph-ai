"""Tests for audit ordering, redaction, concurrency, and tamper detection."""

# Test assertions intentionally use concrete boundary values.
# ruff: noqa: PLR2004, S105

from __future__ import annotations

import asyncio
from dataclasses import replace

import pytest

from app.services.audit import AuditEvent, AuditService, InMemoryAuditSink


def _event(index: int = 1) -> AuditEvent:
    return AuditEvent(
        tenant_id="demo-bank",
        actor_id="analyst-1",
        action="alert.status.updated",
        target_type="alert",
        target_id=f"alert-{index}",
        metadata={"status": "investigating", "access_token": "must-not-appear"},
    )


@pytest.mark.asyncio
async def test_audit_chain_redacts_sensitive_metadata() -> None:
    sink = InMemoryAuditSink()
    service = AuditService(sink)

    first = await service.record(_event(1))
    second = await service.record(_event(2))

    assert first.sequence == 1
    assert second.sequence == 2
    assert second.previous_hash == first.event_hash
    assert second.metadata["access_token"] == "[REDACTED]"
    assert await service.verify("demo-bank") is True


@pytest.mark.asyncio
async def test_concurrent_appends_receive_unique_ordered_sequences() -> None:
    sink = InMemoryAuditSink()
    service = AuditService(sink)

    records = await asyncio.gather(*(service.record(_event(i)) for i in range(1, 21)))

    assert sorted(record.sequence for record in records) == list(range(1, 21))
    assert await service.verify("demo-bank") is True


@pytest.mark.asyncio
async def test_tampering_breaks_chain_verification() -> None:
    sink = InMemoryAuditSink()
    service = AuditService(sink)
    await service.record(_event())
    original = (await sink.records("demo-bank"))[0]
    sink._records["demo-bank"][0] = replace(original, outcome="failure")

    assert await service.verify("demo-bank") is False


@pytest.mark.asyncio
async def test_tenant_chains_are_independent() -> None:
    sink = InMemoryAuditSink()
    service = AuditService(sink)
    await service.record(_event())
    await service.record(replace(_event(), tenant_id="other-bank"))

    demo = (await sink.records("demo-bank"))[0]
    other = (await sink.records("other-bank"))[0]
    assert demo.previous_hash == other.previous_hash
    assert demo.event_hash != other.event_hash
    assert await service.verify("demo-bank") is True
    assert await service.verify("other-bank") is True

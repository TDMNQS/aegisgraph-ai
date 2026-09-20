"""Append-only, tamper-evident audit events with automatic sensitive-data redaction."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import uuid4

GENESIS_HASH = "0" * 64
SENSITIVE_KEYS = frozenset(
    {"password", "secret", "token", "authorization", "pan", "cvv", "email", "phone", "raw_value"}
)
MAX_AUDIT_FIELD_LENGTH = 256


@dataclass(frozen=True, slots=True)
class AuditEvent:
    tenant_id: str
    actor_id: str
    action: str
    target_type: str
    target_id: str
    outcome: str = "success"
    metadata: Mapping[str, object] | None = None


@dataclass(frozen=True, slots=True)
class AuditRecord:
    sequence: int
    event_id: str
    occurred_at: str
    tenant_id: str
    actor_id: str
    action: str
    target_type: str
    target_id: str
    outcome: str
    metadata: Mapping[str, object]
    previous_hash: str
    event_hash: str


class AuditSink(Protocol):
    async def latest(self, tenant_id: str) -> AuditRecord | None: ...
    async def append(self, record: AuditRecord) -> None: ...
    async def records(self, tenant_id: str) -> Sequence[AuditRecord]: ...


class InMemoryAuditSink:
    """Test/development sink; production adapters can persist the same records."""

    def __init__(self) -> None:
        self._records: dict[str, list[AuditRecord]] = {}

    async def latest(self, tenant_id: str) -> AuditRecord | None:
        tenant_records = self._records.get(tenant_id, [])
        return tenant_records[-1] if tenant_records else None

    async def append(self, record: AuditRecord) -> None:
        self._records.setdefault(record.tenant_id, []).append(record)

    async def records(self, tenant_id: str) -> Sequence[AuditRecord]:
        return tuple(self._records.get(tenant_id, ()))


class AuditChainError(RuntimeError):
    """Raised when an append or verification detects a broken hash chain."""


class AuditService:
    """Serialize tenant-local audit appends and verify the complete hash chain."""

    def __init__(self, sink: AuditSink) -> None:
        self._sink = sink
        self._locks: dict[str, asyncio.Lock] = {}
        self._locks_guard = asyncio.Lock()

    async def record(self, event: AuditEvent) -> AuditRecord:
        self._validate_event(event)
        lock = await self._tenant_lock(event.tenant_id)
        async with lock:
            latest = await self._sink.latest(event.tenant_id)
            previous_hash = latest.event_hash if latest else GENESIS_HASH
            sequence = latest.sequence + 1 if latest else 1
            unsigned: dict[str, object] = {
                "sequence": sequence,
                "event_id": str(uuid4()),
                "occurred_at": datetime.now(UTC).isoformat(),
                "tenant_id": event.tenant_id,
                "actor_id": event.actor_id,
                "action": event.action,
                "target_type": event.target_type,
                "target_id": event.target_id,
                "outcome": event.outcome,
                "metadata": self._redact(dict(event.metadata or {})),
                "previous_hash": previous_hash,
            }
            event_hash = self._hash(unsigned)
            record = AuditRecord(**unsigned, event_hash=event_hash)  # type: ignore[arg-type]
            await self._sink.append(record)
            return record

    async def verify(self, tenant_id: str) -> bool:
        records = await self._sink.records(tenant_id)
        expected_previous = GENESIS_HASH
        expected_sequence = 1
        for record in records:
            data = asdict(record)
            claimed_hash = str(data.pop("event_hash"))
            if record.sequence != expected_sequence or record.previous_hash != expected_previous:
                return False
            if hashlib.sha256(self._canonical(data)).hexdigest() != claimed_hash:
                return False
            expected_previous = record.event_hash
            expected_sequence += 1
        return True

    async def require_valid_chain(self, tenant_id: str) -> None:
        if not await self.verify(tenant_id):
            raise AuditChainError(f"audit hash chain validation failed for tenant {tenant_id}")

    async def _tenant_lock(self, tenant_id: str) -> asyncio.Lock:
        async with self._locks_guard:
            return self._locks.setdefault(tenant_id, asyncio.Lock())

    @classmethod
    def _hash(cls, data: Mapping[str, object]) -> str:
        return hashlib.sha256(cls._canonical(data)).hexdigest()

    @staticmethod
    def _canonical(data: Mapping[str, object]) -> bytes:
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

    @classmethod
    def _redact(cls, value: Any, key: str = "") -> Any:
        if any(fragment in key.casefold() for fragment in SENSITIVE_KEYS):
            return "[REDACTED]"
        if isinstance(value, Mapping):
            return {str(k): cls._redact(v, str(k)) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [cls._redact(item) for item in value]
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        return str(value)

    @staticmethod
    def _validate_event(event: AuditEvent) -> None:
        required = (
            event.tenant_id,
            event.actor_id,
            event.action,
            event.target_type,
            event.target_id,
        )
        if any(not item.strip() or len(item) > MAX_AUDIT_FIELD_LENGTH for item in required):
            raise ValueError("audit identity and action fields must contain 1-256 characters")
        if event.outcome not in {"success", "failure", "denied"}:
            raise ValueError("audit outcome must be success, failure, or denied")

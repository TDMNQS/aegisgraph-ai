"""Reliable Kafka publishing and at-least-once transaction consumption."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.errors import KafkaError
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.config import KafkaSecurityProtocol, Settings
from app.models.transaction import Transaction


_CONSUMER_POLL_TIMEOUT_MS = 1_000
_CONSUMER_MAX_RECORDS = 100
_MAX_RETRY_DELAY_SECONDS = 30.0


class IngestionError(Exception):
    """Base error raised by the ingestion boundary."""


class RetryableIngestionError(IngestionError):
    """Handler error that may succeed after a bounded retry."""


class TransactionEvent(BaseModel):
    """Versioned, tokenized transaction event safe for operational transport."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1.0.0"
    event_id: UUID = Field(default_factory=uuid4)
    event_type: str = "payment.transaction.received"
    emitted_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    correlation_id: str = Field(min_length=8, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=64)
    transaction_id: UUID
    external_id: str
    amount: Decimal
    currency: str
    merchant_id: str
    merchant_category_code: str | None
    channel: str
    occurred_at: datetime
    customer_token: str
    account_token: str
    device_token: str | None
    ip_token: str | None
    country_code: str | None
    latitude: Decimal | None
    longitude: Decimal | None

    @classmethod
    def from_transaction(
        cls,
        transaction: Transaction,
        correlation_id: str,
    ) -> TransactionEvent:
        """Build an event without copying unapproved model attributes."""

        return cls(
            correlation_id=correlation_id,
            tenant_id=transaction.tenant_id,
            transaction_id=transaction.id,
            external_id=transaction.external_id,
            amount=transaction.amount,
            currency=transaction.currency,
            merchant_id=transaction.merchant_id,
            merchant_category_code=transaction.merchant_category_code,
            channel=transaction.channel,
            occurred_at=transaction.occurred_at,
            customer_token=transaction.customer_token,
            account_token=transaction.account_token,
            device_token=transaction.device_token,
            ip_token=transaction.ip_token,
            country_code=transaction.country_code,
            latitude=transaction.latitude,
            longitude=transaction.longitude,
        )


class DeadLetterEvent(BaseModel):
    """Safe diagnostic envelope for permanently failed events."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    failed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source_topic: str
    source_partition: int
    source_offset: int
    error_code: str
    correlation_id: str | None = None
    payload_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    payload_size_bytes: int = Field(ge=0)


def _kafka_security_options(settings: Settings) -> dict[str, Any]:
    options: dict[str, Any] = {
        "security_protocol": settings.kafka_security_protocol.value,
    }
    if settings.kafka_security_protocol in {
        KafkaSecurityProtocol.SASL_PLAINTEXT,
        KafkaSecurityProtocol.SASL_SSL,
    }:
        options.update(
            sasl_mechanism=settings.kafka_sasl_mechanism,
            sasl_plain_username=settings.kafka_sasl_username,
            sasl_plain_password=(
                settings.kafka_sasl_password.get_secret_value()
                if settings.kafka_sasl_password is not None
                else None
            ),
        )
    return options


class KafkaTransactionPublisher:
    """Idempotent Kafka producer for canonical transaction events."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._producer: AIOKafkaProducer | None = None

    async def start(self) -> None:
        if self._producer is not None:
            return
        producer = AIOKafkaProducer(
            bootstrap_servers=self._settings.kafka_bootstrap_servers,
            client_id=self._settings.kafka_client_id,
            acks="all",
            enable_idempotence=True,
            compression_type="gzip",
            request_timeout_ms=self._settings.kafka_request_timeout_ms,
            **_kafka_security_options(self._settings),
        )
        try:
            await producer.start()
        except KafkaError as exc:
            await producer.stop()
            raise IngestionError("Kafka producer failed to start") from exc
        self._producer = producer

    async def stop(self) -> None:
        producer, self._producer = self._producer, None
        if producer is not None:
            await producer.stop()

    async def publish(self, event: TransactionEvent) -> tuple[int, int]:
        """Publish with a tenant/customer key to preserve entity ordering."""

        if self._producer is None:
            raise IngestionError("Kafka producer has not been started")
        key = f"{event.tenant_id}:{event.customer_token}".encode()
        headers = [
            ("schema-version", event.schema_version.encode()),
            ("correlation-id", event.correlation_id.encode()),
            ("event-id", str(event.event_id).encode()),
        ]
        try:
            metadata = await self._producer.send_and_wait(
                self._settings.kafka_transaction_topic,
                key=key,
                value=event.model_dump_json().encode(),
                headers=headers,
            )
        except KafkaError as exc:
            raise RetryableIngestionError("Kafka transaction publish failed") from exc
        return metadata.partition, metadata.offset


EventHandler = Callable[[TransactionEvent], Awaitable[None]]


class KafkaTransactionConsumer:
    """Manual-commit consumer with bounded retries and a dead-letter topic."""

    def __init__(self, settings: Settings, handler: EventHandler) -> None:
        self._settings = settings
        self._handler = handler
        self._consumer: AIOKafkaConsumer | None = None
        self._dead_letter_producer: AIOKafkaProducer | None = None

    async def start(self) -> None:
        if self._consumer is not None:
            return
        common = {
            "bootstrap_servers": self._settings.kafka_bootstrap_servers,
            **_kafka_security_options(self._settings),
        }
        consumer = AIOKafkaConsumer(
            self._settings.kafka_transaction_topic,
            group_id=self._settings.kafka_consumer_group,
            client_id=f"{self._settings.kafka_client_id}-consumer",
            enable_auto_commit=False,
            auto_offset_reset=self._settings.kafka_auto_offset_reset,
            **common,
        )
        dead_letter_producer = AIOKafkaProducer(
            client_id=f"{self._settings.kafka_client_id}-dlq",
            acks="all",
            enable_idempotence=True,
            **common,
        )
        try:
            await consumer.start()
            await dead_letter_producer.start()
        except KafkaError as exc:
            await consumer.stop()
            await dead_letter_producer.stop()
            raise IngestionError("Kafka consumer failed to start") from exc
        self._consumer = consumer
        self._dead_letter_producer = dead_letter_producer

    async def stop(self) -> None:
        consumer, self._consumer = self._consumer, None
        producer, self._dead_letter_producer = self._dead_letter_producer, None
        if consumer is not None:
            await consumer.stop()
        if producer is not None:
            await producer.stop()

    async def run(self, stop_event: asyncio.Event) -> None:
        """Process batches until shutdown, committing only handled or DLQ events."""

        if self._consumer is None or self._dead_letter_producer is None:
            raise IngestionError("Kafka consumer has not been started")
        while not stop_event.is_set():
            records = await self._consumer.getmany(
                timeout_ms=_CONSUMER_POLL_TIMEOUT_MS,
                max_records=_CONSUMER_MAX_RECORDS,
            )
            processed_any = False
            for messages in records.values():
                for message in messages:
                    await self._process_message(message)
                    processed_any = True
            if processed_any:
                await self._consumer.commit()

    async def _process_message(self, message: Any) -> None:
        try:
            event = TransactionEvent.model_validate_json(message.value)
        except ValidationError:
            await self._publish_dead_letter(message, "INVALID_EVENT_SCHEMA", None)
            return

        for attempt in range(self._settings.kafka_max_retries + 1):
            try:
                await self._handler(event)
                return
            except RetryableIngestionError:
                if attempt >= self._settings.kafka_max_retries:
                    break
                delay = self._settings.kafka_retry_backoff_ms * (2**attempt) / 1000
                await asyncio.sleep(min(delay, _MAX_RETRY_DELAY_SECONDS))
        await self._publish_dead_letter(message, "HANDLER_RETRIES_EXHAUSTED", event)

    async def _publish_dead_letter(
        self,
        message: Any,
        error_code: str,
        event: TransactionEvent | None,
    ) -> None:
        if self._dead_letter_producer is None:
            raise IngestionError("dead-letter producer has not been started")
        dead_letter = DeadLetterEvent(
            source_topic=message.topic,
            source_partition=message.partition,
            source_offset=message.offset,
            error_code=error_code,
            correlation_id=event.correlation_id if event is not None else None,
            payload_sha256=hashlib.sha256(message.value).hexdigest(),
            payload_size_bytes=len(message.value),
        )
        try:
            await self._dead_letter_producer.send_and_wait(
                self._settings.kafka_dead_letter_topic,
                value=dead_letter.model_dump_json().encode(),
                headers=[("error-code", error_code.encode())],
            )
        except KafkaError as exc:
            raise RetryableIngestionError("dead-letter publish failed") from exc

"""Typed application configuration for AegisGraph AI.

All settings are loaded from environment variables or a local .env file.
Sensitive values use SecretStr so they are not exposed by normal logging or
serialization. Validation intentionally fails fast when security invariants are
broken.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Any, Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppEnvironment(StrEnum):
    """Supported deployment environments."""

    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


class LogLevel(StrEnum):
    """Application log levels accepted by the logging bootstrap."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class KafkaSecurityProtocol(StrEnum):
    """Kafka transport and authentication modes."""

    PLAINTEXT = "PLAINTEXT"
    SSL = "SSL"
    SASL_PLAINTEXT = "SASL_PLAINTEXT"
    SASL_SSL = "SASL_SSL"


class Settings(BaseSettings):
    """Validated, immutable runtime configuration.

    Field names map directly to uppercase keys in .env.example because
    environment matching is case-insensitive.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        frozen=True,
        validate_default=True,
    )

    # Application
    app_name: str = "AegisGraph AI"
    app_env: AppEnvironment = AppEnvironment.DEVELOPMENT
    app_version: str = "0.1.0"
    debug: bool = False
    log_level: LogLevel = LogLevel.INFO
    api_v1_prefix: str = "/api/v1"
    service_instance_id: str = "local-api-1"
    default_timezone: str = "UTC"
    enforce_secure_configuration: bool = True

    # HTTP server and browser security
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    workers: int = Field(default=1, ge=1, le=32)
    request_timeout_seconds: float = Field(default=15.0, gt=0, le=120)
    request_max_bytes: int = Field(default=1_048_576, ge=1_024, le=10_485_760)
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    cors_allow_credentials: bool = True
    trusted_hosts: list[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1"])
    rate_limit_requests: int = Field(default=120, ge=1, le=100_000)
    rate_limit_window_seconds: int = Field(default=60, ge=1, le=3_600)
    auth_rate_limit_requests: int = Field(default=10, ge=1, le=1_000)
    auth_rate_limit_window_seconds: int = Field(default=60, ge=1, le=3_600)

    # PostgreSQL
    postgres_db: str = "aegisgraph"
    postgres_user: str = "aegisgraph"
    postgres_password: SecretStr = SecretStr("aegisgraph_dev_only")
    database_url: SecretStr = SecretStr(
        "postgresql+asyncpg://aegisgraph:aegisgraph_dev_only@localhost:5432/aegisgraph"
    )
    database_pool_size: int = Field(default=10, ge=1, le=100)
    database_max_overflow: int = Field(default=20, ge=0, le=200)
    database_pool_timeout_seconds: int = Field(default=10, ge=1, le=120)
    database_pool_recycle_seconds: int = Field(default=1_800, ge=60)
    database_statement_timeout_ms: int = Field(default=5_000, ge=100, le=120_000)
    database_echo: bool = False

    # Redis
    redis_url: SecretStr = SecretStr("redis://localhost:6379/0")
    redis_prefix: str = "aegisgraph:development"
    redis_socket_timeout_seconds: float = Field(default=2.0, gt=0, le=30)
    redis_connect_timeout_seconds: float = Field(default=2.0, gt=0, le=30)
    redis_max_connections: int = Field(default=50, ge=1, le=1_000)
    idempotency_ttl_seconds: int = Field(default=86_400, ge=60)
    feature_cache_ttl_seconds: int = Field(default=3_600, ge=1)
    session_revocation_ttl_seconds: int = Field(default=604_800, ge=60)

    # Kafka
    kafka_bootstrap_servers: list[str] = Field(default_factory=lambda: ["localhost:9092"])
    kafka_client_id: str = "aegisgraph-api"
    kafka_consumer_group: str = "aegisgraph-fraud-scorers"
    kafka_transaction_topic: str = "payments.transactions.v1"
    kafka_alert_topic: str = "fraud.alerts.v1"
    kafka_dead_letter_topic: str = "payments.transactions.dlq.v1"
    kafka_security_protocol: KafkaSecurityProtocol = KafkaSecurityProtocol.PLAINTEXT
    kafka_auto_offset_reset: str = "earliest"
    kafka_enable_auto_commit: bool = False
    kafka_max_retries: int = Field(default=3, ge=0, le=20)
    kafka_retry_backoff_ms: int = Field(default=500, ge=10, le=60_000)
    kafka_request_timeout_ms: int = Field(default=5_000, ge=100, le=120_000)
    kafka_sasl_mechanism: str | None = None
    kafka_sasl_username: str | None = None
    kafka_sasl_password: SecretStr | None = None

    # Neo4j
    neo4j_uri: str = "neo4j://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: SecretStr = SecretStr("CHANGE_ME_NEO4J_PASSWORD")
    neo4j_database: str = "neo4j"
    neo4j_connection_timeout_seconds: float = Field(default=3.0, gt=0, le=30)
    neo4j_query_timeout_seconds: float = Field(default=2.0, gt=0, le=30)
    neo4j_max_connection_pool_size: int = Field(default=50, ge=1, le=1_000)
    neo4j_max_traversal_depth: int = Field(default=4, ge=1, le=10)
    neo4j_max_result_records: int = Field(default=500, ge=1, le=10_000)

    # Authentication
    jwt_secret_key: SecretStr = SecretStr(
        "CHANGE_ME_GENERATE_AN_INDEPENDENT_64_BYTE_SECRET"
    )
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "aegisgraph-ai"
    jwt_audience: str = "aegisgraph-api"
    access_token_expire_minutes: int = Field(default=15, ge=1, le=60)
    refresh_token_expire_days: int = Field(default=7, ge=1, le=30)
    clock_skew_seconds: int = Field(default=30, ge=0, le=300)
    password_min_length: int = Field(default=12, ge=12, le=128)
    password_max_length: int = Field(default=128, ge=12, le=1_024)
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_digit: bool = True
    password_require_symbol: bool = True
    max_login_attempts: int = Field(default=5, ge=1, le=20)
    account_lock_minutes: int = Field(default=15, ge=1, le=1_440)

    # Privacy-preserving identity vault
    identity_encryption_key: SecretStr = SecretStr("CHANGE_ME_GENERATE_A_FERNET_KEY")
    identity_encryption_key_id: str = "local-key-v1"
    identity_hmac_key: SecretStr = SecretStr(
        "CHANGE_ME_GENERATE_AN_INDEPENDENT_64_BYTE_SECRET"
    )
    identity_token_namespace: str = "aegisgraph-development"
    allow_identity_detokenization: bool = False
    identity_access_purpose_required: bool = True

    # Hybrid fraud scoring
    rules_score_weight: float = Field(default=0.35, ge=0, le=1)
    ml_score_weight: float = Field(default=0.30, ge=0, le=1)
    graph_score_weight: float = Field(default=0.25, ge=0, le=1)
    identity_score_weight: float = Field(default=0.10, ge=0, le=1)
    review_threshold: float = Field(default=0.55, ge=0, le=1)
    block_threshold: float = Field(default=0.82, ge=0, le=1)
    min_decision_confidence: float = Field(default=0.60, ge=0, le=1)
    high_value_amount: float = Field(default=50_000, gt=0)
    velocity_window_seconds: int = Field(default=300, ge=1)
    velocity_max_transactions: int = Field(default=8, ge=1)
    distance_impossible_speed_kmh: float = Field(default=900, gt=0)
    new_device_risk_window_hours: int = Field(default=24, ge=1)
    allow_degraded_scoring: bool = True
    degraded_scoring_max_risk: float = Field(default=0.80, ge=0, le=1)

    # Machine learning
    ml_model_path: Path = Path("artifacts/fraud_model.joblib")
    ml_model_metadata_path: Path = Path("artifacts/fraud_model.metadata.json")
    ml_model_version: str = "untrained"
    ml_feature_schema_version: str = "1.0.0"
    ml_artifact_sha256: str = "CHANGE_ME_AFTER_TRAINING"
    ml_prediction_timeout_ms: int = Field(default=100, ge=10, le=5_000)
    ml_max_batch_size: int = Field(default=256, ge=1, le=10_000)
    ml_random_seed: int = 42
    enable_shap_explanations: bool = False
    shap_max_background_rows: int = Field(default=500, ge=10, le=10_000)

    # Audit and observability
    audit_log_enabled: bool = True
    audit_hash_chain_enabled: bool = True
    audit_fail_closed: bool = True
    log_format: str = "json"
    log_redaction_enabled: bool = True
    log_include_source: bool = False
    metrics_enabled: bool = True
    metrics_path: str = "/metrics"
    prometheus_multiproc_dir: Path | None = None
    tracing_enabled: bool = False
    otel_service_name: str = "aegisgraph-api"
    otel_exporter_otlp_endpoint: str = "http://localhost:4318"

    # Data lifecycle
    transaction_retention_days: int = Field(default=365, ge=1)
    alert_retention_days: int = Field(default=730, ge=1)
    audit_retention_days: int = Field(default=2_555, ge=1)
    identity_retention_days: int = Field(default=365, ge=1)
    enable_retention_jobs: bool = False
    allow_real_customer_data: bool = False
    synthetic_data_seed: int = 42

    # Feature flags
    enable_rules_engine: bool = True
    enable_ml_engine: bool = False
    enable_graph_engine: bool = False
    enable_identity_risk: bool = False
    enable_kafka_ingestion: bool = False
    enable_analyst_detokenization: bool = False

    @field_validator(
        "kafka_sasl_mechanism",
        "kafka_sasl_username",
        "kafka_sasl_password",
        "prometheus_multiproc_dir",
        mode="before",
    )
    @classmethod
    def empty_value_to_none(cls, value: Any) -> Any:
        """Convert blank optional environment variables to None."""

        return None if value == "" else value

    @field_validator("api_v1_prefix", "metrics_path")
    @classmethod
    def validate_url_path(cls, value: str) -> str:
        """Require normalized absolute URL paths."""

        if not value.startswith("/") or value.endswith("/"):
            raise ValueError("must start with '/' and must not end with '/'")
        return value

    @field_validator("kafka_bootstrap_servers", "cors_origins", "trusted_hosts")
    @classmethod
    def reject_empty_lists(cls, value: list[str]) -> list[str]:
        """Prevent accidentally disabling connectivity or host restrictions."""

        cleaned = [item.strip() for item in value if item.strip()]
        if not cleaned:
            raise ValueError("must contain at least one non-empty value")
        return cleaned

    @model_validator(mode="after")
    def validate_security_invariants(self) -> Self:
        """Validate cross-field security and operational invariants."""

        if abs(sum(self.risk_weights.values()) - 1.0) > 1e-9:
            raise ValueError("fraud score weights must sum to exactly 1.0")
        if self.review_threshold >= self.block_threshold:
            raise ValueError("REVIEW_THRESHOLD must be lower than BLOCK_THRESHOLD")
        if self.password_min_length > self.password_max_length:
            raise ValueError("PASSWORD_MIN_LENGTH cannot exceed PASSWORD_MAX_LENGTH")
        if self.enable_analyst_detokenization and not self.allow_identity_detokenization:
            raise ValueError(
                "analyst detokenization requires ALLOW_IDENTITY_DETOKENIZATION=true"
            )

        sasl_enabled = self.kafka_security_protocol in {
            KafkaSecurityProtocol.SASL_PLAINTEXT,
            KafkaSecurityProtocol.SASL_SSL,
        }
        if sasl_enabled and not all(
            (
                self.kafka_sasl_mechanism,
                self.kafka_sasl_username,
                self.kafka_sasl_password,
            )
        ):
            raise ValueError("SASL Kafka modes require mechanism, username, and password")

        if self.app_env is AppEnvironment.PRODUCTION:
            self._validate_production_settings()
        if self.enforce_secure_configuration:
            self._validate_secret_placeholders()
        return self

    @property
    def risk_weights(self) -> dict[str, float]:
        """Return named hybrid scoring weights."""

        return {
            "rules": self.rules_score_weight,
            "ml": self.ml_score_weight,
            "graph": self.graph_score_weight,
            "identity": self.identity_score_weight,
        }

    @property
    def is_production(self) -> bool:
        """Return whether the application is running in production."""

        return self.app_env is AppEnvironment.PRODUCTION

    def safe_summary(self) -> dict[str, Any]:
        """Return non-sensitive settings suitable for startup logs."""

        return {
            "app_name": self.app_name,
            "app_version": self.app_version,
            "environment": self.app_env.value,
            "debug": self.debug,
            "log_level": self.log_level.value,
            "service_instance_id": self.service_instance_id,
            "rules_engine": self.enable_rules_engine,
            "ml_engine": self.enable_ml_engine,
            "graph_engine": self.enable_graph_engine,
            "identity_risk": self.enable_identity_risk,
            "kafka_ingestion": self.enable_kafka_ingestion,
            "model_version": self.ml_model_version,
            "feature_schema_version": self.ml_feature_schema_version,
        }

    def _validate_production_settings(self) -> None:
        """Reject development-only behavior in production."""

        errors: list[str] = []
        if self.debug:
            errors.append("DEBUG must be false")
        if self.host in {"127.0.0.1", "localhost"}:
            errors.append("HOST must be explicitly configured")
        if "*" in self.cors_origins:
            errors.append("wildcard CORS origins are forbidden")
        if "*" in self.trusted_hosts:
            errors.append("wildcard trusted hosts are forbidden")
        if self.database_echo:
            errors.append("DATABASE_ECHO must be false")
        if not self.log_redaction_enabled:
            errors.append("LOG_REDACTION_ENABLED must be true")
        if self.allow_real_customer_data:
            errors.append("real customer data is unsupported by this prototype")
        if (
            self.enable_kafka_ingestion
            and self.kafka_security_protocol is KafkaSecurityProtocol.PLAINTEXT
        ):
            errors.append("Kafka encryption is required")
        if errors:
            raise ValueError("unsafe production configuration: " + "; ".join(errors))

    def _validate_secret_placeholders(self) -> None:
        """Reject documented placeholders and obviously weak secret values."""

        secret_values = {
            "JWT_SECRET_KEY": self.jwt_secret_key.get_secret_value(),
            "IDENTITY_ENCRYPTION_KEY": self.identity_encryption_key.get_secret_value(),
            "IDENTITY_HMAC_KEY": self.identity_hmac_key.get_secret_value(),
            "NEO4J_PASSWORD": self.neo4j_password.get_secret_value(),
        }
        invalid = [
            name
            for name, value in secret_values.items()
            if "CHANGE_ME" in value.upper() or len(value) < 24
        ]
        if invalid:
            raise ValueError(
                "replace insecure or placeholder secrets: " + ", ".join(sorted(invalid))
            )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return one validated settings instance per application process."""

    return Settings()


def clear_settings_cache() -> None:
    """Clear cached settings, primarily for isolated tests."""

    get_settings.cache_clear()

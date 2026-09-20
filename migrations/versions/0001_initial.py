"""Create tenant users, payment transactions, and fraud alerts.

Revision ID: 0001_initial
Revises: None
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    """Create the transactional persistence schema and bounded indexes."""

    op.create_table(
        "users",
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("display_name", sa.String(length=120), nullable=False),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column(
            "role",
            sa.Enum(
                "VIEWER",
                "ANALYST",
                "SENIOR_ANALYST",
                "ADMIN",
                "SERVICE",
                name="user_role",
                native_enum=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum(
                "ACTIVE",
                "LOCKED",
                "DISABLED",
                name="user_status",
                native_enum=False,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column("is_service_account", sa.Boolean(), nullable=False),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("token_version", sa.Integer(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "failed_login_attempts >= 0",
            name=op.f("ck_users_failed_login_attempts_nonnegative"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("tenant_id", "email", name="tenant_email"),
    )
    op.create_index("ix_users_tenant_role", "users", ["tenant_id", "role"])
    op.create_index("ix_users_tenant_status", "users", ["tenant_id", "status"])

    op.create_table(
        "transactions",
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("external_id", sa.String(length=128), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("event_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("amount", sa.Numeric(precision=19, scale=4), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("merchant_id", sa.String(length=128), nullable=False),
        sa.Column("merchant_category_code", sa.String(length=4), nullable=True),
        sa.Column("channel", sa.String(length=32), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("customer_token", sa.String(length=128), nullable=False),
        sa.Column("account_token", sa.String(length=128), nullable=False),
        sa.Column("device_token", sa.String(length=128), nullable=True),
        sa.Column("ip_token", sa.String(length=128), nullable=True),
        sa.Column("country_code", sa.String(length=2), nullable=True),
        sa.Column("latitude", sa.Numeric(precision=9, scale=6), nullable=True),
        sa.Column("longitude", sa.Numeric(precision=9, scale=6), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "RECEIVED",
                "SCORING",
                "DECIDED",
                "FAILED",
                name="payment_status",
                native_enum=False,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column(
            "decision",
            sa.Enum(
                "ALLOW",
                "REVIEW",
                "BLOCK",
                "ERROR",
                name="payment_decision",
                native_enum=False,
                length=16,
            ),
            nullable=True,
        ),
        sa.Column("risk_score", sa.Numeric(precision=6, scale=5), nullable=False),
        sa.Column("rules_score", sa.Numeric(precision=6, scale=5), nullable=False),
        sa.Column("ml_score", sa.Numeric(precision=6, scale=5), nullable=False),
        sa.Column("graph_score", sa.Numeric(precision=6, scale=5), nullable=False),
        sa.Column("identity_score", sa.Numeric(precision=6, scale=5), nullable=False),
        sa.Column("confidence", sa.Numeric(precision=6, scale=5), nullable=True),
        sa.Column("reason_codes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("explanation", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("features", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("rules_version", sa.String(length=64), nullable=True),
        sa.Column("model_version", sa.String(length=64), nullable=True),
        sa.Column("graph_version", sa.String(length=64), nullable=True),
        sa.Column("failure_code", sa.String(length=64), nullable=True),
        sa.Column("failure_detail", sa.Text(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("amount > 0", name=op.f("ck_transactions_amount_positive")),
        sa.CheckConstraint(
            "length(currency) = 3",
            name=op.f("ck_transactions_currency_iso_length"),
        ),
        sa.CheckConstraint(
            "risk_score >= 0 AND risk_score <= 1",
            name=op.f("ck_transactions_risk_score_range"),
        ),
        sa.CheckConstraint(
            "rules_score >= 0 AND rules_score <= 1",
            name=op.f("ck_transactions_rules_score_range"),
        ),
        sa.CheckConstraint(
            "ml_score >= 0 AND ml_score <= 1",
            name=op.f("ck_transactions_ml_score_range"),
        ),
        sa.CheckConstraint(
            "graph_score >= 0 AND graph_score <= 1",
            name=op.f("ck_transactions_graph_score_range"),
        ),
        sa.CheckConstraint(
            "identity_score >= 0 AND identity_score <= 1",
            name=op.f("ck_transactions_identity_score_range"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_transactions")),
        sa.UniqueConstraint("tenant_id", "external_id", name="tenant_external_id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="tenant_idempotency_key"),
    )
    op.create_index(
        "ix_transactions_customer_occurred", "transactions", ["customer_token", "occurred_at"]
    )
    op.create_index(
        "ix_transactions_decision_occurred", "transactions", ["decision", "occurred_at"]
    )
    op.create_index(
        "ix_transactions_device_occurred", "transactions", ["device_token", "occurred_at"]
    )
    op.create_index("ix_transactions_event_fingerprint", "transactions", ["event_fingerprint"])
    op.create_index("ix_transactions_merchant_id", "transactions", ["merchant_id"])
    op.create_index("ix_transactions_tenant_occurred", "transactions", ["tenant_id", "occurred_at"])

    op.create_table(
        "alerts",
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("transaction_id", sa.Uuid(), nullable=False),
        sa.Column(
            "severity",
            sa.Enum(
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL",
                name="alert_severity",
                native_enum=False,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum(
                "OPEN",
                "ASSIGNED",
                "INVESTIGATING",
                "CONFIRMED_FRAUD",
                "FALSE_POSITIVE",
                "CLOSED",
                name="alert_status",
                native_enum=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("title", sa.String(length=180), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("reason_codes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("assigned_to_id", sa.Uuid(), nullable=True),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolution", sa.Text(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "risk_score >= 0 AND risk_score <= 1",
            name=op.f("ck_alerts_alert_risk_range"),
        ),
        sa.ForeignKeyConstraint(
            ["assigned_to_id"],
            ["users.id"],
            name=op.f("fk_alerts_assigned_to_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["transaction_id"],
            ["transactions.id"],
            name=op.f("fk_alerts_transaction_id_transactions"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alerts")),
    )
    op.create_index("ix_alerts_assignee_status", "alerts", ["assigned_to_id", "status"])
    op.create_index("ix_alerts_severity_created", "alerts", ["severity", "created_at"])
    op.create_index(
        "ix_alerts_tenant_status_created", "alerts", ["tenant_id", "status", "created_at"]
    )


def downgrade() -> None:
    """Remove application tables in dependency order."""

    op.drop_table("alerts")
    op.drop_table("transactions")
    op.drop_table("users")

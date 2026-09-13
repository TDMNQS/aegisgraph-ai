# AegisGraph AI — System Requirements Specification

## 1. Scope

AegisGraph AI is a multi-tenant platform that evaluates digital-payment events in
near real time, combines deterministic rules, anomaly detection, graph signals,
and privacy-preserving identity intelligence, and returns an auditable decision:
`allow`, `review`, or `block`.

This specification defines the prototype's testable functional, security,
reliability, data, and operational requirements. It complements the threat model
and is not a claim of PCI DSS, ISO 27001, RBI, or other regulatory certification.

## 2. Actors and External Systems

| Actor/system | Responsibility |
|---|---|
| Payment producer | Sends authenticated, idempotent, tokenized payment events |
| Fraud analyst | Reviews alerts and records investigation outcomes |
| Senior analyst | Assigns cases and performs purpose-bound identity access |
| Administrator | Manages users, roles, rules, and model activation |
| Kafka | Durable transaction and alert event transport |
| PostgreSQL | System of record for users, decisions, alerts, and audit metadata |
| Redis | Rate limits, idempotency locks, short-lived features, and revocations |
| Neo4j | Bounded relationship traversal and fraud-ring signals |
| Model registry | Versioned, checksummed model artifacts and metadata |

## 3. Functional Requirements

### 3.1 Authentication and authorization

- **FR-AUTH-01:** The API shall authenticate human users using an Argon2 password
  hash and signed, time-limited JWT access and refresh tokens.
- **FR-AUTH-02:** The API shall validate token issuer, audience, signature,
  not-before time, expiry, token type, tenant, role, and unique token identifier.
- **FR-AUTH-03:** Permissions shall be checked server-side for every protected
  operation; frontend visibility shall not be treated as authorization.
- **FR-AUTH-04:** Repeated failed logins shall lock the account according to the
  configured attempt count and lock duration.
- **FR-AUTH-05:** Refresh-token revocation and user token-version changes shall
  invalidate previously issued sessions.

### 3.2 Transaction ingestion

- **FR-ING-01:** Each transaction shall include a tenant-local external ID,
  idempotency key, amount, ISO currency, merchant, channel, occurrence time, and
  vault-issued customer and account tokens.
- **FR-ING-02:** The public schema shall reject unknown fields and shall not expose
  fields for raw PAN, CVV, bank-account number, customer name, email, or phone.
- **FR-ING-03:** Replaying the same tenant and idempotency key shall return the
  original result without creating a second transaction or Kafka event.
- **FR-ING-04:** API and Kafka ingestion shall produce the same canonical internal
  transaction representation and event fingerprint.
- **FR-ING-05:** Invalid or repeatedly failing Kafka events shall be moved to a
  dead-letter topic with a safe failure code and correlation identifier.

### 3.3 Hybrid fraud scoring

- **FR-RISK-01:** The rules engine shall evaluate high value, transaction velocity,
  geographic impossibility, device novelty, and configurable deny-list signals.
- **FR-RISK-02:** The ML engine shall load only an artifact whose checksum, feature
  schema, and model metadata pass validation.
- **FR-RISK-03:** Graph queries shall use parameterized Cypher, tenant filters,
  bounded depth, bounded results, and a configured timeout.
- **FR-RISK-04:** The risk aggregator shall combine normalized rule, ML, graph, and
  identity scores using validated weights that sum to 1.0.
- **FR-RISK-05:** The configured review and block thresholds shall map a score to
  exactly one deterministic decision.
- **FR-RISK-06:** When a component times out or is disabled, the result shall name
  the degraded component, apply the configured safe fallback, and remain auditable.
- **FR-RISK-07:** Every decision shall store reason codes, component scores,
  confidence, processing time, and rules/model/graph versions.

### 3.4 Alerts and investigations

- **FR-CASE-01:** Review and block decisions shall create an alert with severity,
  summary, evidence, reason codes, and a transaction reference.
- **FR-CASE-02:** Analysts shall list and filter alerts by tenant, status, severity,
  creation time, decision, and assignee.
- **FR-CASE-03:** Alert state transitions shall enforce an explicit workflow and
  optimistic version check to prevent lost updates.
- **FR-CASE-04:** Closing an alert shall require a resolution and shall record the
  acting principal and timestamp in the audit trail.

### 3.5 Privacy-preserving identity

- **FR-ID-01:** Operational stores, logs, Kafka events, graph properties, and ML
  features shall use tokens rather than plaintext personally identifiable data.
- **FR-ID-02:** Search tokens shall use a separate HMAC key from the encryption key.
- **FR-ID-03:** Detokenization shall require an authorized role, an explicit purpose,
  a configured feature flag, and a successful audit write before disclosure.
- **FR-ID-04:** Secrets and identity plaintext shall never appear in exceptions,
  metrics, structured logs, API errors, or model-training datasets.

### 3.6 Auditability and explainability

- **FR-AUD-01:** Authentication, authorization failure, ingestion, decision, alert
  mutation, configuration change, model activation, and identity access shall emit
  append-only structured audit events.
- **FR-AUD-02:** Audit events shall include timestamp, tenant, principal, action,
  resource, outcome, correlation ID, and a hash-chain link when enabled.
- **FR-EXP-01:** Explanations shall identify the strongest risk signals in plain
  language without revealing secrets, protected identity data, or exploitable rule
  internals.
- **FR-EXP-02:** Explanation output shall distinguish factual signals, model
  contributions, unavailable components, and uncertainty.

## 4. Data Requirements

- **DR-01:** UUIDs shall be used for internal entity identifiers; externally
  supplied identifiers shall never become authorization boundaries.
- **DR-02:** All persisted timestamps shall be timezone-aware and normalized to UTC.
- **DR-03:** Monetary amounts shall use fixed-precision decimal storage, never
  binary floating point.
- **DR-04:** Every tenant-owned query and uniqueness constraint shall include the
  tenant identifier where applicable.
- **DR-05:** PostgreSQL constraint and index names shall be deterministic so Alembic
  migrations remain reproducible.
- **DR-06:** Retention jobs shall apply separate configured periods for transaction,
  alert, audit, and identity records and shall emit deletion audit events.
- **DR-07:** Synthetic data shall be the only data permitted in this prototype.

## 5. Quality Attributes

| ID | Requirement | Verification target |
|---|---|---|
| NFR-PERF-01 | Synchronous decision latency | p95 under 300 ms at 100 requests/s in the reference environment |
| NFR-PERF-02 | API acknowledgement with async ingestion | p95 under 100 ms |
| NFR-REL-01 | Duplicate delivery | No duplicate transaction or alert for one idempotency key |
| NFR-REL-02 | Component failure | Bounded timeout and deterministic degraded decision |
| NFR-SEC-01 | Transport | TLS for all non-local HTTP, Kafka, PostgreSQL, Redis, and Neo4j traffic |
| NFR-SEC-02 | Secrets | No committed credentials; startup rejects placeholders in secure mode |
| NFR-SEC-03 | Tenant isolation | Cross-tenant API and storage tests return no records |
| NFR-OBS-01 | Correlation | One correlation ID links request, event, decision, alert, and audit log |
| NFR-OBS-02 | Metrics | Latency, throughput, decision, error, timeout, and drift metrics exposed |
| NFR-MAINT-01 | Python quality | Ruff, strict MyPy, Bandit, and pytest pass in CI |
| NFR-TEST-01 | Coverage | At least 85% branch-aware backend test coverage |

## 6. System Interfaces

### HTTP API

- JSON over HTTPS with versioned `/api/v1` routes.
- Bearer access tokens for users and scoped service accounts.
- Stable error envelope containing code, message, correlation ID, and safe details.
- Cursor pagination and explicit limits for all collection endpoints.

### Kafka contracts

- Versioned topic names and event schema versions.
- Event key based on tenant and stable token for per-entity ordering.
- At-least-once consumption with manual offset commit after durable processing.
- No identity plaintext; headers carry correlation and trace context only.

### PostgreSQL, Redis, and Neo4j

- PostgreSQL is authoritative for workflow state and versioned decisions.
- Redis data is disposable and must never be the only copy of an audit decision.
- Neo4j stores tokenized nodes and derived relationships, not identity plaintext.

## 7. Acceptance Criteria

The seven-day implementation is accepted when:

1. A clean checkout can install dependencies and start via Docker Compose.
2. A user can authenticate, submit a synthetic tokenized transaction, receive a
   decision, retrieve it, and view any generated alert in the React dashboard.
3. Unit tests cover security, rules, aggregation, validation, idempotency, tenant
   isolation, and alert transitions.
4. A synthetic dataset can train a reproducible anomaly model and emit checksummed
   artifacts plus evaluation metrics.
5. Graph schema installation and bounded risk queries complete against Neo4j.
6. No plaintext identity or real customer data appears in committed artifacts.
7. CI runs linting, type checking, security scanning, backend tests, and frontend
   build checks before accepting a pull request.
8. Load testing records p50, p95, and p99 latency with decision and error counts.
9. The final report documents architecture, threat mitigations, model results,
   limitations, screenshots, reproducible commands, and future work.

## 8. Traceability

| Requirement group | Planned implementation |
|---|---|
| Authentication | `app/core/security.py`, `app/api/deps.py`, `app/api/routes/auth.py` |
| Persistence | `app/db/base.py`, `app/models/` |
| Ingestion | `app/schemas/transaction.py`, `app/services/ingestion.py` |
| Fraud scoring | rules, ML, graph, identity, and risk aggregator services |
| Investigations | `app/models/alert.py`, alert API, React investigation page |
| Operations | Docker Compose, Prometheus, CI workflow, and load test |
| Evidence | automated tests, audit records, metrics, and `docs/final_report.md` |

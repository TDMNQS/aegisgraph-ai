# AegisGraph AI — Final Project Report

**Project:** Real-Time Digital Payment Fraud Detection and Privacy-Preserving Identity Platform  
**Author:** Numan Qureshi  
**Repository:** `TDMNQS/aegisgraph-ai`  
**Release:** Final-year project prototype, version 0.1.0

## 1. Executive Summary

AegisGraph AI is a production-oriented fraud detection prototype for digital payments. It combines deterministic policy rules, an anomaly/classification model, bounded graph analysis, and identity-risk signals into one explainable risk decision. The system is tenant-isolated, stores tokenized payment identities instead of raw personal data, and preserves security-relevant activity in a tamper-evident audit chain.

The final implementation demonstrates the complete engineering lifecycle expected from a final-year project: threat modelling, typed configuration, authentication and role-based authorization, relational and graph persistence, event ingestion, machine-learning training and inference, analyst workflows, operational telemetry, automated tests, containerized deployment, and CI quality gates.

This repository is an educational prototype. It is not PCI DSS certified, is not a substitute for a regulated payment decision system, and must not process real customer data without an independent security, privacy, and model-risk review.

## 2. Problem Statement

Payment fraud is both a classification problem and a relationship problem. A transaction can appear normal in isolation while being suspicious because the same device, customer, account, or merchant participates in a wider fraud ring. Conversely, rigid rules can block legitimate behavior and generate costly false positives.

AegisGraph addresses four requirements:

1. Score incoming tokenized payment events with low operational latency.
2. Combine multiple independent signals instead of relying on one model.
3. Explain why a transaction was allowed, sent for review, or blocked.
4. Minimize exposure of personally identifiable information throughout the platform.

## 3. System Architecture

| Layer | Technology | Responsibility |
|---|---|---|
| Analyst interface | React, TypeScript, Vite | Dashboard, alert triage, transaction investigation |
| API boundary | FastAPI, Pydantic | Validation, JWT authentication, RBAC, tenant isolation |
| System of record | PostgreSQL, SQLAlchemy, Alembic | Users, transactions, decisions, alerts |
| Streaming | Kafka | Durable, partitioned payment-event transport and retry isolation |
| Online state | Redis | Refresh-token revocation and low-latency operational state |
| Risk rules | Python deterministic engine | Velocity, amount, travel, device, and policy checks |
| ML scoring | scikit-learn/XGBoost-compatible pipeline | Reproducible model training, metadata validation, inference |
| Relationship risk | Neo4j, Cypher | Bounded neighborhood analysis and fraud-ring indicators |
| Privacy | Fernet/HMAC identity vault | Reversible protected vault values and irreversible matching tokens |
| Audit | Hash-linked append-only records | Tamper evidence for security and analyst actions |
| Operations | Prometheus, Docker Compose, GitHub Actions | Metrics, repeatable local deployment, automated quality checks |

The hybrid risk aggregator normalizes component outputs to the interval `[0, 1]`, applies configured weights, handles degraded components explicitly, and maps the final score to `ALLOW`, `REVIEW`, or `BLOCK`. Every decision retains reason codes, component scores, versions, and a human-readable explanation.

## 4. Data and Privacy Design

The transaction schema deliberately excludes PAN, CVV, bank-account number, customer name, email, and phone. Producers send vault-issued or irreversible tokens. This reduces the blast radius of PostgreSQL, Kafka, log, and analytics exposure.

Privacy controls include:

- HMAC-based deterministic tokens for equality matching without plaintext identities.
- Authenticated encryption for the isolated identity vault.
- Purpose, actor, tenant, and expiry checks before detokenization.
- Explicit configuration that rejects real customer data in development.
- Tenant ID enforcement in authenticated principals and every application query.
- Audit records that avoid storing secret values or raw identity material.

Key material in `.env.example` is a placeholder only. Production keys must be created by a secret manager, rotated under an approved procedure, and never committed to Git.

## 5. Fraud Detection Method

### 5.1 Deterministic rules

The rules engine produces transparent, versioned evidence. It checks transaction velocity, unusually high amounts, impossible travel, new-device activity, risky channels, and related policy signals. A rule match contributes a bounded score and stable reason code. Unit tests cover boundary values and deterministic ordering.

### 5.2 Machine learning

The synthetic dataset generator creates reproducible fraud patterns without using customer data. The training pipeline performs a stratified split, preprocessing, model fitting, threshold evaluation, artifact hashing, and metadata export. The runtime engine verifies feature order and metadata before inference and can fail closed or degrade according to policy.

The dataset is useful for demonstrating a repeatable ML lifecycle; it does not establish real-world fraud performance. A production evaluation requires representative, time-split, legally approved payment data and monitoring for drift, calibration, subgroup harm, and label delay.

### 5.3 Graph intelligence

Neo4j stores token relationships between transactions, customers, accounts, devices, IP tokens, and merchants. The graph engine uses parameterized, tenant-bounded, depth-bounded queries. It derives signals such as shared risky devices, dense neighborhoods, and known-fraud proximity while limiting query cost and preventing cross-tenant traversal.

### 5.4 Risk aggregation and explanations

The aggregator combines rule, ML, graph, and identity scores. It records unavailable components instead of silently treating them as safe. Explanations contain top signals, reason codes, confidence, and component versions, making decisions inspectable by an analyst and reproducible during audit.

## 6. Security Model

The repository threat model applies STRIDE across the API, event bus, databases, model artifacts, graph, and identity vault. Implemented controls include:

- Argon2 password hashing and configurable password policy.
- Short-lived signed access tokens and rotating refresh tokens.
- Redis-backed refresh-token revocation.
- Explicit roles and fine-grained permissions.
- PostgreSQL transaction locks for safe first-admin bootstrap.
- Strict Pydantic input models with extra fields rejected.
- Idempotency keys and tenant-scoped uniqueness constraints.
- Parameterized SQL and Cypher.
- Security headers, trusted-host validation, and restricted CORS.
- Non-root application containers and minimal runtime images.
- Constant-cardinality Prometheus route labels.
- Dependency, static-analysis, unit-test, frontend-build, and container-build CI gates.

Remaining deployment controls include TLS termination, managed secret storage, network segmentation, encrypted backups, image signing, centralized logs, alerting rules, disaster-recovery exercises, and independent penetration testing.

## 7. Database and Deployment

Alembic migration `0001_initial` creates the user, transaction, and alert schema with foreign keys, uniqueness guarantees, score constraints, workflow enums, and query indexes. Migrations run as a one-shot Compose service before the API starts.

The local stack contains PostgreSQL, Redis, single-node Kafka in KRaft mode, Neo4j, the FastAPI service, the built React console, and Prometheus. Initialization jobs create Kafka topics and Neo4j constraints before dependent services become ready.

### Local start

Prerequisites: Docker Desktop with Compose v2 and at least 6 GB of available memory.

```powershell
docker compose config --quiet
docker compose up --build -d
docker compose ps
Invoke-RestMethod http://localhost:8000/health/ready
```

Open the analyst console at `http://localhost:5173`, API documentation at `http://localhost:8000/docs`, Neo4j Browser at `http://localhost:7474`, and Prometheus at `http://localhost:9090`.

Stop services without deleting persisted data:

```powershell
docker compose down
```

Delete local volumes only when a complete local reset is intended:

```powershell
docker compose down --volumes
```

## 8. Verification Strategy

| Scope | Verification |
|---|---|
| Rules and aggregation | Focused unit tests for scores, thresholds, reason codes, and degraded inputs |
| ML | Dataset reproducibility, artifact contract, inference bounds, explanation behavior |
| Graph | Tenant isolation, bounded queries, risk normalization, safe degradation |
| Identity | Token stability, encryption round-trip, purpose and expiry enforcement |
| Audit | Hash-chain verification and tamper detection |
| API | Schema validation, permissions, tenant filtering, idempotency behavior |
| Frontend | TypeScript compilation and optimized Vite build |
| Packaging | Python syntax, ZIP manifest, Compose rendering, Docker image builds |
| Performance | Locust mix of authenticated writes and bounded analyst reads |

Run the local code checks:

```powershell
python -m pip install -e ".[ml,dev,load-test]"
python -m pytest -o addopts="" -q
ruff check app ml tests migrations
Push-Location frontend; npm ci; npm run build; Pop-Location
```

Run a headless load test after creating the configured service account:

```powershell
$env:AEGIS_LOAD_TENANT="load-test"
$env:AEGIS_LOAD_EMAIL="load-service@example.test"
$env:AEGIS_LOAD_PASSWORD="replace-with-the-account-password"
locust -f tests/load_test.py --host http://localhost:8000 --headless -u 20 -r 5 -t 2m
```

The acceptance target for a development laptop is no HTTP failures after warm-up and a p95 below 500 ms for API operations. This is a reproducible engineering target, not a production capacity claim.

## 9. Demonstration Flow

1. Start the Compose stack and confirm `/health/ready` and `/metrics`.
2. Register the first account for a new tenant; it becomes tenant administrator.
3. Sign in through the analyst console.
4. Submit tokenized transactions through the API, repeating one idempotency key to show deduplication.
5. Review the dashboard risk distribution and alert queue.
6. Open an investigation, inspect component scores and reason codes, then update workflow status.
7. Inspect Neo4j relationships and Prometheus request metrics.
8. Run unit tests and show the GitHub Actions workflow definition.

## 10. Evaluation and Limitations

The project proves architectural integration and software quality, but has deliberate limits:

- Synthetic labels do not reproduce all adversarial or demographic patterns.
- The local Kafka and Neo4j deployments are single-node and not highly available.
- The project does not include card-network certification or bank integration.
- Alert feedback is captured but is not yet an automated retraining trigger.
- The audit chain is tamper-evident in application logic but should be anchored to immutable external storage.
- Prometheus is configured without long-term storage or alert routing.
- Business loss optimization and cost-sensitive threshold approval require stakeholder data.

These boundaries are documented to avoid overstating the prototype's readiness.

## 11. Future Work

Priority extensions are temporal graph features, a Kafka scoring worker with transactional outbox semantics, feature-store versioning, champion/challenger models, model and data drift alerts, analyst-label quality controls, OpenTelemetry traces, immutable audit anchoring, Kubernetes deployment, and a formal privacy impact assessment.

## 12. Conclusion

AegisGraph AI demonstrates that fraud detection can be engineered as an explainable, defense-in-depth platform rather than a single prediction endpoint. The final system connects secure APIs, relational guarantees, streaming infrastructure, reproducible ML, graph relationships, privacy controls, analyst workflows, observability, and automated delivery checks. Its documented limitations provide a clear path from final-year prototype to a governed production pilot.


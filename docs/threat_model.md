# AegisGraph AI Threat Model

**Document status:** Initial security baseline  
**Project:** AegisGraph AI  
**Scope:** Real-time payment fraud detection and privacy-preserving identity platform  
**Method:** STRIDE-based analysis with risk-prioritized mitigations

## 1. Purpose

This document identifies security, privacy, fraud, and operational threats that
could affect AegisGraph AI. It defines trust boundaries, protected assets,
likely threat actors, required controls, and verification criteria before the
prototype is treated as production-like.

The goal is not to claim regulatory certification. The goal is to ensure that
security requirements are explicit, testable, and connected to the system
architecture.

## 2. Security Objectives

AegisGraph AI must:

1. Accept transactions only from authenticated and authorized producers.
2. Preserve the integrity and ordering context of transaction events.
3. Prevent plaintext personally identifiable information (PII) from entering
   operational stores, logs, analytics, or graph records.
4. Produce fraud decisions that are explainable and traceable to versioned
   rules, models, and input signals.
5. Restrict analyst and administrator actions through least-privilege
   role-based access control.
6. Detect replay, tampering, enumeration, credential abuse, and unusual
   privileged activity.
7. Remain available during traffic spikes and partial dependency failures.
8. Support investigation without exposing unnecessary customer identity data.

## 3. System Components in Scope

| Component | Responsibility | Sensitive inputs or outputs |
| --- | --- | --- |
| Transaction producer | Simulates or submits payment events | Transaction and account identifiers |
| FastAPI gateway | Authentication, validation, routing, rate limits | Tokens, requests, decisions |
| Kafka | Durable transaction and alert event streams | Transaction events and metadata |
| Fraud scoring service | Rules, ML, graph, and identity risk aggregation | Features, scores, reason codes |
| PostgreSQL | Transaction, alert, case, user, and audit records | Financial metadata and decisions |
| Redis | Rate limits, idempotency keys, and short-lived features | Request and behavioral metadata |
| Neo4j | Relationships among accounts, devices, merchants, and payments | Tokenized entity identifiers |
| Identity vault | Tokenization and controlled detokenization | PII and cryptographic material |
| Model artifact storage | Versioned ML models and metadata | Serialized models and evaluation data |
| React dashboard | Analyst investigation and case management | Alerts, graph views, case notes |
| Observability stack | Metrics, traces, and structured logs | Operational metadata |

## 4. Trust Boundaries

~~~mermaid
flowchart TD
    U[External Client] -->|Untrusted HTTPS| A[API Gateway]
    A -->|Authenticated Internal Traffic| S[Scoring Services]
    S -->|Service Credentials| D[(PostgreSQL and Redis)]
    S -->|Producer and Consumer ACLs| K[Kafka]
    S -->|Restricted Graph Account| G[(Neo4j)]
    A -->|Privileged, Audited Request| V[Identity Vault]
    O[Analyst Browser] -->|Authenticated HTTPS| A
    M[CI/CD Pipeline] -->|Signed Artifact Promotion| S
~~~

Every boundary crossing requires authentication, authorization, input
validation, encrypted transport, and sufficient audit evidence.

## 5. Protected Assets

### Critical

- Encryption and tokenization keys.
- Authentication signing keys and refresh-token records.
- Raw PII stored inside the identity vault.
- Administrator accounts and privileged service credentials.
- Fraud model artifacts and rule configurations used for live decisions.

### High

- Transaction records and account relationships.
- Alert decisions, case evidence, and analyst notes.
- Kafka events and consumer offsets.
- Immutable audit events.
- Model training datasets and labels.

### Moderate

- Aggregated metrics and operational dashboards.
- Public API documentation.
- Non-sensitive configuration and service health information.

## 6. Threat Actors

| Actor | Motivation | Expected capability |
| --- | --- | --- |
| Fraudster | Evade detection or take over accounts | Repeated requests, device rotation, synthetic identities |
| Malicious client | Submit forged or malformed transactions | API access and protocol knowledge |
| Compromised analyst | Abuse legitimate access or leak data | Dashboard and case access |
| Privileged insider | Alter controls or retrieve identities | Administrative knowledge and credentials |
| Supply-chain attacker | Introduce malicious dependency or artifact | Package, repository, or CI compromise |
| Automated bot | Enumerate endpoints or exhaust resources | High request volume and distributed sources |
| Accidental operator | Misconfigure secrets, access, or retention | Legitimate infrastructure access |

## 7. Risk Rating Method

Each threat is assigned:

- **Likelihood:** Low, Medium, or High.
- **Impact:** Low, Medium, High, or Critical.
- **Priority:** P0, P1, P2, or P3.

| Priority | Meaning | Required action |
| --- | --- | --- |
| P0 | Immediate compromise or catastrophic exposure | Must be prevented before any shared deployment |
| P1 | Serious security, privacy, or integrity risk | Must be controlled before production-like testing |
| P2 | Important hardening requirement | Must be addressed before final release |
| P3 | Defense-in-depth improvement | Track and implement when practical |

## 8. STRIDE Threat Register

### 8.1 Spoofing

| ID | Threat | Likelihood | Impact | Priority | Required controls |
| --- | --- | --- | --- | --- | --- |
| S-01 | Attacker impersonates a transaction producer | High | Critical | P0 | Short-lived service credentials, producer identity, TLS, key rotation |
| S-02 | Stolen analyst token is reused | Medium | High | P1 | Short token lifetime, refresh rotation, session revocation, MFA-ready design |
| S-03 | Service connects using another service's identity | Medium | High | P1 | Unique service accounts, audience-bound tokens, per-service ACLs |
| S-04 | Forged device or account identifiers poison the graph | High | High | P1 | Server-issued tokens, identifier validation, provenance tracking |

**Verification**

- Requests with missing, expired, wrong-audience, or revoked credentials return
  an authorization error without processing the transaction.
- Kafka producers cannot write to unauthorized topics.
- Audit events record authentication failures without recording secrets.

### 8.2 Tampering

| ID | Threat | Likelihood | Impact | Priority | Required controls |
| --- | --- | --- | --- | --- | --- |
| T-01 | Transaction fields are modified in transit | Medium | Critical | P0 | TLS, authenticated producers, event integrity signature or HMAC |
| T-02 | Duplicate or replayed events alter velocity features | High | High | P1 | Idempotency key, timestamp window, nonce/replay detection |
| T-03 | Rules or thresholds are changed without approval | Medium | High | P1 | Versioning, approval workflow, RBAC, immutable audit record |
| T-04 | ML artifact is replaced with an untrusted file | Medium | Critical | P0 | Artifact checksum/signature, allowlisted source, safe loader, promotion gate |
| T-05 | Audit history is edited or deleted | Low | Critical | P0 | Append-only storage, integrity chain, restricted retention operations |

**Verification**

- Replaying the same transaction identifier does not create a second decision.
- Altered signed events are rejected.
- Every ruleset and model decision includes an immutable version identifier.
- Model loading fails closed when the artifact digest does not match.

### 8.3 Repudiation

| ID | Threat | Likelihood | Impact | Priority | Required controls |
| --- | --- | --- | --- | --- | --- |
| R-01 | Analyst denies changing an alert status | Medium | High | P1 | Actor ID, timestamp, before/after state, request correlation ID |
| R-02 | Administrator denies detokenizing identity data | Medium | Critical | P0 | Purpose-bound request, privileged role, reason, immutable audit event |
| R-03 | Producer denies submitting a transaction | Low | High | P1 | Authenticated producer identity and event integrity metadata |
| R-04 | Decision cannot be reproduced | Medium | High | P1 | Store model, ruleset, feature schema, graph snapshot reference, reasons |

**Verification**

- All state-changing API requests produce audit events.
- Audit records contain no plaintext PII, access tokens, passwords, or keys.
- A decision can be reconstructed from retained non-sensitive inputs and
  versioned artifacts.

### 8.4 Information Disclosure

| ID | Threat | Likelihood | Impact | Priority | Required controls |
| --- | --- | --- | --- | --- | --- |
| I-01 | PII appears in application logs or exceptions | High | Critical | P0 | Structured redaction, safe error messages, log-field allowlist |
| I-02 | Graph queries reveal customer identities | Medium | Critical | P0 | Tokenized node IDs, restricted graph roles, no raw PII properties |
| I-03 | Analyst accesses cases outside assigned scope | Medium | High | P1 | Object-level authorization and tenant filtering |
| I-04 | Backup, export, or model dataset exposes sensitive data | Medium | Critical | P0 | Encryption, tokenization, access controls, retention, export review |
| I-05 | API error reveals stack, query, or secret details | Medium | Medium | P2 | Generic external errors and protected internal diagnostics |
| I-06 | Browser stores sensitive tokens insecurely | Medium | High | P1 | Secure HttpOnly cookies where applicable, CSP, no token logging |

**Verification**

- Automated scans find no PII-shaped values in logs generated by security tests.
- Neo4j nodes contain tokenized identifiers only.
- Cross-tenant resource requests are rejected even when IDs are known.
- Production-mode responses do not expose stack traces.

### 8.5 Denial of Service

| ID | Threat | Likelihood | Impact | Priority | Required controls |
| --- | --- | --- | --- | --- | --- |
| D-01 | API flood exhausts scoring capacity | High | High | P1 | Per-client rate limits, bounded queues, timeouts, load shedding |
| D-02 | Expensive graph traversal consumes Neo4j resources | Medium | High | P1 | Query templates, depth limits, timeouts, indexes, result caps |
| D-03 | Poison events repeatedly crash Kafka consumers | Medium | High | P1 | Schema validation, retry ceiling, dead-letter topic |
| D-04 | Dependency failure causes cascading outage | Medium | High | P1 | Circuit breakers, bounded retries, degraded scoring policy |
| D-05 | Large request body consumes memory | High | Medium | P2 | Request-size limit and early content validation |

**Verification**

- Load tests demonstrate controlled rejection rather than process failure.
- Invalid events are routed to quarantine after bounded retries.
- Dependency timeouts do not exceed the end-to-end scoring latency budget.
- Graph queries enforce maximum depth and result size.

### 8.6 Elevation of Privilege

| ID | Threat | Likelihood | Impact | Priority | Required controls |
| --- | --- | --- | --- | --- | --- |
| E-01 | Analyst invokes administrator-only endpoint | Medium | Critical | P0 | Deny-by-default RBAC enforced server-side |
| E-02 | User modifies role or tenant in a request | High | High | P1 | Identity derived from verified token, not request body |
| E-03 | Injection reaches SQL, Cypher, or shell execution | Medium | Critical | P0 | Parameterized queries, fixed query templates, no shell interpolation |
| E-04 | Compromised service credential reaches identity vault | Low | Critical | P0 | Network isolation, explicit vault audience, least privilege |
| E-05 | CI job promotes unreviewed artifact | Medium | High | P1 | Protected branch, review gate, pinned actions, signed provenance |

**Verification**

- A role-permission test matrix covers every protected endpoint.
- User-controlled values never become raw SQL or Cypher fragments.
- Service accounts have only the permissions needed by their component.

## 9. Fraud-Specific Adversarial Threats

### 9.1 Model Evasion

Attackers may split amounts, rotate devices, delay actions, or coordinate
accounts to keep individual events below thresholds.

Controls:

- Combine transaction, identity, behavioral, velocity, and graph signals.
- Evaluate rolling windows at multiple durations.
- Detect shared infrastructure and community-level behavior.
- Monitor score distribution and feature drift.
- Preserve a human-review path for uncertain high-impact decisions.

### 9.2 Data and Label Poisoning

Incorrect or adversarial labels may reduce model quality or create targeted
blind spots.

Controls:

- Track dataset origin, transformation, reviewer, and version.
- Separate raw, curated, training, and evaluation datasets.
- Require approval for label changes used in a promoted model.
- Test against a locked evaluation set.
- Compare feature and label distributions between versions.

### 9.3 Feature Manipulation

Clients may attempt to choose fields that reduce their score.

Controls:

- Treat client-provided risk attributes as untrusted.
- Derive timestamps, identity context, and velocity features server-side.
- Record feature provenance.
- Apply sensible bounds and consistency validation.

### 9.4 Feedback-Loop Abuse

Analyst decisions used as labels may be biased, mistaken, or malicious.

Controls:

- Do not train directly from unreviewed decisions.
- Use dual review for sensitive label corrections.
- Measure disagreement and reversal rates.
- Retain the original decision and label history.

## 10. Privacy Design

### 10.1 Data Classification

| Class | Examples | Storage rule |
| --- | --- | --- |
| Restricted | Name, phone, email, government identifier | Identity vault only; encrypted and access audited |
| Confidential | Transaction metadata, case notes, graph relationships | Encrypted storage; role and tenant restrictions |
| Internal | Model metrics, service health, non-sensitive configuration | Authenticated internal access |
| Public | Approved documentation and health status | May be exposed intentionally |

### 10.2 Tokenization Rules

- Operational systems use random or keyed tokens instead of raw identities.
- The same person may use stable scoped tokens only where relationship analysis
  requires linkability.
- Tokens must be domain-separated so a value from one context cannot be reused
  to correlate another context unintentionally.
- Detokenization requires an authorized role, explicit purpose, and audit event.
- Encryption keys must not be stored in source code, images, logs, or datasets.

### 10.3 Data Minimization and Retention

- Collect only fields required for detection, investigation, or audit.
- Define retention by data class instead of retaining every record forever.
- Delete or aggregate expired records through an auditable process.
- Never use real customer PII in development fixtures or public demonstrations.
- Use synthetic data for the 40-day prototype.

## 11. API Security Requirements

- Validate every request with strict Pydantic schemas.
- Reject unknown fields for security-sensitive requests.
- Enforce request-body and pagination limits.
- Use server-generated identifiers where feasible.
- Require idempotency keys for transaction submission.
- Apply authentication before resource lookup to reduce enumeration signals.
- Enforce authorization on the server for every object operation.
- Return consistent error structures with correlation IDs.
- Never include secrets, raw PII, or internal queries in responses.
- Rate-limit by authenticated client, user, and relevant resource.
- Configure a narrow CORS allowlist for deployed environments.

## 12. Storage and Messaging Requirements

### PostgreSQL

- Use parameterized ORM or SQL queries.
- Give the application a non-owner database role.
- Apply row- or query-level tenant isolation.
- Encrypt connections and protect backups.
- Prevent direct modification of immutable audit records.

### Redis

- Require authentication and encrypted network transport outside local-only use.
- Set explicit TTLs for idempotency, session, and feature keys.
- Never store plaintext PII or long-lived secrets.
- Prefix keys by environment and purpose.

### Kafka

- Restrict producers and consumers by topic.
- Validate message schema before business processing.
- Define dead-letter behavior and maximum retry attempts.
- Avoid sensitive data in message headers.
- Track consumer lag and processing failures.

### Neo4j

- Use parameterized Cypher only.
- Apply query timeout, traversal depth, and result-size controls.
- Store tokenized entity identifiers.
- Use a restricted application role rather than an administrative account.

## 13. Secret and Key Management

- Secrets must be supplied through environment-specific secret storage.
- The repository may contain variable names and safe examples, never values.
- Development, test, and deployment environments use different credentials.
- Compromised credentials can be rotated without a code change.
- Token-signing and identity-encryption keys have separate purposes.
- Logs must redact authorization headers, cookies, connection strings, and keys.

## 14. Secure Failure Behavior

| Failure | Required behavior |
| --- | --- |
| Rules engine unavailable | Use documented degraded policy and create operational alert |
| ML model unavailable or invalid | Continue only with approved fallback scoring; never load unverified artifact |
| Neo4j timeout | Exclude graph signal explicitly and lower decision confidence |
| Identity vault unavailable | Deny detokenization; fraud scoring continues with tokens |
| Kafka unavailable | Apply bounded buffering or reject safely; do not silently lose accepted events |
| Audit write failure | Reject privileged state changes that require auditability |

The response must indicate which signals were unavailable so that a partial
score is never presented as a fully informed score.

## 15. Security Logging and Detection

Security events include:

- Authentication failures and token reuse.
- Authorization denials.
- Rate-limit violations.
- Event replay and schema-validation failures.
- Model or ruleset promotion.
- Privileged identity access.
- Alert disposition and case ownership changes.
- Audit integrity failures.
- Abnormal request volume or graph query cost.

Each event should include timestamp, event type, pseudonymous actor or service
ID, correlation ID, outcome, and safe context. Logs must exclude raw PII and
credentials.

## 16. Security Acceptance Criteria

The prototype is ready for final demonstration only when:

- [ ] All P0 threats have implemented and tested controls.
- [ ] All P1 threats have controls or documented, approved residual risk.
- [ ] Authentication and authorization tests cover positive and negative cases.
- [ ] Duplicate transaction tests prove idempotent scoring.
- [ ] SQL and Cypher injection tests demonstrate parameterized access.
- [ ] Logs from the security test suite contain no raw PII or secrets.
- [ ] Model artifacts are verified before loading.
- [ ] Every decision records model, ruleset, and feature-schema versions.
- [ ] Every privileged state change produces an immutable audit event.
- [ ] Load tests demonstrate bounded resource usage and controlled rejection.
- [ ] Backup and restore procedures are tested using synthetic data.
- [ ] Dependency and container scans have no unresolved critical findings.

## 17. Residual Risk

This educational prototype cannot eliminate all fraud, insider abuse, model
bias, zero-day vulnerabilities, or infrastructure compromise. A real financial
deployment would additionally require independent penetration testing, legal
and regulatory review, formal incident response, production key management,
privacy impact assessment, continuous monitoring, and institution-specific
risk approval.

## 18. Review Triggers

Update this threat model when:

- A new service, datastore, external API, or trust boundary is introduced.
- PII fields or identity workflows change.
- A new model, graph algorithm, or feedback source is added.
- Authentication, authorization, or deployment architecture changes.
- A security test, dependency scan, or incident reveals a new threat.
- The platform moves beyond synthetic data or local demonstration.

## 19. Traceability Convention

Implementation code and tests should reference the relevant threat ID in
comments or test names where useful, for example:

~~~text
test_replayed_transaction_is_rejected_T02
test_analyst_cannot_use_admin_route_E01
test_logs_redact_identity_fields_I01
~~~

This makes the threat model an active engineering document instead of a static
report.

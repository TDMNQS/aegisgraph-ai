// AegisGraph AI — tenant-isolated payment intelligence graph schema
// Run once against the configured Neo4j database. Every application query must
// include tenant_id; composite uniqueness prevents cross-tenant node collisions.

CREATE CONSTRAINT customer_tenant_token IF NOT EXISTS
FOR (n:Customer) REQUIRE (n.tenant_id, n.token) IS UNIQUE;

CREATE CONSTRAINT device_tenant_token IF NOT EXISTS
FOR (n:Device) REQUIRE (n.tenant_id, n.token) IS UNIQUE;

CREATE CONSTRAINT account_tenant_token IF NOT EXISTS
FOR (n:Account) REQUIRE (n.tenant_id, n.token) IS UNIQUE;

CREATE CONSTRAINT merchant_tenant_id IF NOT EXISTS
FOR (n:Merchant) REQUIRE (n.tenant_id, n.merchant_id) IS UNIQUE;

CREATE CONSTRAINT transaction_tenant_id IF NOT EXISTS
FOR (n:Transaction) REQUIRE (n.tenant_id, n.transaction_id) IS UNIQUE;

CREATE INDEX transaction_occurred_at IF NOT EXISTS
FOR (n:Transaction) ON (n.occurred_at);

CREATE INDEX transaction_decision IF NOT EXISTS
FOR (n:Transaction) ON (n.decision);

CREATE INDEX device_last_seen IF NOT EXISTS
FOR (n:Device) ON (n.last_seen_at);

CREATE INDEX merchant_risk_score IF NOT EXISTS
FOR (n:Merchant) ON (n.risk_score);


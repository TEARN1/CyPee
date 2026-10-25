-- ─────────────────────────────────────────────────────────────
-- CyPee Sovereign Tier 4: Database-Kernel Row-Level Security (RLS)
-- Target: PostgreSQL 14+
-- Enforces tenant isolation inside the database query engine kernel.
-- Even if an attacker executes arbitrary SQL, cross-tenant leaks are blocked.
-- ─────────────────────────────────────────────────────────────

-- 1. Enable Row-Level Security across all multi-tenant tables
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE repositories ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE zk_certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE honeytokens ENABLE ROW LEVEL SECURITY;

-- 2. Force RLS for table owners (prevents bypass by administrative app roles)
ALTER TABLE users FORCE ROW LEVEL SECURITY;
ALTER TABLE user_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE repositories FORCE ROW LEVEL SECURITY;
ALTER TABLE scans FORCE ROW LEVEL SECURITY;
ALTER TABLE findings FORCE ROW LEVEL SECURITY;
ALTER TABLE zk_certificates FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;
ALTER TABLE incidents FORCE ROW LEVEL SECURITY;
ALTER TABLE honeytokens FORCE ROW LEVEL SECURITY;

-- 3. Create Tenant Isolation Policies (enforced against app.current_tenant_id session variable)
CREATE POLICY tenant_isolation_users ON users
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant_id', true)::text);

CREATE POLICY tenant_isolation_sessions ON user_sessions
  FOR ALL
  USING (user_id IN (SELECT id FROM users WHERE tenant_id = current_setting('app.current_tenant_id', true)::text));

CREATE POLICY tenant_isolation_repositories ON repositories
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant_id', true)::text);

CREATE POLICY tenant_isolation_scans ON scans
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant_id', true)::text);

CREATE POLICY tenant_isolation_findings ON findings
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant_id', true)::text);

CREATE POLICY tenant_isolation_zk_certs ON zk_certificates
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant_id', true)::text);

CREATE POLICY tenant_isolation_audit_logs ON audit_logs
  FOR ALL
  USING (tenant_id IS NULL OR tenant_id = current_setting('app.current_tenant_id', true)::text);

CREATE POLICY tenant_isolation_incidents ON incidents
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant_id', true)::text);

CREATE POLICY tenant_isolation_honeytokens ON honeytokens
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant_id', true)::text);

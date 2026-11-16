-- Gate 0.5.6: PostgreSQL-backed model registry with tenant + business-unit RLS.
-- Apply using a database migration role. Runtime roles must not own these tables or have BYPASSRLS.
CREATE TABLE IF NOT EXISTS powerops_ml_model_candidates (
  tenant_id text NOT NULL,
  business_unit_id text NOT NULL,
  candidate_id text NOT NULL,
  model_version text NOT NULL,
  manifest_sha256 char(64) NOT NULL,
  artifact_sha256 char(64) NOT NULL,
  status text NOT NULL CHECK (status IN ('candidate','rejected','released')),
  candidate_data jsonb NOT NULL,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, business_unit_id, candidate_id)
);
CREATE TABLE IF NOT EXISTS powerops_ml_model_releases (
  tenant_id text NOT NULL,
  business_unit_id text NOT NULL,
  release_id text NOT NULL,
  candidate_id text NOT NULL,
  is_active boolean NOT NULL DEFAULT false,
  release_data jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, business_unit_id, release_id),
  FOREIGN KEY (tenant_id, business_unit_id, candidate_id)
    REFERENCES powerops_ml_model_candidates (tenant_id, business_unit_id, candidate_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS powerops_ml_one_active_release_per_scope
  ON powerops_ml_model_releases (tenant_id, business_unit_id) WHERE is_active = true;
CREATE TABLE IF NOT EXISTS powerops_ml_audit_events (
  tenant_id text NOT NULL,
  business_unit_id text NOT NULL,
  sequence bigint NOT NULL,
  event_type text NOT NULL,
  payload jsonb NOT NULL,
  actor_id text NOT NULL,
  previous_hash text NOT NULL,
  event_hash char(64) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, business_unit_id, sequence),
  UNIQUE (tenant_id, business_unit_id, event_hash)
);
CREATE INDEX IF NOT EXISTS powerops_ml_candidates_scope_created
  ON powerops_ml_model_candidates (tenant_id, business_unit_id, created_at DESC);
ALTER TABLE powerops_ml_model_candidates ENABLE ROW LEVEL SECURITY;
ALTER TABLE powerops_ml_model_candidates FORCE ROW LEVEL SECURITY;
ALTER TABLE powerops_ml_model_releases ENABLE ROW LEVEL SECURITY;
ALTER TABLE powerops_ml_model_releases FORCE ROW LEVEL SECURITY;
ALTER TABLE powerops_ml_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE powerops_ml_audit_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS powerops_ml_candidates_scope ON powerops_ml_model_candidates;
CREATE POLICY powerops_ml_candidates_scope ON powerops_ml_model_candidates
  USING (tenant_id = current_setting('app.tenant_id', true) AND business_unit_id = current_setting('app.business_unit_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true) AND business_unit_id = current_setting('app.business_unit_id', true));
DROP POLICY IF EXISTS powerops_ml_releases_scope ON powerops_ml_model_releases;
CREATE POLICY powerops_ml_releases_scope ON powerops_ml_model_releases
  USING (tenant_id = current_setting('app.tenant_id', true) AND business_unit_id = current_setting('app.business_unit_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true) AND business_unit_id = current_setting('app.business_unit_id', true));
DROP POLICY IF EXISTS powerops_ml_audit_scope ON powerops_ml_audit_events;
CREATE POLICY powerops_ml_audit_scope ON powerops_ml_audit_events
  USING (tenant_id = current_setting('app.tenant_id', true) AND business_unit_id = current_setting('app.business_unit_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true) AND business_unit_id = current_setting('app.business_unit_id', true));

-- Audit rows are append-only for every runtime role; corrections are new events.
CREATE OR REPLACE FUNCTION powerops_ml_reject_audit_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'PowerOps ML audit events are append-only';
END;
$$;
DROP TRIGGER IF EXISTS powerops_ml_audit_no_update ON powerops_ml_audit_events;
CREATE TRIGGER powerops_ml_audit_no_update
  BEFORE UPDATE OR DELETE ON powerops_ml_audit_events
  FOR EACH ROW EXECUTE FUNCTION powerops_ml_reject_audit_mutation();
-- Production deployment must provision a non-owner runtime role without BYPASSRLS,
-- restrict direct table access, and grant only required SELECT/INSERT/UPDATE privileges.
-- Hash chaining is tamper-evident, not immutable WORM storage; anchor/export the chain to
-- independently controlled immutable storage for a formal WORM guarantee.

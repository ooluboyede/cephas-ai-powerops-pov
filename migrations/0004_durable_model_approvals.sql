-- Gate 0.6.3: durable scoped authorization assignments and immutable approval decisions.
-- Apply after 0001, 0002 and 0003 as the migration administrator.
BEGIN;

CREATE TABLE IF NOT EXISTS powerops_ml_principal_role_assignments (
  tenant_id text NOT NULL,
  business_unit_id text NOT NULL,
  principal_id text NOT NULL CHECK (length(btrim(principal_id)) > 0),
  role_name text NOT NULL CHECK (role_name IN ('model-risk','security','operations-owner')),
  granted_by text NOT NULL CHECK (length(btrim(granted_by)) > 0),
  granted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  revoked_at timestamptz,
  PRIMARY KEY (tenant_id,business_unit_id,principal_id,role_name),
  CHECK (revoked_at IS NULL OR revoked_at >= granted_at)
);

CREATE TABLE IF NOT EXISTS powerops_ml_model_approvals (
  tenant_id text NOT NULL,
  business_unit_id text NOT NULL,
  candidate_id text NOT NULL,
  approval_id text NOT NULL,
  principal_id text NOT NULL,
  role_name text NOT NULL CHECK (role_name IN ('model-risk','security','operations-owner')),
  decision text NOT NULL CHECK (decision IN ('approve','reject')),
  reason text NOT NULL CHECK (length(btrim(reason)) > 0),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,business_unit_id,candidate_id,role_name),
  UNIQUE (tenant_id,business_unit_id,candidate_id,principal_id),
  UNIQUE (tenant_id,business_unit_id,approval_id),
  FOREIGN KEY (tenant_id,business_unit_id,candidate_id)
    REFERENCES powerops_ml_model_candidates (tenant_id,business_unit_id,candidate_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id,business_unit_id,principal_id,role_name)
    REFERENCES powerops_ml_principal_role_assignments
      (tenant_id,business_unit_id,principal_id,role_name)
    ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS powerops_ml_role_assignment_active
 ON powerops_ml_principal_role_assignments
 (tenant_id,business_unit_id,principal_id,role_name)
 WHERE revoked_at IS NULL;

ALTER TABLE powerops_ml_principal_role_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE powerops_ml_principal_role_assignments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS powerops_ml_role_assignments_scope ON powerops_ml_principal_role_assignments;
CREATE POLICY powerops_ml_role_assignments_scope ON powerops_ml_principal_role_assignments
 USING (tenant_id=powerops_security.current_tenant_id()
    AND business_unit_id=powerops_security.current_business_unit_id())
 WITH CHECK (tenant_id=powerops_security.current_tenant_id()
    AND business_unit_id=powerops_security.current_business_unit_id());

ALTER TABLE powerops_ml_model_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE powerops_ml_model_approvals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS powerops_ml_approvals_scope ON powerops_ml_model_approvals;
CREATE POLICY powerops_ml_approvals_scope ON powerops_ml_model_approvals
 USING (tenant_id=powerops_security.current_tenant_id()
    AND business_unit_id=powerops_security.current_business_unit_id())
 WITH CHECK (tenant_id=powerops_security.current_tenant_id()
    AND business_unit_id=powerops_security.current_business_unit_id());

ALTER TABLE powerops_ml_principal_role_assignments OWNER TO powerops_registry_owner;
ALTER TABLE powerops_ml_model_approvals OWNER TO powerops_registry_owner;
REVOKE ALL ON powerops_ml_principal_role_assignments,powerops_ml_model_approvals FROM PUBLIC;
REVOKE ALL ON powerops_ml_principal_role_assignments,powerops_ml_model_approvals FROM powerops_runtime;
GRANT SELECT ON powerops_ml_principal_role_assignments TO powerops_runtime;
GRANT SELECT,INSERT ON powerops_ml_model_approvals TO powerops_runtime;

CREATE OR REPLACE FUNCTION powerops_ml_require_active_approval_assignment()
RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog
AS $body$
BEGIN
 IF NOT EXISTS (
   SELECT 1 FROM public.powerops_ml_principal_role_assignments a
   WHERE a.tenant_id=NEW.tenant_id
     AND a.business_unit_id=NEW.business_unit_id
     AND a.principal_id=NEW.principal_id
     AND a.role_name=NEW.role_name
     AND a.revoked_at IS NULL
 ) THEN
   RAISE EXCEPTION 'An active scoped role assignment is required for this approval'
    USING ERRCODE='42501';
 END IF;
 RETURN NEW;
END;
$body$;
ALTER FUNCTION powerops_ml_require_active_approval_assignment() OWNER TO powerops_registry_owner;
REVOKE ALL ON FUNCTION powerops_ml_require_active_approval_assignment() FROM PUBLIC;
DROP TRIGGER IF EXISTS powerops_ml_approval_requires_active_assignment ON powerops_ml_model_approvals;
CREATE TRIGGER powerops_ml_approval_requires_active_assignment
 BEFORE INSERT ON powerops_ml_model_approvals
 FOR EACH ROW EXECUTE FUNCTION powerops_ml_require_active_approval_assignment();

CREATE OR REPLACE FUNCTION powerops_ml_reject_approval_mutation()
RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog
AS $$
BEGIN
 RAISE EXCEPTION 'PowerOps model approvals are immutable; record a new decision through a governed workflow'
 USING ERRCODE='42501';
END;
$$;
ALTER FUNCTION powerops_ml_reject_approval_mutation() OWNER TO powerops_registry_owner;
REVOKE ALL ON FUNCTION powerops_ml_reject_approval_mutation() FROM PUBLIC;
DROP TRIGGER IF EXISTS powerops_ml_approvals_no_mutation ON powerops_ml_model_approvals;
CREATE TRIGGER powerops_ml_approvals_no_mutation
 BEFORE UPDATE OR DELETE ON powerops_ml_model_approvals
 FOR EACH ROW EXECUTE FUNCTION powerops_ml_reject_approval_mutation();

COMMIT;

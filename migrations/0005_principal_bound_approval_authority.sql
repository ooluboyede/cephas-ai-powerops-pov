-- Gate 0.6.3.1: bind approval authority to the authenticated PostgreSQL login.
-- Apply after migrations 0001-0004 as a database administrator.
-- Approval-capable LOGIN roles must be dedicated per human principal and scope.

BEGIN;

ALTER TABLE powerops_security.db_principal_scopes
  ADD COLUMN IF NOT EXISTS principal_id text;
ALTER TABLE powerops_security.db_principal_scopes
  DROP CONSTRAINT IF EXISTS db_principal_scopes_principal_id_nonempty;
ALTER TABLE powerops_security.db_principal_scopes
  ADD CONSTRAINT db_principal_scopes_principal_id_nonempty
  CHECK (principal_id IS NULL OR length(btrim(principal_id)) > 0);

CREATE OR REPLACE FUNCTION powerops_security.current_principal_id()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, powerops_security
AS $function$
  SELECT principal_id
  FROM powerops_security.db_principal_scopes
  WHERE db_role = SESSION_USER::name
    AND enabled = true
    AND principal_id IS NOT NULL
$function$;
ALTER FUNCTION powerops_security.current_principal_id() OWNER TO powerops_scope_owner;
REVOKE ALL ON FUNCTION powerops_security.current_principal_id() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION powerops_security.current_principal_id() TO powerops_runtime, powerops_registry_owner;
GRANT EXECUTE ON FUNCTION powerops_security.current_tenant_id() TO powerops_registry_owner;
GRANT EXECUTE ON FUNCTION powerops_security.current_business_unit_id() TO powerops_registry_owner;

DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'powerops_approval_runtime') THEN
    CREATE ROLE powerops_approval_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
END
$roles$;
ALTER ROLE powerops_approval_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
GRANT USAGE ON SCHEMA powerops_security TO powerops_approval_runtime, powerops_registry_owner;

-- Reconstruct approval capability membership after restore/hardening. The
-- principal mapping is protected data; only mapped dedicated logins receive it.
DO $principal_roles$
DECLARE
  scoped record;
BEGIN
  FOR scoped IN
    SELECT db_role FROM powerops_security.db_principal_scopes
    WHERE enabled = true AND principal_id IS NOT NULL
  LOOP
    EXECUTE format(
      'ALTER ROLE %I WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
      scoped.db_role
    );
    EXECUTE format('GRANT powerops_runtime TO %I WITH INHERIT TRUE, SET TRUE', scoped.db_role);
    EXECUTE format('GRANT powerops_approval_runtime TO %I WITH INHERIT TRUE, SET TRUE', scoped.db_role);
  END LOOP;
END
$principal_roles$;

-- Convert assignments into immutable grant records. Revocation is the only
-- permitted update; re-grant creates a new UUID-backed row.
ALTER TABLE powerops_ml_principal_role_assignments
  ADD COLUMN IF NOT EXISTS grant_id uuid DEFAULT gen_random_uuid();

UPDATE powerops_ml_principal_role_assignments
SET grant_id = gen_random_uuid()
WHERE grant_id IS NULL;

ALTER TABLE powerops_ml_principal_role_assignments
  ALTER COLUMN grant_id SET DEFAULT gen_random_uuid(),
  ALTER COLUMN grant_id SET NOT NULL;

DO $constraints$
DECLARE
  fk record;
BEGIN
  FOR fk IN
    SELECT conname
    FROM pg_constraint
    WHERE conrelid = 'public.powerops_ml_model_approvals'::regclass
      AND contype = 'f'
      AND confrelid = 'public.powerops_ml_principal_role_assignments'::regclass
  LOOP
    EXECUTE format('ALTER TABLE public.powerops_ml_model_approvals DROP CONSTRAINT %I', fk.conname);
  END LOOP;
END
$constraints$;

ALTER TABLE powerops_ml_principal_role_assignments
  DROP CONSTRAINT IF EXISTS powerops_ml_principal_role_assignments_pkey;
ALTER TABLE powerops_ml_principal_role_assignments
  ADD CONSTRAINT powerops_ml_principal_role_assignments_pkey PRIMARY KEY (grant_id);

CREATE UNIQUE INDEX IF NOT EXISTS powerops_ml_role_assignment_one_active
  ON powerops_ml_principal_role_assignments
    (tenant_id,business_unit_id,principal_id,role_name)
  WHERE revoked_at IS NULL;

ALTER TABLE powerops_ml_model_approvals
  ADD COLUMN IF NOT EXISTS grant_id uuid;

UPDATE powerops_ml_model_approvals a
SET grant_id = g.grant_id
FROM powerops_ml_principal_role_assignments g
WHERE a.grant_id IS NULL
  AND a.tenant_id = g.tenant_id
  AND a.business_unit_id = g.business_unit_id
  AND a.principal_id = g.principal_id
  AND a.role_name = g.role_name;



-- Existing approvals must retain their exact historical assignment reference.
DO $legacy$
BEGIN
  IF EXISTS (SELECT 1 FROM powerops_ml_model_approvals WHERE grant_id IS NULL) THEN
    RAISE EXCEPTION 'Cannot migrate approval history: an approval has no matching historical role grant';
  END IF;
END
$legacy$;

ALTER TABLE powerops_ml_model_approvals
  ALTER COLUMN grant_id SET NOT NULL;
ALTER TABLE powerops_ml_model_approvals
  ADD CONSTRAINT powerops_ml_approvals_exact_grant_fk
  FOREIGN KEY (grant_id)
  REFERENCES powerops_ml_principal_role_assignments (grant_id)
  ON DELETE RESTRICT;

CREATE OR REPLACE FUNCTION powerops_ml_require_active_approval_assignment()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $body$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM public.powerops_ml_principal_role_assignments g
    WHERE g.grant_id = NEW.grant_id
      AND g.tenant_id = NEW.tenant_id
      AND g.business_unit_id = NEW.business_unit_id
      AND g.principal_id = NEW.principal_id
      AND g.role_name = NEW.role_name
      AND g.revoked_at IS NULL
  ) THEN
    RAISE EXCEPTION 'An active exact scoped role grant is required for this approval'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$body$;
ALTER FUNCTION powerops_ml_require_active_approval_assignment() OWNER TO powerops_registry_owner;

CREATE OR REPLACE FUNCTION powerops_ml_reject_grant_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $body$
BEGIN
  IF NEW.grant_id IS DISTINCT FROM OLD.grant_id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.business_unit_id IS DISTINCT FROM OLD.business_unit_id
     OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
     OR NEW.role_name IS DISTINCT FROM OLD.role_name
     OR NEW.granted_by IS DISTINCT FROM OLD.granted_by
     OR NEW.granted_at IS DISTINCT FROM OLD.granted_at
     OR OLD.revoked_at IS NOT NULL
     OR NEW.revoked_at IS NULL THEN
    RAISE EXCEPTION 'Role grant history is immutable; only one-way revocation is permitted'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$body$;
ALTER FUNCTION powerops_ml_reject_grant_mutation() OWNER TO powerops_registry_owner;
REVOKE ALL ON FUNCTION powerops_ml_reject_grant_mutation() FROM PUBLIC;
DROP TRIGGER IF EXISTS powerops_ml_grants_immutable ON powerops_ml_principal_role_assignments;
CREATE TRIGGER powerops_ml_grants_immutable
  BEFORE UPDATE ON powerops_ml_principal_role_assignments
  FOR EACH ROW EXECUTE FUNCTION powerops_ml_reject_grant_mutation();

-- Approvals can no longer be inserted directly by the shared runtime role.
REVOKE INSERT ON powerops_ml_model_approvals FROM PUBLIC, powerops_runtime, powerops_approval_runtime;
GRANT SELECT ON powerops_ml_model_approvals TO powerops_runtime;

CREATE OR REPLACE FUNCTION powerops_ml_record_principal_approval(
  p_candidate_id text,
  p_approval_id text,
  p_role_name text,
  p_decision text,
  p_reason text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $body$
DECLARE
  v_tenant_id text;
  v_business_unit_id text;
  v_principal_id text;
  v_grant_id uuid;
  v_creator text;
  v_status text;
  v_existing public.powerops_ml_model_approvals%ROWTYPE;
  v_result public.powerops_ml_model_approvals%ROWTYPE;
BEGIN
  v_tenant_id := powerops_security.current_tenant_id();
  v_business_unit_id := powerops_security.current_business_unit_id();
  v_principal_id := powerops_security.current_principal_id();

  IF v_tenant_id IS NULL OR v_business_unit_id IS NULL OR v_principal_id IS NULL THEN
    RAISE EXCEPTION 'Approval requires an enabled principal-bound database login'
      USING ERRCODE = '42501';
  END IF;
  IF p_candidate_id IS NULL OR length(btrim(p_candidate_id)) = 0
     OR p_approval_id IS NULL OR length(btrim(p_approval_id)) = 0
     OR p_reason IS NULL OR length(btrim(p_reason)) = 0 THEN
    RAISE EXCEPTION 'Candidate, approval ID and reason are required'
      USING ERRCODE = '22023';
  END IF;
  IF p_role_name NOT IN ('model-risk','security','operations-owner')
     OR p_decision NOT IN ('approve','reject') THEN
    RAISE EXCEPTION 'Approval role or decision is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT a.grant_id INTO v_grant_id
  FROM public.powerops_ml_principal_role_assignments a
  WHERE a.tenant_id = v_tenant_id
    AND a.business_unit_id = v_business_unit_id
    AND a.principal_id = v_principal_id
    AND a.role_name = p_role_name
    AND a.revoked_at IS NULL
  FOR SHARE;

  IF v_grant_id IS NULL THEN
    RAISE EXCEPTION 'No active role grant exists for the authenticated database principal'
      USING ERRCODE = '42501';
  END IF;

  SELECT c.created_by, c.status INTO v_creator, v_status
  FROM public.powerops_ml_model_candidates c
  WHERE c.tenant_id = v_tenant_id
    AND c.business_unit_id = v_business_unit_id
    AND c.candidate_id = p_candidate_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Unknown candidate in the authenticated scope'
      USING ERRCODE = 'P0002';
  END IF;
  IF v_status <> 'candidate' THEN
    RAISE EXCEPTION 'Candidate is not open for approval'
      USING ERRCODE = '55000';
  END IF;
  IF v_creator = v_principal_id THEN
    RAISE EXCEPTION 'Model creator cannot approve their own candidate'
      USING ERRCODE = '42501';
  END IF;

  SELECT * INTO v_existing
  FROM public.powerops_ml_model_approvals a
  WHERE a.tenant_id = v_tenant_id
    AND a.business_unit_id = v_business_unit_id
    AND a.approval_id = p_approval_id;

  IF FOUND THEN
    IF v_existing.candidate_id = p_candidate_id
       AND v_existing.principal_id = v_principal_id
       AND v_existing.role_name = p_role_name
       AND v_existing.decision = p_decision
       AND v_existing.reason = p_reason THEN
      RETURN to_jsonb(v_existing);
    END IF;
    RAISE EXCEPTION 'Approval ID already exists with different content'
      USING ERRCODE = '23505';
  END IF;

  INSERT INTO public.powerops_ml_model_approvals
    (tenant_id,business_unit_id,candidate_id,approval_id,principal_id,role_name,decision,reason,grant_id)
  VALUES
    (v_tenant_id,v_business_unit_id,p_candidate_id,p_approval_id,v_principal_id,p_role_name,p_decision,p_reason,v_grant_id)
  RETURNING * INTO v_result;

  IF p_decision = 'reject' THEN
    UPDATE public.powerops_ml_model_candidates
    SET status = 'rejected',
        candidate_data = jsonb_set(candidate_data, '{status}', to_jsonb('rejected'::text)),
        updated_at = clock_timestamp()
    WHERE tenant_id = v_tenant_id
      AND business_unit_id = v_business_unit_id
      AND candidate_id = p_candidate_id;
  END IF;

  RETURN to_jsonb(v_result);
END;
$body$;

ALTER FUNCTION powerops_ml_record_principal_approval(text,text,text,text,text)
  OWNER TO powerops_registry_owner;
REVOKE ALL ON FUNCTION powerops_ml_record_principal_approval(text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION powerops_ml_record_principal_approval(text,text,text,text,text)
  TO powerops_approval_runtime;

COMMIT;

-- Provisioning contract (administrator only):
-- 1. Create a unique LOGIN role for each approval principal in each tenant/BU.
-- 2. Grant powerops_runtime and powerops_approval_runtime to that LOGIN role.
-- 3. Insert db_principal_scopes(db_role,tenant_id,business_unit_id,principal_id,enabled).
-- 4. Do not reuse that login for another human principal; rotate credentials through
--    the customer's secret manager and isolate connection pools by exact login.
-- 5. Reapply migration 0005 after migration 0003 during fresh-cluster role reconstruction,
--    then reconstruct principal-bound LOGIN roles and mapping rows from protected backup.

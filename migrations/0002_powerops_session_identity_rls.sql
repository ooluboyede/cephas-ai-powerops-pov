-- Gate 0.5.8: bind RLS scope to the authenticated PostgreSQL login.
-- Apply as a database administrator/migration role. Runtime connections must use
-- one database login per tenant + business unit. Never share a scoped login across scopes.

DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'powerops_runtime') THEN
    CREATE ROLE powerops_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'powerops_scope_owner') THEN
    CREATE ROLE powerops_scope_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'powerops_registry_owner') THEN
    CREATE ROLE powerops_registry_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
END
$roles$;

ALTER ROLE powerops_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
ALTER ROLE powerops_scope_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
ALTER ROLE powerops_registry_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;

CREATE SCHEMA IF NOT EXISTS powerops_security AUTHORIZATION powerops_scope_owner;
ALTER SCHEMA powerops_security OWNER TO powerops_scope_owner;
REVOKE ALL ON SCHEMA powerops_security FROM PUBLIC;
GRANT USAGE ON SCHEMA powerops_security TO powerops_runtime;

CREATE TABLE IF NOT EXISTS powerops_security.db_principal_scopes (
  db_role name PRIMARY KEY,
  tenant_id text NOT NULL,
  business_unit_id text NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE powerops_security.db_principal_scopes OWNER TO powerops_scope_owner;
REVOKE ALL ON powerops_security.db_principal_scopes FROM PUBLIC;
REVOKE ALL ON powerops_security.db_principal_scopes FROM powerops_runtime;

CREATE OR REPLACE FUNCTION powerops_security.current_tenant_id()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, powerops_security
AS $function$
  SELECT tenant_id
  FROM powerops_security.db_principal_scopes
  WHERE db_role = SESSION_USER::name AND enabled = true
$function$;

CREATE OR REPLACE FUNCTION powerops_security.current_business_unit_id()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, powerops_security
AS $function$
  SELECT business_unit_id
  FROM powerops_security.db_principal_scopes
  WHERE db_role = SESSION_USER::name AND enabled = true
$function$;

ALTER FUNCTION powerops_security.current_tenant_id() OWNER TO powerops_scope_owner;
ALTER FUNCTION powerops_security.current_business_unit_id() OWNER TO powerops_scope_owner;
REVOKE ALL ON FUNCTION powerops_security.current_tenant_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION powerops_security.current_business_unit_id() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION powerops_security.current_tenant_id() TO powerops_runtime;
GRANT EXECUTE ON FUNCTION powerops_security.current_business_unit_id() TO powerops_runtime;

-- Registry objects are owned by a non-login role, never by a runtime connection.
ALTER TABLE powerops_ml_model_candidates OWNER TO powerops_registry_owner;
ALTER TABLE powerops_ml_model_releases OWNER TO powerops_registry_owner;
ALTER TABLE powerops_ml_audit_events OWNER TO powerops_registry_owner;
ALTER FUNCTION powerops_ml_reject_audit_mutation() OWNER TO powerops_registry_owner;

-- Remove the old caller-controlled custom-GUC policies. Scope now comes from SESSION_USER.
DROP POLICY IF EXISTS powerops_ml_candidates_scope ON powerops_ml_model_candidates;
CREATE POLICY powerops_ml_candidates_scope ON powerops_ml_model_candidates
  USING (
    tenant_id = powerops_security.current_tenant_id()
    AND business_unit_id = powerops_security.current_business_unit_id()
  )
  WITH CHECK (
    tenant_id = powerops_security.current_tenant_id()
    AND business_unit_id = powerops_security.current_business_unit_id()
  );

DROP POLICY IF EXISTS powerops_ml_releases_scope ON powerops_ml_model_releases;
CREATE POLICY powerops_ml_releases_scope ON powerops_ml_model_releases
  USING (
    tenant_id = powerops_security.current_tenant_id()
    AND business_unit_id = powerops_security.current_business_unit_id()
  )
  WITH CHECK (
    tenant_id = powerops_security.current_tenant_id()
    AND business_unit_id = powerops_security.current_business_unit_id()
  );

DROP POLICY IF EXISTS powerops_ml_audit_scope ON powerops_ml_audit_events;
CREATE POLICY powerops_ml_audit_scope ON powerops_ml_audit_events
  USING (
    tenant_id = powerops_security.current_tenant_id()
    AND business_unit_id = powerops_security.current_business_unit_id()
  )
  WITH CHECK (
    tenant_id = powerops_security.current_tenant_id()
    AND business_unit_id = powerops_security.current_business_unit_id()
  );

-- Runtime permissions are intentionally narrow. Audit records cannot be changed
-- or deleted by the runtime group; no table is writable by a runtime table owner.
REVOKE ALL ON powerops_ml_model_candidates, powerops_ml_model_releases, powerops_ml_audit_events FROM PUBLIC;
REVOKE ALL ON powerops_ml_model_candidates, powerops_ml_model_releases, powerops_ml_audit_events FROM powerops_runtime;
GRANT SELECT, INSERT, UPDATE ON powerops_ml_model_candidates TO powerops_runtime;
GRANT SELECT, INSERT, UPDATE ON powerops_ml_model_releases TO powerops_runtime;
GRANT SELECT, INSERT ON powerops_ml_audit_events TO powerops_runtime;

-- The migration/administrator provisions one LOGIN role per tenant+business-unit,
-- grants it membership in powerops_runtime, and inserts its exact scope in
-- powerops_security.db_principal_scopes. Runtime roles must never be members of
-- another scoped LOGIN role, the scope-owner role, or the registry-owner role.

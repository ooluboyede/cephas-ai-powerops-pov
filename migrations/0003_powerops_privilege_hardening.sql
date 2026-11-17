-- Gate 0.5.9: normalize scoped LOGIN roles against legacy privilege contamination.
-- Apply as a database administrator after 0002. Scope rows are the authoritative
-- inventory of provisioned runtime login roles.

DO $hardening$
DECLARE
  scoped record;
  membership record;
BEGIN
  FOR scoped IN
    SELECT db_role
    FROM powerops_security.db_principal_scopes
  LOOP
    -- A scoped identity must be an ordinary LOGIN role. It inherits only the
    -- explicitly granted powerops_runtime group; it is never an owner/admin.
    EXECUTE format(
      'ALTER ROLE %I WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
      scoped.db_role
    );

    -- Remove every inherited membership except the single runtime group.
    FOR membership IN
      SELECT granted.rolname
      FROM pg_auth_members m
      JOIN pg_roles member_role ON member_role.oid = m.member
      JOIN pg_roles granted ON granted.oid = m.roleid
      WHERE member_role.rolname = scoped.db_role::text
        AND granted.rolname <> 'powerops_runtime'
    LOOP
      EXECUTE format('REVOKE %I FROM %I', membership.rolname, scoped.db_role);
    END LOOP;

    -- Strip direct privileges that may have been granted before this upgrade.
    EXECUTE format(
      'REVOKE ALL PRIVILEGES ON TABLE powerops_ml_model_candidates, powerops_ml_model_releases, powerops_ml_audit_events, powerops_security.db_principal_scopes FROM %I',
      scoped.db_role
    );
    EXECUTE format('REVOKE ALL PRIVILEGES ON SCHEMA powerops_security FROM %I', scoped.db_role);
    EXECUTE format('REVOKE CREATE ON SCHEMA public FROM %I', scoped.db_role);
    EXECUTE format('GRANT powerops_runtime TO %I', scoped.db_role);
  END LOOP;

  -- The runtime capability role itself must not inherit another role's powers.
  FOR membership IN
    SELECT granted.rolname
    FROM pg_auth_members m
    JOIN pg_roles member_role ON member_role.oid = m.member
    JOIN pg_roles granted ON granted.oid = m.roleid
    WHERE member_role.rolname = 'powerops_runtime'
  LOOP
    EXECUTE format('REVOKE %I FROM powerops_runtime', membership.rolname);
  END LOOP;
END
$hardening$;

-- Reassert protected object ownership after any legacy deployment changes.
ALTER TABLE powerops_ml_model_candidates OWNER TO powerops_registry_owner;
ALTER TABLE powerops_ml_model_releases OWNER TO powerops_registry_owner;
ALTER TABLE powerops_ml_audit_events OWNER TO powerops_registry_owner;
ALTER TABLE powerops_security.db_principal_scopes OWNER TO powerops_scope_owner;
ALTER FUNCTION powerops_security.current_tenant_id() OWNER TO powerops_scope_owner;
ALTER FUNCTION powerops_security.current_business_unit_id() OWNER TO powerops_scope_owner;
ALTER FUNCTION powerops_ml_reject_audit_mutation() OWNER TO powerops_registry_owner;

-- Reassert exact capability grants after cleanup.
REVOKE ALL ON powerops_ml_model_candidates, powerops_ml_model_releases, powerops_ml_audit_events FROM PUBLIC;
REVOKE ALL ON powerops_ml_model_candidates, powerops_ml_model_releases, powerops_ml_audit_events FROM powerops_runtime;
GRANT SELECT, INSERT, UPDATE ON powerops_ml_model_candidates TO powerops_runtime;
GRANT SELECT, INSERT, UPDATE ON powerops_ml_model_releases TO powerops_runtime;
GRANT SELECT, INSERT ON powerops_ml_audit_events TO powerops_runtime;
REVOKE ALL ON powerops_security.db_principal_scopes FROM PUBLIC, powerops_runtime;
GRANT USAGE ON SCHEMA powerops_security TO powerops_runtime;

"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const adminUrl = process.env.POWEROPS_PG_ADMIN_URL;

test("PostgreSQL RLS scope is bound to SESSION_USER and resists custom-GUC impersonation", {
  skip: !adminUrl ? "Set POWEROPS_PG_ADMIN_URL to run PostgreSQL identity-boundary integration tests" : false
}, async () => {
  const { Pool } = require("pg");
  const admin = new Pool({ connectionString: adminUrl, max: 2 });
  const password = "powerops_gate058_test_password";
  const roleMap = [
    { role: "powerops_app_a1", tenant: "tenant-a", bu: "unit-1" },
    { role: "powerops_app_a2", tenant: "tenant-a", bu: "unit-2" },
    { role: "powerops_app_b1", tenant: "tenant-b", bu: "unit-1" }
  ];
  const pools = new Map();
  const makePool = role => {
    const url = new URL(adminUrl);
    url.username = role;
    url.password = password;
    return new Pool({ connectionString: url.toString(), max: 4 });
  };
  try {
    const initialMigration = fs.readFileSync(path.join(__dirname, "..", "migrations", "0001_powerops_ml_registry_rls.sql"), "utf8");
    await admin.query(initialMigration);

    // Simulate a legacy upgrade: scoped logins already exist with excessive
    // role attributes, direct table privileges and unwanted role memberships.
    await admin.query("CREATE ROLE powerops_legacy_privileged NOLOGIN");
    for (const item of roleMap) {
      await admin.query(
        `CREATE ROLE ${item.role} LOGIN INHERIT PASSWORD '${password}' CREATEDB CREATEROLE NOSUPERUSER NOBYPASSRLS`
      );
    }
    await admin.query("GRANT powerops_legacy_privileged TO powerops_app_a1");
    await admin.query("GRANT powerops_app_a2 TO powerops_app_a1");
    await admin.query("GRANT ALL PRIVILEGES ON powerops_ml_model_candidates, powerops_ml_model_releases, powerops_ml_audit_events TO powerops_app_a1");

    for (const migrationFile of [
      "0002_powerops_session_identity_rls.sql"
    ]) {
      const migration = fs.readFileSync(path.join(__dirname, "..", "migrations", migrationFile), "utf8");
      await admin.query(migration);
    }

    // Add additional unwanted owner memberships after 0002 creates the owner roles.
    await admin.query("GRANT powerops_scope_owner TO powerops_app_a1");
    await admin.query("GRANT powerops_registry_owner TO powerops_app_a1");
    await admin.query("GRANT SELECT, INSERT, UPDATE, DELETE ON powerops_security.db_principal_scopes TO powerops_app_a1");
    for (const item of roleMap) {
      await admin.query(
        "INSERT INTO powerops_security.db_principal_scopes (db_role,tenant_id,business_unit_id,enabled) VALUES ($1,$2,$3,true) ON CONFLICT (db_role) DO UPDATE SET tenant_id=EXCLUDED.tenant_id,business_unit_id=EXCLUDED.business_unit_id,enabled=true",
        [item.role, item.tenant, item.bu]
      );
    }
    const hardening = fs.readFileSync(path.join(__dirname, "..", "migrations", "0003_powerops_privilege_hardening.sql"), "utf8");
    await admin.query(hardening);
    for (const item of roleMap) pools.set(item.role, makePool(item.role));

    const roleFlags = await admin.query(
      "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls FROM pg_roles WHERE rolname = ANY($1::text[])",
      [roleMap.map(x => x.role)]
    );
    for (const role of roleFlags.rows) {
      assert.equal(role.rolsuper, false);
      assert.equal(role.rolcreatedb, false);
      assert.equal(role.rolcreaterole, false);
      assert.equal(role.rolbypassrls, false);
    }

    const candidateA = "scope-a-" + crypto.randomUUID();
    const candidateB = "scope-b-" + crypto.randomUUID();
    const data = (candidateId, tenant) => ({
      candidateId, modelVersion: "identity-boundary-test", manifestSha256: "a".repeat(64),
      artifactSha256: "b".repeat(64), status: "candidate", createdBy: tenant, approvals: []
    });
    for (const [tenant, bu, candidateId] of [
      ["tenant-a", "unit-1", candidateA],
      ["tenant-b", "unit-1", candidateB]
    ]) {
      const d = data(candidateId, tenant);
      await admin.query(
        "INSERT INTO powerops_ml_model_candidates (tenant_id,business_unit_id,candidate_id,model_version,manifest_sha256,artifact_sha256,status,candidate_data,created_by) VALUES ($1,$2,$3,$4,$5,$6,'candidate',$7::jsonb,$8)",
        [tenant, bu, candidateId, d.modelVersion, d.manifestSha256, d.artifactSha256, JSON.stringify(d), tenant]
      );
    }

    const principals = {
      readerA1: { tenantId: "tenant-a", businessUnitId: "unit-1", roles: ["registry-reader", "auditor"] },
      readerA2: { tenantId: "tenant-a", businessUnitId: "unit-2", roles: ["registry-reader"] },
      readerB1: { tenantId: "tenant-b", businessUnitId: "unit-1", roles: ["registry-reader"] }
    };
    const { createTokenAuthority } = require("../src/ml-registry-security.js");
    const { createPostgresRegistry } = require("../src/ml-registry-postgres.js");
    const authority = createTokenAuthority({ secret: "gate-058-integration-secret-at-least-32-bytes", principals });
    const poolForIdentity = identity => {
      const role = roleMap.find(x => x.tenant === identity.tenantId && x.bu === identity.businessUnitId)?.role;
      return role ? pools.get(role) : null;
    };
    const registry = createPostgresRegistry({ poolForIdentity, tokenAuthority: authority });

    assert.deepEqual((await registry.listCandidates(authority.issueToken("readerA1"))).map(x => x.candidateId), [candidateA]);
    assert.deepEqual(await registry.listCandidates(authority.issueToken("readerA2")), []);
    assert.deepEqual((await registry.listCandidates(authority.issueToken("readerB1"))).map(x => x.candidateId), [candidateB]);

    // Critical negative test: the real tenant-A runtime login deliberately changes
    // both legacy custom GUCs to tenant-B. RLS must still use the immutable login mapping.
    const attacker = await pools.get("powerops_app_a1").connect();
    try {
      await attacker.query("BEGIN");
      await attacker.query("SELECT set_config('app.tenant_id',$1,true), set_config('app.business_unit_id',$2,true)", ["tenant-b", "unit-1"]);
      const stolen = await attacker.query("SELECT candidate_id FROM powerops_ml_model_candidates WHERE candidate_id=$1", [candidateB]);
      assert.equal(stolen.rowCount, 0, "custom GUC spoofing must not disclose another tenant's row");
      await assert.rejects(() => attacker.query(
        "INSERT INTO powerops_ml_model_candidates (tenant_id,business_unit_id,candidate_id,model_version,manifest_sha256,artifact_sha256,status,candidate_data,created_by) VALUES ('tenant-b','unit-1',$1,'attack',$2,$3,'candidate','{}','attacker')",
        ["spoof-" + crypto.randomUUID(), "c".repeat(64), "d".repeat(64)]
      ), /row-level security/i, "custom GUC spoofing must not permit cross-tenant writes");
      await attacker.query("ROLLBACK");
      await assert.rejects(() => attacker.query("SET ROLE powerops_app_b1"), /permission denied|cannot set role/i);
    } finally { attacker.release(); }

    // Catalog-level ownership assertions cover tables, scope schema/map and functions.
    const owners = await admin.query(`
      SELECT c.relname, r.rolname AS owner
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_roles r ON r.oid = c.relowner
      WHERE (n.nspname = 'public' AND c.relname IN ('powerops_ml_model_candidates','powerops_ml_model_releases','powerops_ml_audit_events'))
         OR (n.nspname = 'powerops_security' AND c.relname = 'db_principal_scopes')
      ORDER BY c.relname
    `);
    assert.deepEqual(owners.rows, [
      { relname: "db_principal_scopes", owner: "powerops_scope_owner" },
      { relname: "powerops_ml_audit_events", owner: "powerops_registry_owner" },
      { relname: "powerops_ml_model_candidates", owner: "powerops_registry_owner" },
      { relname: "powerops_ml_model_releases", owner: "powerops_registry_owner" }
    ]);
    const functionOwners = await admin.query(`
      SELECT p.proname, r.rolname AS owner
      FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      JOIN pg_roles r ON r.oid=p.proowner
      WHERE (n.nspname='powerops_security' AND p.proname IN ('current_tenant_id','current_business_unit_id'))
         OR (n.nspname='public' AND p.proname='powerops_ml_reject_audit_mutation')
      ORDER BY p.proname
    `);
    assert.deepEqual(functionOwners.rows, [
      { proname: "current_business_unit_id", owner: "powerops_scope_owner" },
      { proname: "current_tenant_id", owner: "powerops_scope_owner" },
      { proname: "powerops_ml_reject_audit_mutation", owner: "powerops_registry_owner" }
    ]);
    const schemaOwner = await admin.query(`
      SELECT r.rolname AS owner FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner
      WHERE n.nspname='powerops_security'
    `);
    assert.equal(schemaOwner.rows[0].owner, "powerops_scope_owner");

    // Scoped login roles may inherit only the runtime capability group.
    const memberships = await admin.query(`
      SELECT member_role.rolname AS member, granted_role.rolname AS granted,
             m.inherit_option AS inherit_option, m.set_option AS set_option, m.admin_option AS admin_option
      FROM pg_auth_members m
      JOIN pg_roles member_role ON member_role.oid=m.member
      JOIN pg_roles granted_role ON granted_role.oid=m.roleid
      WHERE member_role.rolname = ANY($1::text[])
      ORDER BY member_role.rolname, granted_role.rolname
    `, [roleMap.map(x => x.role)]);
    assert.deepEqual(memberships.rows, roleMap.map(x => ({ member: x.role, granted: "powerops_runtime", inherit_option: true, set_option: true, admin_option: false })).sort((a,b)=>a.member.localeCompare(b.member)));
    for (const item of roleMap) {
      assert.equal(await admin.query("SELECT pg_has_role($1,'powerops_runtime','USAGE') AS inherits_runtime", [item.role]).then(x=>x.rows[0].inherits_runtime), true);
    }
    const roleFlagsAfterUpgrade = await admin.query(
      "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, rolinherit FROM pg_roles WHERE rolname = ANY($1::text[])",
      [roleMap.map(x=>x.role)]
    );
    for (const role of roleFlagsAfterUpgrade.rows) {
      assert.equal(role.rolsuper, false);
      assert.equal(role.rolcreatedb, false);
      assert.equal(role.rolcreaterole, false);
      assert.equal(role.rolreplication, false);
      assert.equal(role.rolbypassrls, false);
      assert.equal(role.rolinherit, true);
    }
    const runtimeMemberships = await admin.query(`
      SELECT granted_role.rolname
      FROM pg_auth_members m JOIN pg_roles member_role ON member_role.oid=m.member
      JOIN pg_roles granted_role ON granted_role.oid=m.roleid
      WHERE member_role.rolname='powerops_runtime'
    `);
    assert.deepEqual(runtimeMemberships.rows, []);
    const ownerRoleFlags = await admin.query(
      "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls FROM pg_roles WHERE rolname IN ('powerops_runtime','powerops_scope_owner','powerops_registry_owner') ORDER BY rolname"
    );
    assert.deepEqual(ownerRoleFlags.rows, [
      { rolname: "powerops_registry_owner", rolcanlogin: false, rolsuper: false, rolcreatedb: false, rolcreaterole: false, rolbypassrls: false },
      { rolname: "powerops_runtime", rolcanlogin: false, rolsuper: false, rolcreatedb: false, rolcreaterole: false, rolbypassrls: false },
      { rolname: "powerops_scope_owner", rolcanlogin: false, rolsuper: false, rolcreatedb: false, rolcreaterole: false, rolbypassrls: false }
    ]);
    const ownerMemberships = await admin.query(`
      SELECT member_role.rolname
      FROM pg_auth_members m JOIN pg_roles member_role ON member_role.oid=m.member
      WHERE member_role.rolname IN ('powerops_scope_owner','powerops_registry_owner')
    `);
    assert.deepEqual(ownerMemberships.rows, []);

    const schemaPrivileges = await admin.query(
      "SELECT has_schema_privilege('powerops_app_a1','powerops_security','CREATE') AS security_create, has_schema_privilege('powerops_app_a1','public','CREATE') AS public_create"
    );
    assert.deepEqual(schemaPrivileges.rows[0], { security_create: false, public_create: false });

    const protectedObjects = [
      "powerops_ml_model_candidates",
      "powerops_ml_model_releases",
      "powerops_ml_audit_events",
      "powerops_security.db_principal_scopes"
    ];
    for (const objectName of protectedObjects) {
      const matrix = await admin.query(
        "SELECT has_table_privilege('powerops_app_a1',$1,'SELECT') AS can_select, has_table_privilege('powerops_app_a1',$1,'INSERT') AS can_insert, has_table_privilege('powerops_app_a1',$1,'UPDATE') AS can_update, has_table_privilege('powerops_app_a1',$1,'DELETE') AS can_delete, has_table_privilege('powerops_app_a1',$1,'TRUNCATE') AS can_truncate",
        [objectName]
      );
      const expected = objectName === "powerops_ml_audit_events"
        ? { can_select: true, can_insert: true, can_update: false, can_delete: false, can_truncate: false }
        : objectName === "powerops_security.db_principal_scopes"
          ? { can_select: false, can_insert: false, can_update: false, can_delete: false, can_truncate: false }
          : { can_select: true, can_insert: true, can_update: true, can_delete: false, can_truncate: false };
      assert.deepEqual(matrix.rows[0], expected, `unexpected effective privileges for ${objectName}`);
    }

    // Exercise the full denied DELETE/TRUNCATE matrix with the real scoped login.
    const deniedObjects = [
      "powerops_ml_model_candidates",
      "powerops_ml_model_releases",
      "powerops_ml_audit_events",
      "powerops_security.db_principal_scopes"
    ];
    const privilegeClient = await pools.get("powerops_app_a1").connect();
    try {
      for (const objectName of deniedObjects) {
        await assert.rejects(
          () => privilegeClient.query(`DELETE FROM ${objectName} WHERE false`),
          /permission denied/i,
          `DELETE must be denied for ${objectName}`
        );
        await assert.rejects(
          () => privilegeClient.query(`TRUNCATE TABLE ${objectName}`),
          /permission denied/i,
          `TRUNCATE must be denied for ${objectName}`
        );
      }
    } finally { privilegeClient.release(); }

    // Reconnect/pool recreation must preserve the authenticated database scope.
    await pools.get("powerops_app_a1").end();
    pools.set("powerops_app_a1", makePool("powerops_app_a1"));
    const afterReconnect = await registry.listCandidates(authority.issueToken("readerA1"));
    assert.deepEqual(afterReconnect.map(x => x.candidateId), [candidateA]);
  } finally {
    for (const pool of pools.values()) await pool.end();
    await admin.end();
  }
});

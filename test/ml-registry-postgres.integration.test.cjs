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
    await admin.query("GRANT SELECT, INSERT, UPDATE, DELETE ON powerops_security.db_principal_scopes TO powerops_app_a1");

    for (const migrationFile of [
      "0002_powerops_session_identity_rls.sql"
    ]) {
      const migration = fs.readFileSync(path.join(__dirname, "..", "migrations", migrationFile), "utf8");
      await admin.query(migration);
    }

    // Add additional unwanted owner memberships after 0002 creates the owner roles.
    await admin.query("GRANT powerops_scope_owner TO powerops_app_a1");
    await admin.query("GRANT powerops_registry_owner TO powerops_app_a1");
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

    const privilegeCheck = await admin.query(
      "SELECT has_table_privilege('powerops_app_a1','powerops_ml_model_candidates','DELETE') AS candidate_delete, has_table_privilege('powerops_app_a1','powerops_ml_audit_events','UPDATE') AS audit_update, has_table_privilege('powerops_app_a1','powerops_ml_audit_events','DELETE') AS audit_delete, has_table_privilege('powerops_app_a1','powerops_ml_audit_events','TRUNCATE') AS audit_truncate, has_table_privilege('powerops_app_a1','powerops_security.db_principal_scopes','SELECT') AS scope_read"
    );
    assert.deepEqual(privilegeCheck.rows[0], {
      candidate_delete: false, audit_update: false, audit_delete: false, audit_truncate: false, scope_read: false
    });

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

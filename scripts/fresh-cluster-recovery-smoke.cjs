"use strict";

// Fresh-cluster recovery acceptance. Credentials are ephemeral and never logged.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { Pool } = require("pg");
const { provisionScopedDatabaseRoles } = require("./provision-scoped-db-roles.cjs");

const adminUrl = process.env.POWEROPS_FRESH_CLUSTER_PG_ADMIN_URL;
if (!adminUrl) throw new Error("POWEROPS_FRESH_CLUSTER_PG_ADMIN_URL is required");

function runtimeUrl(base, role, password) {
  const url = new URL(base);
  url.username = role;
  url.password = password;
  return url.toString();
}

(async () => {
  const admin = new Pool({ connectionString: adminUrl, max: 2 });
  const pools = [];
  try {
    const migrations = path.join(__dirname, "..", "migrations");
    await admin.query(fs.readFileSync(path.join(migrations, "0001_powerops_ml_registry_rls.sql"), "utf8"));
    await admin.query(fs.readFileSync(path.join(migrations, "0002_powerops_session_identity_rls.sql"), "utf8"));
    const credentials = new Map();
    const provisioned = await provisionScopedDatabaseRoles({
      admin,
      credentialForRole: async role => {
        const password = crypto.randomBytes(32).toString("base64url");
        credentials.set(role, password);
        return password;
      }
    });
    assert.equal(provisioned.length, 3, "expected all three restored scoped identities to be provisioned");
    await admin.query(fs.readFileSync(path.join(migrations, "0003_powerops_privilege_hardening.sql"), "utf8"));

    const owner = await admin.query(`
      SELECT count(*)::int AS failures
      FROM (
        SELECT c.relname
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        JOIN pg_roles r ON r.oid=c.relowner
        WHERE (n.nspname='public' AND c.relname IN ('powerops_ml_model_candidates','powerops_ml_model_releases','powerops_ml_audit_events') AND r.rolname <> 'powerops_registry_owner')
           OR (n.nspname='powerops_security' AND c.relname='db_principal_scopes' AND r.rolname <> 'powerops_scope_owner')
      ) bad
    `);
    assert.equal(owner.rows[0].failures, 0, "restored object ownership must be re-established");

    const membership = await admin.query(`
      SELECT count(*)::int AS failures
      FROM pg_auth_members m JOIN pg_roles member_role ON member_role.oid=m.member
      JOIN pg_roles granted_role ON granted_role.oid=m.roleid
      WHERE member_role.rolname LIKE 'powerops_app_%' AND granted_role.rolname <> 'powerops_runtime'
    `);
    assert.equal(membership.rows[0].failures, 0, "scoped logins may inherit only powerops_runtime");

    const roles = await admin.query(`
      SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, rolinherit
      FROM pg_roles WHERE rolname = ANY($1::text[]) ORDER BY rolname
    `, [provisioned.map(x => x.role)]);
    assert.equal(roles.rowCount, 3);
    for (const role of roles.rows) {
      assert.equal(role.rolcanlogin, true);
      for (const flag of ["rolsuper","rolcreatedb","rolcreaterole","rolreplication","rolbypassrls"]) assert.equal(role[flag], false);
      assert.equal(role.rolinherit, true);
    }

    for (const identity of provisioned) {
      const password = credentials.get(identity.role);
      const pool = new Pool({ connectionString: runtimeUrl(adminUrl, identity.role, password), max: 1 });
      pools.push(pool);
      const client = await pool.connect();
      try {
        const who = await client.query("SELECT SESSION_USER, powerops_security.current_tenant_id() AS tenant_id, powerops_security.current_business_unit_id() AS bu_id");
        assert.deepEqual(who.rows[0], { session_user: identity.role, tenant_id: identity.tenantId, bu_id: identity.businessUnitId });
        const matrix = await client.query(`
          SELECT has_table_privilege(SESSION_USER,'powerops_ml_model_candidates','SELECT') AS candidate_read,
                 has_table_privilege(SESSION_USER,'powerops_ml_model_candidates','INSERT') AS candidate_insert,
                 has_table_privilege(SESSION_USER,'powerops_ml_model_candidates','UPDATE') AS candidate_update,
                 has_table_privilege(SESSION_USER,'powerops_ml_model_candidates','DELETE') AS candidate_delete,
                 has_table_privilege(SESSION_USER,'powerops_ml_model_candidates','TRUNCATE') AS candidate_truncate,
                 has_table_privilege(SESSION_USER,'powerops_ml_audit_events','SELECT') AS audit_read,
                 has_table_privilege(SESSION_USER,'powerops_ml_audit_events','INSERT') AS audit_insert,
                 has_table_privilege(SESSION_USER,'powerops_ml_audit_events','UPDATE') AS audit_update,
                 has_table_privilege(SESSION_USER,'powerops_security.db_principal_scopes','SELECT') AS scope_read
        `);
        assert.deepEqual(matrix.rows[0], {
          candidate_read: true, candidate_insert: true, candidate_update: true,
          candidate_delete: false, candidate_truncate: false,
          audit_read: true, audit_insert: true, audit_update: false, scope_read: false
        });
        await client.query("BEGIN");
        await client.query("SELECT set_config('app.tenant_id',$1,true)", [identity.tenantId === "tenant-a" ? "tenant-b" : "tenant-a"]);
        const current = await client.query("SELECT powerops_security.current_tenant_id() AS tenant_id");
        assert.equal(current.rows[0].tenant_id, identity.tenantId, "custom GUC must not override restored SESSION_USER mapping");
        await client.query("ROLLBACK");
      } finally { client.release(); }
    }

    const tenantA = provisioned.find(x => x.tenantId === "tenant-a" && x.businessUnitId === "unit-1");
    assert.ok(tenantA, "tenant-a/unit-1 scoped login must be present");
    const attackPool = pools[provisioned.indexOf(tenantA)];
    const attacker = await attackPool.connect();
    try {
      await assert.rejects(() => attacker.query(
        "INSERT INTO powerops_ml_model_candidates (tenant_id,business_unit_id,candidate_id,model_version,manifest_sha256,artifact_sha256,status,candidate_data,created_by) VALUES ('tenant-b','unit-1',$1,'fresh-cluster-attack',$2,$3,'candidate','{}','attacker')",
        ["fresh-" + crypto.randomUUID(), "a".repeat(64), "b".repeat(64)]
      ), /row-level security/i);
    } finally { attacker.release(); }

    console.log("Fresh-cluster recovery: scoped logins recreated, credentials authenticated, ownership/membership/privilege matrix passed, tenant spoofing/write isolation passed.");
  } finally {
    for (const pool of pools) await pool.end();
    await admin.end();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });

"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { Pool } = require("pg");
const { provisionScopedDatabaseRoles } = require("./provision-scoped-db-roles.cjs");

const adminUrl = process.env.POWEROPS_FRESH_CLUSTER_PG_ADMIN_URL;
if (!adminUrl) throw new Error("POWEROPS_FRESH_CLUSTER_PG_ADMIN_URL is required");
const tables = [
  "powerops_ml_model_candidates",
  "powerops_ml_model_releases",
  "powerops_ml_audit_events",
  "powerops_security.db_principal_scopes"
];
const privileges = ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE"];
const expected = [
  [true, true, true, false, false],
  [true, true, true, false, false],
  [true, true, false, false, false],
  [false, false, false, false, false]
];
function urlFor(base, role, password) {
  const url = new URL(base);
  url.username = role;
  url.password = password;
  return url.toString();
}
function id(prefix) { return prefix + crypto.randomUUID().replace(/-/g, ""); }
async function denied(client, sql, label) {
  await assert.rejects(() => client.query(sql),
    error => error && error.code === "42501",
    label + " must fail with PostgreSQL insufficient_privilege (42501)");
}

(async () => {
  const admin = new Pool({ connectionString: adminUrl, max: 3 });
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
    assert.equal(provisioned.length, 3);
    await admin.query(fs.readFileSync(path.join(migrations, "0003_powerops_privilege_hardening.sql"), "utf8"));

    const ownership = await admin.query(
      "SELECT " +
      "(SELECT r.rolname FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner WHERE n.nspname='powerops_security') AS schema_owner, " +
      "(SELECT r.rolname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND c.relname='powerops_ml_model_candidates') AS candidates_owner, " +
      "(SELECT r.rolname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND c.relname='powerops_ml_model_releases') AS releases_owner, " +
      "(SELECT r.rolname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND c.relname='powerops_ml_audit_events') AS audit_owner, " +
      "(SELECT r.rolname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='powerops_security' AND c.relname='db_principal_scopes') AS scope_owner, " +
      "(SELECT r.rolname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='powerops_security' AND p.proname='current_tenant_id') AS tenant_fn_owner, " +
      "(SELECT r.rolname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='powerops_security' AND p.proname='current_business_unit_id') AS bu_fn_owner, " +
      "(SELECT r.rolname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname='powerops_ml_reject_audit_mutation') AS audit_fn_owner"
    );
    assert.deepEqual(ownership.rows[0], {
      schema_owner: "powerops_scope_owner",
      candidates_owner: "powerops_registry_owner",
      releases_owner: "powerops_registry_owner",
      audit_owner: "powerops_registry_owner",
      scope_owner: "powerops_scope_owner",
      tenant_fn_owner: "powerops_scope_owner",
      bu_fn_owner: "powerops_scope_owner",
      audit_fn_owner: "powerops_registry_owner"
    });

    for (const identity of provisioned) {
      const membership = await admin.query(
        "SELECT granted.rolname,m.inherit_option,m.set_option,m.admin_option " +
        "FROM pg_auth_members m JOIN pg_roles member_role ON member_role.oid=m.member " +
        "JOIN pg_roles granted ON granted.oid=m.roleid WHERE member_role.rolname=$1",
        [identity.role]
      );
      assert.equal(membership.rowCount, 1, identity.role + " must have exactly one membership");
      assert.deepEqual(membership.rows[0], {
        rolname: "powerops_runtime", inherit_option: true, set_option: true, admin_option: false
      });
    }

    const groups = await admin.query(
      "SELECT r.rolname,r.rolcanlogin,r.rolsuper,r.rolcreatedb,r.rolcreaterole,r.rolreplication," +
      "r.rolbypassrls,r.rolinherit,(SELECT count(*)::int FROM pg_auth_members m WHERE m.member=r.oid) AS memberships " +
      "FROM pg_roles r WHERE r.rolname=ANY($1::text[]) ORDER BY r.rolname",
      [["powerops_runtime", "powerops_scope_owner", "powerops_registry_owner"]]
    );
    assert.equal(groups.rowCount, 3);
    for (const role of groups.rows) {
      assert.equal(role.rolcanlogin, false);
      for (const flag of ["rolsuper","rolcreatedb","rolcreaterole","rolreplication","rolbypassrls"]) assert.equal(role[flag], false);
      assert.equal(role.rolinherit, false);
      assert.equal(role.memberships, 0);
    }

    const loginRoles = await admin.query(
      "SELECT rolname,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls,rolinherit " +
      "FROM pg_roles WHERE rolname=ANY($1::text[]) ORDER BY rolname",
      [provisioned.map(x => x.role)]
    );
    assert.equal(loginRoles.rowCount, provisioned.length);
    for (const role of loginRoles.rows) {
      assert.equal(role.rolcanlogin, true);
      for (const flag of ["rolsuper","rolcreatedb","rolcreaterole","rolreplication","rolbypassrls"]) assert.equal(role[flag], false);
      assert.equal(role.rolinherit, true);
    }

    const fixtures = [];
    for (const identity of provisioned) {
      const candidate = id("fresh_candidate_");
      const release = id("fresh_release_");
      const eventHash = crypto.createHash("sha256").update(id("fresh_event_")).digest("hex");
      await admin.query(
        "INSERT INTO powerops_ml_model_candidates " +
        "(tenant_id,business_unit_id,candidate_id,model_version,manifest_sha256,artifact_sha256,status,candidate_data,created_by) " +
        "VALUES ($1,$2,$3,'fresh-cluster-fixture',$4,$5,'candidate','{}','gate-0.5.11')",
        [identity.tenantId, identity.businessUnitId, candidate, "a".repeat(64), "b".repeat(64)]
      );
      await admin.query(
        "INSERT INTO powerops_ml_model_releases (tenant_id,business_unit_id,release_id,candidate_id,is_active,release_data) " +
        "VALUES ($1,$2,$3,$4,false,'{}')",
        [identity.tenantId, identity.businessUnitId, release, candidate]
      );
      await admin.query(
        "INSERT INTO powerops_ml_audit_events " +
        "(tenant_id,business_unit_id,sequence,event_type,payload,actor_id,previous_hash,event_hash) " +
        "VALUES ($1,$2,1,'fresh-cluster-fixture','{}','gate-0.5.11','genesis',$3)",
        [identity.tenantId, identity.businessUnitId, eventHash]
      );
      fixtures.push({ role: identity.role, tenantId: identity.tenantId, businessUnitId: identity.businessUnitId,
        candidate, release, eventHash });
    }

    for (const identity of provisioned) {
      const password = credentials.get(identity.role);
      assert.ok(password);
      const pool = new Pool({ connectionString: urlFor(adminUrl, identity.role, password), max: 1 });
      pools.push(pool);
      const client = await pool.connect();
      try {
        const who = await client.query(
          "SELECT SESSION_USER,powerops_security.current_tenant_id() AS tenant_id," +
          "powerops_security.current_business_unit_id() AS bu_id"
        );
        assert.deepEqual(who.rows[0], {
          session_user: identity.role, tenant_id: identity.tenantId, bu_id: identity.businessUnitId
        });

        const columns = [];
        const expectedRow = {};
        tables.forEach((table, ti) => privileges.forEach((privilege, pi) => {
          const alias = "p_" + ti + "_" + pi;
          columns.push("has_table_privilege(SESSION_USER,'" + table + "','" + privilege + "') AS " + alias);
          expectedRow[alias] = expected[ti][pi];
        }));
        const matrix = await client.query("SELECT " + columns.join(","));
        assert.deepEqual(matrix.rows[0], expectedRow, identity.role + " complete effective privilege matrix");

        for (const table of tables) {
          await denied(client, "DELETE FROM " + table + " WHERE false", identity.role + " DELETE " + table);
          await denied(client, "TRUNCATE TABLE " + table, identity.role + " TRUNCATE " + table);
        }

        const other = fixtures.filter(row => row.tenantId !== identity.tenantId || row.businessUnitId !== identity.businessUnitId);
        assert.ok(other.length, "fixture must include another tenant/business unit");
        await client.query("BEGIN");
        await client.query("SELECT set_config('app.tenant_id',$1,true),set_config('app.business_unit_id',$2,true)",
          [other[0].tenantId, other[0].businessUnitId]);
        const spoofed = await client.query(
          "SELECT powerops_security.current_tenant_id() AS tenant_id," +
          "powerops_security.current_business_unit_id() AS bu_id"
        );
        assert.deepEqual(spoofed.rows[0], { tenant_id: identity.tenantId, bu_id: identity.businessUnitId },
          "custom GUCs must not override SESSION_USER scope");
        for (const fixture of other) {
          const candidateRead = await client.query("SELECT count(*)::int AS n FROM powerops_ml_model_candidates WHERE candidate_id=$1", [fixture.candidate]);
          const releaseRead = await client.query("SELECT count(*)::int AS n FROM powerops_ml_model_releases WHERE release_id=$1", [fixture.release]);
          const auditRead = await client.query("SELECT count(*)::int AS n FROM powerops_ml_audit_events WHERE event_hash=$1", [fixture.eventHash]);
          assert.equal(candidateRead.rows[0].n, 0, "cross-scope candidate read denied");
          assert.equal(releaseRead.rows[0].n, 0, "cross-scope release read denied");
          assert.equal(auditRead.rows[0].n, 0, "cross-scope audit read denied");
        }
        await client.query("ROLLBACK");

        const target = other[0];
        await denied(client,
          "INSERT INTO powerops_ml_model_candidates " +
          "(tenant_id,business_unit_id,candidate_id,model_version,manifest_sha256,artifact_sha256,status,candidate_data,created_by) " +
          "VALUES ('" + target.tenantId + "','" + target.businessUnitId + "','" + id("attack_candidate_") +
          "','cross-scope-attack','" + "c".repeat(64) + "','" + "d".repeat(64) + "','candidate','{}','attacker')",
          identity.role + " cross-scope candidate insert");
        await denied(client,
          "INSERT INTO powerops_ml_model_releases " +
          "(tenant_id,business_unit_id,release_id,candidate_id,is_active,release_data) VALUES ('" +
          target.tenantId + "','" + target.businessUnitId + "','" + id("attack_release_") + "','" +
          target.candidate + "',false,'{}')",
          identity.role + " cross-scope release insert");
        await denied(client,
          "INSERT INTO powerops_ml_audit_events " +
          "(tenant_id,business_unit_id,sequence,event_type,payload,actor_id,previous_hash,event_hash) VALUES ('" +
          target.tenantId + "','" + target.businessUnitId + "',999,'cross-scope-attack','{}','attacker','genesis','" +
          crypto.createHash("sha256").update(id("attack_event_")).digest("hex") + "')",
          identity.role + " cross-scope audit insert");
      } finally {
        client.release();
      }
    }
    console.log("Gate 0.5.11 passed: full 4-object/5-privilege matrix; denied DELETE/TRUNCATE; exact memberships/options; ownership; role attributes; authentication; GUC spoofing; cross-scope reads/writes.");
  } finally {
    for (const pool of pools) await pool.end();
    await admin.end();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });

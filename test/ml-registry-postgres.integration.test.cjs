"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const adminUrl = process.env.POWEROPS_PG_ADMIN_URL;
const appUrl = process.env.POWEROPS_PG_APP_URL;

test("real PostgreSQL migration enforces tenant + business-unit RLS and append-only audit", {
  skip: !adminUrl || !appUrl ? "Set POWEROPS_PG_ADMIN_URL and POWEROPS_PG_APP_URL to run PostgreSQL integration tests" : false
}, async () => {
  const { Pool } = require("pg");
  const admin = new Pool({ connectionString: adminUrl, max: 2 });
  let app;
  try {
    const migration = fs.readFileSync(path.join(__dirname, "..", "migrations", "0001_powerops_ml_registry_rls.sql"), "utf8");
    await admin.query(migration);

    await admin.query("DO $role$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'powerops_app') THEN CREATE ROLE powerops_app LOGIN PASSWORD 'powerops_app_test_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS; END IF; END $role$;");
    await admin.query("ALTER ROLE powerops_app WITH LOGIN PASSWORD 'powerops_app_test_password' NOSUPERUSER NOBYPASSRLS");
    await admin.query("GRANT USAGE ON SCHEMA public TO powerops_app");
    await admin.query("GRANT SELECT, INSERT, UPDATE, DELETE ON powerops_ml_model_candidates, powerops_ml_model_releases, powerops_ml_audit_events TO powerops_app");
    const roleCheck = await admin.query("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname='powerops_app'");
    assert.equal(roleCheck.rows[0].rolsuper, false);
    assert.equal(roleCheck.rows[0].rolbypassrls, false);

    app = new Pool({ connectionString: appUrl, max: 1 });
    const { createPostgresRegistry } = require("../src/ml-registry-postgres.js");
    const { createTokenAuthority } = require("../src/ml-registry-security.js");
    const authority = createTokenAuthority({
      secret: "postgres-integration-secret-at-least-32-bytes",
      principals: {
        tenantAUnit1: { tenantId: "tenant-a", businessUnitId: "unit-1", roles: ["registry-reader", "auditor"] },
        tenantAUnit2: { tenantId: "tenant-a", businessUnitId: "unit-2", roles: ["registry-reader", "auditor"] },
        tenantBUnit1: { tenantId: "tenant-b", businessUnitId: "unit-1", roles: ["registry-reader", "auditor"] }
      }
    });
    const registry = createPostgresRegistry({ pool: app, tokenAuthority: authority });
    const candidateId = "pg-it-" + require("node:crypto").randomUUID();

    const client = await app.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT set_config('app.tenant_id',$1,true), set_config('app.business_unit_id',$2,true)", ["tenant-a", "unit-1"]);
      await client.query(
        "INSERT INTO powerops_ml_model_candidates (tenant_id,business_unit_id,candidate_id,model_version,manifest_sha256,artifact_sha256,status,candidate_data,created_by) VALUES ($1,$2,$3,$4,$5,$6,'candidate',$7::jsonb,$8)",
        ["tenant-a", "unit-1", candidateId, "integration-test", "a".repeat(64), "b".repeat(64), JSON.stringify({ candidateId, marker: "tenant-a-unit-1" }), "integration-test"]
      );
      await client.query(
        "INSERT INTO powerops_ml_audit_events (tenant_id,business_unit_id,sequence,event_type,payload,actor_id,previous_hash,event_hash) VALUES ($1,$2,1,$3,$4::jsonb,$5,$6,$7)",
        ["tenant-a", "unit-1", "integration-test", JSON.stringify({ ok: true }), "integration-test", "GENESIS", "c".repeat(64)]
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }

    assert.equal((await registry.listCandidates(authority.issueToken("tenantAUnit1"))).length, 1);
    assert.equal((await registry.listCandidates(authority.issueToken("tenantAUnit2"))).length, 0, "same tenant, different business unit must see no rows");
    assert.equal((await registry.listCandidates(authority.issueToken("tenantBUnit1"))).length, 0, "different tenant must see no rows");

    const hiddenWithoutScope = await app.query("SELECT candidate_id FROM powerops_ml_model_candidates");
    assert.equal(hiddenWithoutScope.rowCount, 0, "transaction-local scope must not leak to a reused pooled connection");

    const crossScope = await app.connect();
    try {
      await crossScope.query("BEGIN");
      await crossScope.query("SELECT set_config('app.tenant_id',$1,true), set_config('app.business_unit_id',$2,true)", ["tenant-a", "unit-1"]);
      await assert.rejects(() => crossScope.query(
        "INSERT INTO powerops_ml_model_candidates (tenant_id,business_unit_id,candidate_id,model_version,manifest_sha256,artifact_sha256,status,candidate_data,created_by) VALUES ($1,$2,$3,$4,$5,$6,'candidate',$7::jsonb,$8)",
        ["tenant-b", "unit-1", "cross-scope-" + require("node:crypto").randomUUID(), "bad", "d".repeat(64), "e".repeat(64), JSON.stringify({}), "attacker"]
      ), /row-level security/i);
      await crossScope.query("ROLLBACK");
    } finally {
      crossScope.release();
    }

    const audit = await app.connect();
    try {
      await audit.query("BEGIN");
      await audit.query("SELECT set_config('app.tenant_id',$1,true), set_config('app.business_unit_id',$2,true)", ["tenant-a", "unit-1"]);
      await audit.query("SAVEPOINT before_update");
      await assert.rejects(() => audit.query("UPDATE powerops_ml_audit_events SET event_type='tampered' WHERE sequence=1"), /append-only/i);
      await audit.query("ROLLBACK TO SAVEPOINT before_update");
      await audit.query("SAVEPOINT before_delete");
      await assert.rejects(() => audit.query("DELETE FROM powerops_ml_audit_events WHERE sequence=1"), /append-only/i);
      await audit.query("ROLLBACK TO SAVEPOINT before_delete");
      await audit.query("COMMIT");
    } finally {
      audit.release();
    }
  } finally {
    if (app) await app.end();
    await admin.end();
  }
});

"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const adminUrl = process.env.POWEROPS_PG_ADMIN_URL;
const appUrl = process.env.POWEROPS_PG_APP_URL;

test("PostgreSQL RLS, concurrent approvals/releases, audit integrity and reconnect recovery", {
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

    app = new Pool({ connectionString: appUrl, max: 2 });
    const { createPostgresRegistry } = require("../src/ml-registry-postgres.js");
    const { createTokenAuthority } = require("../src/ml-registry-security.js");
    const principals = {
      readerA1: { tenantId: "tenant-a", businessUnitId: "unit-1", roles: ["registry-reader"] },
      readerA2: { tenantId: "tenant-a", businessUnitId: "unit-2", roles: ["registry-reader"] },
      readerB1: { tenantId: "tenant-b", businessUnitId: "unit-1", roles: ["registry-reader"] },
      creator: { tenantId: "tenant-a", businessUnitId: "unit-1", roles: ["registry-reader"] },
      riskReviewer: { tenantId: "tenant-a", businessUnitId: "unit-1", roles: ["model-risk"] },
      securityReviewer: { tenantId: "tenant-a", businessUnitId: "unit-1", roles: ["security"] },
      operationsReviewer: { tenantId: "tenant-a", businessUnitId: "unit-1", roles: ["operations-owner"] },
      releaseManager: { tenantId: "tenant-a", businessUnitId: "unit-1", roles: ["release-manager"] }
    };
    const authority = createTokenAuthority({ secret: "postgres-integration-secret-at-least-32-bytes", principals });
    let registry = createPostgresRegistry({ pool: app, tokenAuthority: authority });
    const candidateId = "pg-it-" + crypto.randomUUID();
    const candidateData = {
      candidateId, modelVersion: "integration-test", manifestSha256: "a".repeat(64),
      artifactSha256: "b".repeat(64), eligibility: { eligible: true, reasons: [] },
      artifactVerification: { verified: true, publisherKeyId: "test-publisher", verifierVersion: "integration-test" },
      createdBy: "creator", status: "candidate", approvals: []
    };

    const client = await app.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT set_config('app.tenant_id',$1,true), set_config('app.business_unit_id',$2,true)", ["tenant-a", "unit-1"]);
      await client.query(
        "INSERT INTO powerops_ml_model_candidates (tenant_id,business_unit_id,candidate_id,model_version,manifest_sha256,artifact_sha256,status,candidate_data,created_by) VALUES ($1,$2,$3,$4,$5,$6,'candidate',$7::jsonb,$8)",
        ["tenant-a", "unit-1", candidateId, candidateData.modelVersion, candidateData.manifestSha256, candidateData.artifactSha256, JSON.stringify(candidateData), "creator"]
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally { client.release(); }

    assert.equal((await registry.listCandidates(authority.issueToken("readerA1"))).length, 1);
    assert.equal((await registry.listCandidates(authority.issueToken("readerA2"))).length, 0, "same tenant, different business unit must see no rows");
    assert.equal((await registry.listCandidates(authority.issueToken("readerB1"))).length, 0, "different tenant must see no rows");
    assert.equal((await app.query("SELECT candidate_id FROM powerops_ml_model_candidates")).rowCount, 0, "transaction-local scope must not leak to a reused pooled connection");

    const crossScope = await app.connect();
    try {
      await crossScope.query("BEGIN");
      await crossScope.query("SELECT set_config('app.tenant_id',$1,true), set_config('app.business_unit_id',$2,true)", ["tenant-a", "unit-1"]);
      await assert.rejects(() => crossScope.query(
        "INSERT INTO powerops_ml_model_candidates (tenant_id,business_unit_id,candidate_id,model_version,manifest_sha256,artifact_sha256,status,candidate_data,created_by) VALUES ($1,$2,$3,$4,$5,$6,'candidate',$7::jsonb,$8)",
        ["tenant-b", "unit-1", "cross-scope-" + crypto.randomUUID(), "bad", "d".repeat(64), "e".repeat(64), JSON.stringify({}), "attacker"]
      ), /row-level security/i);
      await crossScope.query("ROLLBACK");
    } finally { crossScope.release(); }

    const approvals = await Promise.all([
      registry.recordApproval(authority.issueToken("riskReviewer"), { candidateId, approvalId: "approval-risk", role: "model-risk", reason: "Integration test approval" }),
      registry.recordApproval(authority.issueToken("securityReviewer"), { candidateId, approvalId: "approval-security", role: "security", reason: "Integration test approval" }),
      registry.recordApproval(authority.issueToken("operationsReviewer"), { candidateId, approvalId: "approval-operations", role: "operations-owner", reason: "Integration test approval" })
    ]);
    assert.equal(approvals.length, 3);
    const approvedCandidate = (await registry.listCandidates(authority.issueToken("readerA1")))[0];
    assert.equal(approvedCandidate.approvals.length, 3, "concurrent independent approvals must all be retained");

    const releaseAttempts = await Promise.allSettled([
      registry.activateRelease(authority.issueToken("releaseManager"), { candidateId, releaseId: "release-a" }),
      registry.activateRelease(authority.issueToken("releaseManager"), { candidateId, releaseId: "release-b" })
    ]);
    assert.equal(releaseAttempts.filter(x => x.status === "fulfilled").length, 1, "only one concurrent release activation may succeed");
    assert.equal(releaseAttempts.filter(x => x.status === "rejected").length, 1, "competing activation must fail closed");
    const active = await admin.query("SELECT release_id FROM powerops_ml_model_releases WHERE tenant_id='tenant-a' AND business_unit_id='unit-1' AND is_active=true");
    assert.equal(active.rowCount, 1, "database must retain exactly one active release");
    const chainBeforeRestart = await registry.verifyAuditChain(authority.issueToken("readerA1"));
    assert.equal(chainBeforeRestart.valid, true);
    assert.ok(chainBeforeRestart.eventCount >= 4);

    const audit = await app.connect();
    try {
      await audit.query("BEGIN");
      await audit.query("SELECT set_config('app.tenant_id',$1,true), set_config('app.business_unit_id',$2,true)", ["tenant-a", "unit-1"]);
      await audit.query("SAVEPOINT before_update");
      await assert.rejects(() => audit.query("UPDATE powerops_ml_audit_events SET event_type='tampered' WHERE tenant_id='tenant-a' AND business_unit_id='unit-1' AND sequence=1"), /append-only/i);
      await audit.query("ROLLBACK TO SAVEPOINT before_update");
      await audit.query("SAVEPOINT before_delete");
      await assert.rejects(() => audit.query("DELETE FROM powerops_ml_audit_events WHERE tenant_id='tenant-a' AND business_unit_id='unit-1' AND sequence=1"), /append-only/i);
      await audit.query("ROLLBACK TO SAVEPOINT before_delete");
      await audit.query("COMMIT");
    } finally { audit.release(); }

    // Simulate an application process/pool restart while retaining the PostgreSQL database.
    await app.end();
    app = new Pool({ connectionString: appUrl, max: 2 });
    registry = createPostgresRegistry({ pool: app, tokenAuthority: authority });
    const recovered = await registry.listCandidates(authority.issueToken("readerA1"));
    assert.equal(recovered.length, 1, "candidate state must survive application pool recreation");
    assert.equal(recovered[0].status, "released");
    const chainAfterRestart = await registry.verifyAuditChain(authority.issueToken("readerA1"));
    assert.deepEqual(chainAfterRestart, chainBeforeRestart, "audit chain must remain identical after reconnect/recovery");
    const activeAfterRestart = await admin.query("SELECT release_id FROM powerops_ml_model_releases WHERE tenant_id='tenant-a' AND business_unit_id='unit-1' AND is_active=true");
    assert.equal(activeAfterRestart.rowCount, 1);
    assert.equal(activeAfterRestart.rows[0].release_id, active.rows[0].release_id);
  } finally {
    if (app) await app.end();
    await admin.end();
  }
});

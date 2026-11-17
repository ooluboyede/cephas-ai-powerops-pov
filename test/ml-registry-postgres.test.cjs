"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createPostgresRegistry } = require("../src/ml-registry-postgres.js");
const { createTokenAuthority } = require("../src/ml-registry-security.js");

function fakePool(handler = () => ({ rows: [] })) {
  const calls = [];
  return {
    calls,
    async connect() {
      return {
        async query(sql, params = []) {
          calls.push({ sql, params });
          return handler(sql, params);
        },
        release() { calls.push({ sql: "RELEASE" }); }
      };
    }
  };
}
function setup() {
  const pool = fakePool(sql => sql.includes("powerops_security.current_tenant_id")
    ? { rows: [{ db_role: "powerops_test_scope", tenant_id: "tenant-x", business_unit_id: "bu-y" }] }
    : { rows: [] });
  const authority = createTokenAuthority({
    secret: "unit-test-secret-at-least-thirty-two-bytes-long",
    principals: {
      reader: { tenantId: "tenant-x", businessUnitId: "bu-y", roles: ["registry-reader", "auditor"] },
      trainer: { tenantId: "tenant-x", businessUnitId: "bu-y", roles: ["model-trainer"] }
    }
  });
  return { pool, registry: createPostgresRegistry({ poolForIdentity: () => pool, tokenAuthority: authority }), authority };
}

test("registry verifies scope using the authenticated database login, not caller-controlled GUCs", async () => {
  const { pool, registry, authority } = setup();
  assert.deepEqual(await registry.listCandidates(authority.issueToken("reader")), []);
  const check = pool.calls.find(x => x.sql.includes("powerops_security.current_tenant_id"));
  assert.ok(check);
  assert.match(check.sql, /SESSION_USER/);
  assert.ok(pool.calls.findIndex(x => x.sql === "BEGIN") < pool.calls.indexOf(check));
  assert.ok(!pool.calls.some(x => x.sql.includes("set_config('app.tenant_id'")));
  assert.ok(pool.calls.some(x => x.sql === "COMMIT"));
  assert.ok(pool.calls.some(x => x.sql === "RELEASE"));
});

test("database login scope mismatch fails closed before registry queries", async () => {
  const pool = fakePool(sql => sql.includes("powerops_security.current_tenant_id")
    ? { rows: [{ db_role: "scope-b", tenant_id: "tenant-b", business_unit_id: "unit-1" }] }
    : { rows: [] });
  const authority = createTokenAuthority({
    secret: "unit-test-secret-at-least-thirty-two-bytes-long",
    principals: { reader: { tenantId: "tenant-a", businessUnitId: "unit-1", roles: ["registry-reader"] } }
  });
  const registry = createPostgresRegistry({ poolForIdentity: () => pool, tokenAuthority: authority });
  await assert.rejects(() => registry.listCandidates(authority.issueToken("reader")), /does not match the database login identity/);
  assert.ok(!pool.calls.some(x => x.sql.includes("SELECT candidate_id")));
});

test("unauthorized role is rejected before acquiring a database connection", async () => {
  const { pool, registry, authority } = setup();
  await assert.rejects(() => registry.registerCandidate(authority.issueToken("reader"), {}), /Forbidden/);
  assert.equal(pool.calls.length, 0);
});

test("candidate registration trusts only the injected server-side artifact verifier", async () => {
  const { createDatasetManifest, createModelManifest, FEATURE_SCHEMA } = require("../src/ml-governance.js");
  const dataset = createDatasetManifest([{ id: "synthetic-1" }], { datasetId: "gate-058", sourceType: "synthetic" });
  const manifest = createModelManifest({ modelVersion: "0.5.8-test", featureVersion: "v1", featureSchema: FEATURE_SCHEMA, datasetManifest: dataset });
  const pool = fakePool(sql => {
    if (sql.includes("powerops_security.current_tenant_id")) return { rows: [{ db_role: "scope-x-y", tenant_id: "tenant-x", business_unit_id: "bu-y" }] };
    if (sql.includes("INSERT INTO powerops_ml_model_candidates")) return { rows: [{ candidate_id: "candidate-a" }] };
    return { rows: [] };
  });
  const authority = createTokenAuthority({
    secret: "unit-test-secret-at-least-thirty-two-bytes-long",
    principals: { trainer: { tenantId: "tenant-x", businessUnitId: "bu-y", roles: ["model-trainer"] } }
  });
  let verifierContext;
  const registry = createPostgresRegistry({
    poolForIdentity: () => pool, tokenAuthority: authority,
    artifactVerifier: async (receipt, context) => {
      verifierContext = { receipt, context };
      return { verified: true, artifactSha256: context.artifactSha256, publisherKeyId: "trusted-key-01", verifierVersion: "gate-0.5.4-verifier" };
    },
    promotionAssessor: async context => ({ eligible: false, reasons: ["Evaluation has not met the Gate 0.5.3 threshold"], evaluatedForTenant: context.tenantId })
  });
  const artifactSha256 = "a".repeat(64);
  const result = await registry.registerCandidate(authority.issueToken("trainer"), {
    candidateId: "candidate-a", manifest, artifactSha256,
    artifactReceipt: { signature: "opaque-signed-receipt" },
    eligibility: { eligible: true, reasons: [] }
  });
  assert.equal(result.createdBy, "trainer");
  assert.equal(result.artifactVerification.publisherKeyId, "trusted-key-01");
  assert.equal(result.eligibility.eligible, false);
  assert.equal(verifierContext.context.tenantId, "tenant-x");
  assert.equal(verifierContext.receipt.signature, "opaque-signed-receipt");
  assert.ok(pool.calls.some(x => x.sql.includes("pg_advisory_xact_lock")));
});

test("registration fails closed if no trusted artifact verifier is configured", async () => {
  const { registry, authority, pool } = setup();
  const { createDatasetManifest, createModelManifest, FEATURE_SCHEMA } = require("../src/ml-governance.js");
  const dataset = createDatasetManifest([{ id: "synthetic-2" }], { datasetId: "no-verifier", sourceType: "synthetic" });
  const manifest = createModelManifest({ modelVersion: "no-verifier", featureVersion: "v1", featureSchema: FEATURE_SCHEMA, datasetManifest: dataset });
  await assert.rejects(() => registry.registerCandidate(authority.issueToken("trainer"), {
    candidateId: "candidate-a", manifest, artifactSha256: "b".repeat(64), artifactReceipt: { signature: "caller-claimed" }
  }), /verifier is not configured/);
  assert.equal(pool.calls.length, 0);
});

test("RLS migration uses SESSION_USER-backed protected scope and least-privilege runtime grants", () => {
  const files = ["0001_powerops_ml_registry_rls.sql", "0002_powerops_session_identity_rls.sql"];
  const migration = files.map(file => fs.readFileSync(path.join(__dirname, "..", "migrations", file), "utf8")).join("\n");
  const identityMigration = fs.readFileSync(path.join(__dirname, "..", "migrations", "0002_powerops_session_identity_rls.sql"), "utf8");
  for (const table of ["powerops_ml_model_candidates", "powerops_ml_model_releases", "powerops_ml_audit_events"]) {
    assert.match(migration, new RegExp("ALTER TABLE " + table + " ENABLE ROW LEVEL SECURITY"));
    assert.match(migration, new RegExp("ALTER TABLE " + table + " FORCE ROW LEVEL SECURITY"));
    assert.match(migration, new RegExp("CREATE POLICY .* ON " + table));
  }
  assert.match(migration, /SESSION_USER::name/);
  assert.match(migration, /SECURITY DEFINER/);
  assert.match(migration, /powerops_security\.current_tenant_id\(\)/);
  assert.match(migration, /GRANT SELECT, INSERT ON powerops_ml_audit_events TO powerops_runtime/);
  assert.doesNotMatch(identityMigration, /CREATE POLICY[\s\S]*current_setting\('app\.tenant_id'/);
});

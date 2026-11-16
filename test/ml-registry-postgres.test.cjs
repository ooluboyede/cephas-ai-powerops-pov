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
  const pool = fakePool();
  const authority = createTokenAuthority({
    secret: "unit-test-secret-at-least-thirty-two-bytes-long",
    principals: {
      reader: { tenantId: "tenant-x", businessUnitId: "bu-y", roles: ["registry-reader", "auditor"] },
      trainer: { tenantId: "tenant-x", businessUnitId: "bu-y", roles: ["model-trainer"] }
    }
  });
  return { pool, registry: createPostgresRegistry({ pool, tokenAuthority: authority }), authority };
}

test("registry transactions set authenticated tenant and business-unit context before queries", async () => {
  const { pool, registry, authority } = setup();
  const token = authority.issueToken("reader");
  assert.deepEqual(await registry.listCandidates(token), []);
  const context = pool.calls.find(x => x.sql.includes("set_config('app.tenant_id'"));
  assert.deepEqual(context.params, ["tenant-x", "bu-y"]);
  assert.ok(pool.calls.findIndex(x => x.sql === "BEGIN") < pool.calls.indexOf(context));
  assert.ok(pool.calls.some(x => x.sql === "COMMIT"));
  assert.ok(pool.calls.some(x => x.sql === "RELEASE"));
});

test("unauthorized role is rejected before acquiring a database connection", async () => {
  const { pool, registry, authority } = setup();
  const token = authority.issueToken("reader");
  await assert.rejects(() => registry.registerCandidate(token, {}), /Forbidden/);
  assert.equal(pool.calls.length, 0);
});


test("candidate registration trusts only the injected server-side artifact verifier", async () => {
  const { createDatasetManifest, createModelManifest, FEATURE_SCHEMA } = require("../src/ml-governance.js");
  const dataset = createDatasetManifest([{ id: "synthetic-1" }], { datasetId: "gate-056", sourceType: "synthetic" });
  const manifest = createModelManifest({ modelVersion: "0.5.6-test", featureVersion: "v1", featureSchema: FEATURE_SCHEMA, datasetManifest: dataset });
  const pool = fakePool(sql => {
    if (sql.includes("INSERT INTO powerops_ml_model_candidates")) return { rows: [{ candidate_id: "candidate-a" }] };
    return { rows: [] };
  });
  const authority = createTokenAuthority({
    secret: "unit-test-secret-at-least-thirty-two-bytes-long",
    principals: { trainer: { tenantId: "tenant-x", businessUnitId: "bu-y", roles: ["model-trainer"] } }
  });
  let verifierContext;
  const registry = createPostgresRegistry({
    pool, tokenAuthority: authority,
    artifactVerifier: async (receipt, context) => {
      verifierContext = { receipt, context };
      return { verified: true, artifactSha256: context.artifactSha256, publisherKeyId: "trusted-key-01", verifierVersion: "gate-0.5.4-verifier" };
    }
  });
  const artifactSha256 = "a".repeat(64);
  const result = await registry.registerCandidate(authority.issueToken("trainer"), {
    candidateId: "candidate-a", createdBy: "untrusted-client-value", manifest,
    artifactSha256, artifactReceipt: { signature: "opaque-signed-receipt" },
    eligibility: { eligible: false, reasons: ["not yet evaluated"] }
  });
  assert.equal(result.createdBy, "trainer");
  assert.equal(result.artifactVerification.publisherKeyId, "trusted-key-01");
  assert.equal(verifierContext.context.tenantId, "tenant-x");
  assert.equal(verifierContext.receipt.signature, "opaque-signed-receipt");
  assert.ok(pool.calls.some(x => x.sql.includes("pg_advisory_xact_lock")));
});

test("registration fails closed if no trusted artifact verifier is configured", async () => {
  const { registry, authority, pool } = setup();
  const token = authority.issueToken("trainer");
  await assert.rejects(() => registry.registerCandidate(token, {
    candidateId: "candidate-a", manifest: { manifestSha256: "a".repeat(64) },
    artifactSha256: "b".repeat(64), artifactReceipt: { signature: "caller-claimed" }
  }), /verifier is not configured/);
  assert.equal(pool.calls.length, 0);
});

test("PostgreSQL migration enables and forces RLS for all registry tables", () => {
  const migration = fs.readFileSync(path.join(__dirname, "..", "migrations", "0001_powerops_ml_registry_rls.sql"), "utf8");
  for (const table of ["powerops_ml_model_candidates", "powerops_ml_model_releases", "powerops_ml_audit_events"]) {
    assert.match(migration, new RegExp("ALTER TABLE " + table + " ENABLE ROW LEVEL SECURITY"));
    assert.match(migration, new RegExp("ALTER TABLE " + table + " FORCE ROW LEVEL SECURITY"));
    assert.match(migration, new RegExp("CREATE POLICY .* ON " + table));
  }
  assert.match(migration, /current_setting\('app\.tenant_id', true\)/);
  assert.match(migration, /current_setting\('app\.business_unit_id', true\)/);
});

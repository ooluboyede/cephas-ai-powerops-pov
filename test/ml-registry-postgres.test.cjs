const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createPostgresRegistry } = require("../src/ml-registry-postgres.js");
const { createTokenAuthority } = require("../src/ml-registry-security.js");

function fakePool() {
  const calls = [];
  return {
    calls,
    async connect() {
      return {
        async query(sql, params = []) {
          calls.push({ sql, params });
          if (sql.includes("SELECT candidate_id, candidate_data")) return { rows: [] };
          if (sql.includes("SELECT sequence, event_type")) return { rows: [] };
          return { rows: [] };
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

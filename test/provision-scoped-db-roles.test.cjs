"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { provisionScopedDatabaseRoles, createScramVerifier } = require("../scripts/provision-scoped-db-roles.cjs");

test("SCRAM verifier is validly shaped and does not disclose the supplied password", () => {
  const password = crypto.randomBytes(32).toString("base64url");
  const verifier = createScramVerifier(password);
  assert.match(verifier, /^SCRAM-SHA-256\$4096:[A-Za-z0-9+/]{20,24}={0,2}\$[A-Za-z0-9+/]{43}={1}:[A-Za-z0-9+/]{43}={1}$/);
  assert.equal(verifier.includes(password), false);
});

test("role provisioning sends a SCRAM verifier, never the plaintext password, to PostgreSQL", async () => {
  const password = crypto.randomBytes(32).toString("base64url");
  const statements = [];
  const admin = {
    async query(sql, params) {
      statements.push({ sql, params });
      if (sql.startsWith("SELECT db_role")) {
        return { rowCount: 1, rows: [{ role_name: "powerops_app_a1", tenant_id: "tenant-a", business_unit_id: "bu-1", enabled: true }] };
      }
      if (sql.startsWith("SELECT 1 FROM pg_roles")) return { rowCount: 0, rows: [] };
      return { rowCount: 0, rows: [] };
    }
  };

  const provisioned = await provisionScopedDatabaseRoles({
    admin,
    credentialForRole: async role => {
      assert.equal(role, "powerops_app_a1");
      return password;
    }
  });

  assert.equal(provisioned.length, 1);
  const roleStatement = statements.find(entry => entry.sql.startsWith("CREATE ROLE"));
  assert.ok(roleStatement);
  assert.equal(roleStatement.sql.includes(password), false);
  assert.match(roleStatement.sql, /PASSWORD 'SCRAM-SHA-256\$4096:/);
  assert.equal(statements.some(entry => entry.sql.includes(password)), false);
});

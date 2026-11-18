"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const migration = fs.readFileSync(
  path.join(__dirname, "..", "migrations", "0005_principal_bound_approval_authority.sql"),
  "utf8"
);

test("approval principal is derived only from protected SESSION_USER mapping", () => {
  assert.match(migration, /ADD COLUMN IF NOT EXISTS principal_id text/);
  assert.match(migration, /WHERE db_role = SESSION_USER::name/);
  assert.match(migration, /FUNCTION powerops_security\.current_principal_id\(\)/);
  const functionBody = migration.match(/CREATE OR REPLACE FUNCTION powerops_ml_record_principal_approval\([\s\S]*?\$body\$;/)?.[0];
  assert.ok(functionBody, "principal approval function must exist");
  assert.match(functionBody, /powerops_security\.current_principal_id\(\)/);
  assert.doesNotMatch(functionBody, /p_principal_id|p_tenant_id|p_business_unit_id/);
});

test("shared runtime cannot directly insert approvals", () => {
  assert.match(migration, /REVOKE INSERT ON powerops_ml_model_approvals FROM PUBLIC, powerops_runtime, powerops_approval_runtime/);
  assert.match(migration, /GRANT EXECUTE ON FUNCTION powerops_ml_record_principal_approval\(text,text,text,text,text\)[\s\S]*TO powerops_approval_runtime/);
  assert.doesNotMatch(migration, /GRANT INSERT ON powerops_ml_model_approvals TO powerops_runtime/);
});

test("grant history uses immutable grant IDs and one-way revocation", () => {
  assert.match(migration, /ADD COLUMN IF NOT EXISTS grant_id uuid/);
  assert.match(migration, /PRIMARY KEY \(grant_id\)/);
  assert.match(migration, /WHERE revoked_at IS NULL/);
  assert.match(migration, /REFERENCES powerops_ml_principal_role_assignments \(grant_id\)/);
  assert.match(migration, /Role grant history is immutable; only one-way revocation is permitted/);
  assert.match(migration, /OLD\.revoked_at IS NOT NULL/);
});

test("database approval function enforces active grant, candidate scope and self-approval denial", () => {
  const functionBody = migration.match(/CREATE OR REPLACE FUNCTION powerops_ml_record_principal_approval\([\s\S]*?\$body\$;/)?.[0] || "";
  assert.match(functionBody, /revoked_at IS NULL/);
  assert.match(functionBody, /FOR SHARE/);
  assert.match(functionBody, /FOR UPDATE/);
  assert.match(functionBody, /v_creator = v_principal_id/);
  assert.match(functionBody, /INSERT INTO public\.powerops_ml_model_approvals/);
  assert.match(functionBody, /IF p_decision = 'reject'/);
});

"use strict";
const test=require("node:test");
const assert=require("node:assert/strict");
const fs=require("node:fs");
const path=require("node:path");
const sql=fs.readFileSync(path.join(__dirname,"..","migrations","0004_durable_model_approvals.sql"),"utf8");

test("Gate 0.6.3 creates tenant and business-unit scoped durable role assignments",()=>{
 assert.match(sql,/CREATE TABLE IF NOT EXISTS powerops_ml_principal_role_assignments/);
 assert.match(sql,/PRIMARY KEY\s*\(tenant_id,business_unit_id,principal_id,role_name\)/);
 assert.match(sql,/revoked_at timestamptz/);
 assert.match(sql,/powerops_security\.current_tenant_id\(\)/);
 assert.match(sql,/powerops_security\.current_business_unit_id\(\)/);
 assert.match(sql,/ENABLE ROW LEVEL SECURITY/);
 assert.match(sql,/FORCE ROW LEVEL SECURITY/);
});

test("Gate 0.6.3 approvals bind to an existing candidate and a matching scoped role assignment",()=>{
 assert.match(sql,/CREATE TABLE IF NOT EXISTS powerops_ml_model_approvals/);
 assert.match(sql,/FOREIGN KEY\s*\(tenant_id,business_unit_id,candidate_id\)/);
 assert.match(sql,/REFERENCES powerops_ml_model_candidates/);
 assert.match(sql,/FOREIGN KEY\s*\(tenant_id,business_unit_id,principal_id,role_name\)/);
 assert.match(sql,/REFERENCES powerops_ml_principal_role_assignments/);
 assert.match(sql,/UNIQUE\s*\(tenant_id,business_unit_id,candidate_id,role_name\)/);
 assert.match(sql,/UNIQUE\s*\(tenant_id,business_unit_id,candidate_id,principal_id\)/);
});

test("Gate 0.6.3 runtime privileges separate role administration from approval recording",()=>{
 assert.match(sql,/GRANT SELECT ON powerops_ml_principal_role_assignments TO powerops_runtime/);
 assert.match(sql,/GRANT SELECT,INSERT ON powerops_ml_model_approvals TO powerops_runtime/);
 assert.doesNotMatch(sql,/GRANT INSERT[^;]*powerops_ml_principal_role_assignments/i);
 assert.match(sql,/ALTER TABLE powerops_ml_principal_role_assignments OWNER TO powerops_registry_owner/);
 assert.match(sql,/ALTER TABLE powerops_ml_model_approvals OWNER TO powerops_registry_owner/);
});

test("Gate 0.6.3 prevents mutation or deletion of recorded approval decisions",()=>{
 assert.match(sql,/CREATE OR REPLACE FUNCTION powerops_ml_reject_approval_mutation/);
 assert.match(sql,/BEFORE UPDATE OR DELETE ON powerops_ml_model_approvals/);
 assert.match(sql,/ERRCODE='42501'/);
});

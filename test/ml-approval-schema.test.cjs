"use strict";
const test=require("node:test");
const assert=require("node:assert/strict");
const fs=require("node:fs");
const path=require("node:path");
const sql=fs.readFileSync(path.join(__dirname,"..","migrations","0004_durable_model_approvals.sql"),"utf8");
const compact=sql.replace(/\s+/g," ").toLowerCase();

test("Gate 0.6.3 creates tenant and business-unit scoped durable role assignments",()=>{
 assert.ok(compact.includes("create table if not exists powerops_ml_principal_role_assignments"));
 assert.ok(compact.includes("primary key (tenant_id,business_unit_id,principal_id,role_name)"));
 assert.ok(compact.includes("revoked_at timestamptz"));
 assert.ok(compact.includes("powerops_security.current_tenant_id()"));
 assert.ok(compact.includes("powerops_security.current_business_unit_id()"));
 assert.ok(compact.includes("enable row level security"));
 assert.ok(compact.includes("force row level security"));
});

test("Gate 0.6.3 approvals bind to an existing candidate and a matching scoped role assignment",()=>{
 assert.ok(compact.includes("create table if not exists powerops_ml_model_approvals"));
 assert.ok(compact.includes("foreign key (tenant_id,business_unit_id,candidate_id)"));
 assert.ok(compact.includes("references powerops_ml_model_candidates"));
 assert.ok(compact.includes("foreign key (tenant_id,business_unit_id,principal_id,role_name)"));
 assert.ok(compact.includes("references powerops_ml_principal_role_assignments"));
 assert.ok(compact.includes("primary key (tenant_id,business_unit_id,candidate_id,role_name)"));
 assert.ok(compact.includes("unique (tenant_id,business_unit_id,candidate_id,principal_id)"));
});

test("Gate 0.6.3 runtime privileges separate role administration from approval recording",()=>{
 assert.ok(compact.includes("grant select on powerops_ml_principal_role_assignments to powerops_runtime"));
 assert.ok(compact.includes("grant select,insert on powerops_ml_model_approvals to powerops_runtime"));
 assert.doesNotMatch(sql,/GRANT INSERT[^;]*powerops_ml_principal_role_assignments/i);
 assert.ok(compact.includes("alter table powerops_ml_principal_role_assignments owner to powerops_registry_owner"));
 assert.ok(compact.includes("alter table powerops_ml_model_approvals owner to powerops_registry_owner"));
});

test("Gate 0.6.3 prevents mutation or deletion of recorded approval decisions",()=>{
 assert.ok(compact.includes("create or replace function powerops_ml_reject_approval_mutation"));
 assert.ok(compact.includes("before update or delete on powerops_ml_model_approvals"));
 assert.ok(compact.includes("errcode='42501'"));
});

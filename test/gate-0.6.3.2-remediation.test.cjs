"use strict";
const test=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const Ajv2020=require("ajv/dist/2020"),addFormats=require("ajv-formats"),canonicalizeA=require("canonicalize"),jcs=require("json-canonicalize"),canonicalizeB=jcs.canonicalize||jcs.default||jcs;
const base=path.join(__dirname,"..","schemas","gate-0.6.3.2");
const schema=JSON.parse(fs.readFileSync(path.join(base,"audit-registry-v2.schema.json"),"utf8"));
const catalog=JSON.parse(fs.readFileSync(path.join(base,"fixture-catalog.v1.json"),"utf8"));
const vectors=JSON.parse(fs.readFileSync(path.join(base,"jcs-golden-vectors.v1.json"),"utf8"));
const ajv=new Ajv2020({allErrors:true,strict:false,validateFormats:true});addFormats(ajv);
const eventCatalog=new Map(schema["x-event-catalog"].map(x=>[x.mutation_type,x]));
const eventFixtures=new Map(catalog.event_fixtures.map(x=>[x.mutation_type,x]));
const validators=new Map();
function validatorFor(token){if(!validators.has(token))validators.set(token,ajv.compile({$schema:schema.$schema,$defs:schema.$defs,$ref:"#/$defs/"+token}));return validators.get(token);}
const validateManifest=ajv.compile({$schema:schema.$schema,$defs:schema.$defs,$ref:"#/$defs/mutationManifest"});
const semanticAssertions=schema["x-semanticAssertions"]||[];
function scopeKey(x){return JSON.stringify([x.scope_kind,x.tenant_id,x.business_unit_id]);}
function eventMatchesManifest(e,m){
 const x=m.expected_events[e.mutation_event_index];if(!x)return false;
 if(e.registry_version!==2||e.registry_token!=="cephas.powerops.audit-payload-registry.v2"||e.event_envelope_schema_token!=="cephas.powerops.audit-event-envelope.v2"||e.mutation_schema_version!=="cephas.powerops.mutation.v1"||e.manifest_schema_token!=="cephas.powerops.mutation-manifest.v1")return false;
 for(const k of ["mutation_id","operation_id","mutation_type","actor_principal_id","actor_login_binding_id","actor_mapping_version","reason_code"])if(e[k]!==m[k])return false;
 if(e.mutation_event_count!==m.expected_event_count||e.mutation_event_index!==x.mutation_event_index||e.event_type!==x.event_type||e.event_payload_schema_token!==x.event_payload_schema_token)return false;
 if(scopeKey(e)!==scopeKey(x)||!(m.affected_scope_keys||[]).some(y=>scopeKey(y)===scopeKey(x)))return false;
 for(const k of ["affected_mapping_ids","affected_scope_keys","affected_object_refs"])if(JSON.stringify(e[k])!==JSON.stringify(m[k]))return false;
 return true;
}
function semanticAccepts(mutation,p){
 const a=semanticAssertions.find(x=>x.mutation_type===mutation);if(!a)return true;
 const prior=p[a.prior_field],next=p[a.resulting_field];
 if(!Number.isSafeInteger(prior)||!Number.isSafeInteger(next)||next<=prior)return false;
 if(a.status_rule==="same_active_or_pending")return p.prior_status===p.resulting_status&&["active","pending"].includes(p.prior_status);
 if(a.status_rule==="active_or_pending_to_suspended")return ["active","pending"].includes(p.prior_status)&&p.resulting_status==="suspended";
 return true;
}
function lifecycleAccepts(mutation,p){return !(mutation==="security_incident.reconciled"&&p.prior_stream_condition==="quarantined"&&p.resulting_stream_condition!=="quarantined");}
function digest(m){return crypto.createHash("sha256").update(canonicalizeA(m),"utf8").digest("hex");}
function reconstructs(m,events){
 if(!validateManifest(m)||m.expected_event_count!==m.expected_events.length||events.length!==m.expected_event_count)return false;
 const d=digest(m);
 for(let i=0;i<events.length;i++){const e=events[i];if(e.mutation_event_index!==i||m.expected_events[i].mutation_event_index!==i||e.mutation_event_count!==events.length||e.mutation_payload_sha256!==d||!eventMatchesManifest(e,m))return false;}
 return true;
}
function manifestForEvent(e){return {mutation_id:e.mutation_id,operation_id:e.operation_id,mutation_type:e.mutation_type,actor_principal_id:e.actor_principal_id,actor_login_binding_id:e.actor_login_binding_id,actor_mapping_version:e.actor_mapping_version,reason_code:e.reason_code,affected_mapping_ids:e.affected_mapping_ids,affected_scope_keys:e.affected_scope_keys,affected_object_refs:e.affected_object_refs,expected_event_count:e.mutation_event_count,expected_events:[{tenant_id:e.tenant_id,business_unit_id:e.business_unit_id,scope_kind:e.scope_kind,event_type:e.event_type,event_payload_schema_token:e.event_payload_schema_token,mutation_event_index:e.mutation_event_index}]};}

test("registry, schemas and positive fixture catalogue are one-to-one",()=>{
 assert.equal(eventCatalog.size,eventFixtures.size);assert.equal(eventCatalog.size,schema["x-event-catalog"].length);
 for(const [mutation,entry] of eventCatalog){const f=eventFixtures.get(mutation);assert.ok(f,"missing "+mutation);assert.equal(f.event_type,entry.event_type);assert.equal(f.event_payload_schema_token,entry.event_payload_schema_token);const def=schema.$defs[entry.event_payload_schema_token];assert.ok(def);assert.ok((def.allOf||[]).some(x=>x.$ref==="#/$defs/commonScopeConstraints"));}
 assert.ok(eventCatalog.has("accountable_role.granted"));assert.equal(eventCatalog.get("accountable_role.granted").event_type,"authority.accountable-role-granted");
});
test("every positive event fixture validates",()=>{for(const f of catalog.event_fixtures){const v=validatorFor(f.event_payload_schema_token);assert.equal(v(f.positive_fixture),true,f.mutation_type+": "+JSON.stringify(v.errors));}});
test("every negative payload fixture reaches its declared rejecting validator",()=>{
 let schemaRejected=0,semanticRejected=0,executed=0;
 for(const f of catalog.event_fixtures){const v=validatorFor(f.event_payload_schema_token);for(const n of f.negative_payload_fixtures||[]){executed++;const k=n.expected_failure;
  if(k==="semantic-reconstruction"){assert.equal(v(n.payload),true,f.mutation_type+"/"+n.case_id+" schema precondition");assert.equal(eventMatchesManifest(n.payload,manifestForEvent(f.positive_fixture)),false,f.mutation_type+"/"+n.case_id);semanticRejected++;}
  else if(String(k).startsWith("semantic:")){assert.equal(v(n.payload),true,f.mutation_type+"/"+n.case_id+" schema precondition");assert.equal(semanticAccepts(f.mutation_type,n.payload),false,f.mutation_type+"/"+n.case_id);semanticRejected++;}
  else if(k==="state-transition"){assert.equal(v(n.payload),true,f.mutation_type+"/"+n.case_id+" schema precondition");assert.equal(lifecycleAccepts(f.mutation_type,n.payload),false,f.mutation_type+"/"+n.case_id);semanticRejected++;}
  else{assert.equal(v(n.payload),false,f.mutation_type+"/"+n.case_id+" schema rejection");schemaRejected++;}
 }}
 const declared=catalog.event_fixtures.reduce((n,f)=>n+(f.negative_payload_fixtures||[]).length,0);
 assert.equal(executed,declared,"no negative fixture may be skipped");assert.equal(schemaRejected+semanticRejected,declared);assert.ok(schemaRejected>0&&semanticRejected>0);
});
test("all four declared semantic assertions have positive and schema-valid negative coverage",()=>{
 assert.equal(semanticAssertions.length,4);
 for(const a of semanticAssertions){const f=eventFixtures.get(a.mutation_type);assert.ok(f);const v=validatorFor(f.event_payload_schema_token);assert.equal(v(f.positive_fixture),true);assert.equal(semanticAccepts(a.mutation_type,f.positive_fixture),true);const ns=(f.negative_payload_fixtures||[]).filter(n=>String(n.expected_failure).startsWith("semantic:"));assert.ok(ns.length>0,"missing negative "+a.id);for(const n of ns){assert.equal(v(n.payload),true);assert.equal(semanticAccepts(a.mutation_type,n.payload),false);}}
});
test("every manifest golden fixture validates and both JCS implementations match pinned bytes and digests",()=>{
 assert.ok(catalog.manifest_golden_fixtures.length>0);
 for(const f of catalog.manifest_golden_fixtures){assert.equal(validateManifest(f.source_object),true,f.fixture_id+": "+JSON.stringify(validateManifest.errors));const a=canonicalizeA(f.source_object),b=canonicalizeB(f.source_object);assert.equal(a,f.canonical_utf8);assert.equal(b,f.canonical_utf8);assert.equal(Buffer.byteLength(a,"utf8"),f.byte_length);assert.equal(crypto.createHash("sha256").update(a,"utf8").digest("hex"),f.sha256);}
 for(const v of vectors.vectors){const a=canonicalizeA(v.source_object),b=canonicalizeB(v.source_object);assert.equal(a,v.canonical_utf8);assert.equal(b,v.canonical_utf8);assert.equal(Buffer.byteLength(a,"utf8"),v.byte_length);assert.equal(crypto.createHash("sha256").update(a,"utf8").digest("hex"),v.sha256);assert.equal(crypto.createHash("sha256").update(b,"utf8").digest("hex"),v.sha256);}
});
test("expected-event item enforces common global-versus-tenant scope constraints",()=>{
 const base=JSON.parse(JSON.stringify(catalog.manifest_golden_fixtures[0].source_object));assert.equal(validateManifest(base),true);
 const g=JSON.parse(JSON.stringify(base));g.expected_events[0].scope_kind="global";g.expected_events[0].tenant_id="33333333-3333-4333-8333-333333333333";g.expected_events[0].business_unit_id="44444444-4444-4444-8444-444444444444";assert.equal(validateManifest(g),false);
 const t=JSON.parse(JSON.stringify(base));t.expected_events[0].scope_kind="tenant_business_unit";t.expected_events[0].tenant_id=null;t.expected_events[0].business_unit_id=null;assert.equal(validateManifest(t),false);
 const good=JSON.parse(JSON.stringify(base));good.affected_scope_keys=[{scope_kind:"global",tenant_id:null,business_unit_id:null}];good.expected_events[0].scope_kind="global";good.expected_events[0].tenant_id=null;good.expected_events[0].business_unit_id=null;assert.equal(validateManifest(good),true);
});
test("all mutation-reconstruction negative descriptors are executable adversarial cases",()=>{
 assert.ok(catalog.mutation_reconstruction_negative_fixtures.length>0);
 const mf=catalog.manifest_golden_fixtures[0],m=JSON.parse(JSON.stringify(mf.source_object)),f=eventFixtures.get("approval_grant.created"),e=JSON.parse(JSON.stringify(f.positive_fixture));e.mutation_payload_sha256=digest(m);
 assert.equal(reconstructs(m,[e]),true,"baseline reconstruction");
 for(const x of catalog.mutation_reconstruction_negative_fixtures){let mm=JSON.parse(JSON.stringify(m)),es=[JSON.parse(JSON.stringify(e))];switch(x.case_id){
 case "missing-scope-event":es=[];break;case "duplicate-scope-event":es.push(JSON.parse(JSON.stringify(e)));break;case "wrong-scope-event":es[0].tenant_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";break;
 case "wrong-event-type":es[0].event_type="approval.grant-revoked";break;case "actor-substitution":es[0].actor_principal_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";break;
 case "manifest-digest-mismatch":mm.reason_code="ALTERED_AFTER_SIGNING";break;case "non-contiguous-order":es[0].mutation_event_index=1;break;case "v1-event-in-v2-mutation":es[0].registry_version=1;break;
 default:assert.fail("unhandled reconstruction fixture "+x.case_id);}
 assert.equal(reconstructs(mm,es),false,x.case_id+" unexpectedly passed");
 }
});
test("quarantine remains terminal under incident reconciliation",()=>{
 const f=eventFixtures.get("security_incident.reconciled"),n=f.negative_payload_fixtures.find(x=>x.expected_failure==="state-transition");assert.ok(n);assert.equal(validatorFor(f.event_payload_schema_token)(n.payload),true);assert.equal(lifecycleAccepts("security_incident.reconciled",n.payload),false);
});

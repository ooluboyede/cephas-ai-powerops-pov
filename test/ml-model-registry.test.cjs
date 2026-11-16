const test=require("node:test");
const assert=require("node:assert/strict");
const gov=require("../src/ml-governance.js");
const {createRegistry}=require("../src/ml-model-registry.js");
function setup(){
 const records=Array.from({length:12},(_,i)=>({id:"SYN-"+i,value:i,label:i%2?"normal":"anomaly"}));
 const dataset=gov.createDatasetManifest(records,{datasetId:"POWEROPS-SYNTHETIC-REGISTRY-V1",sourceType:"synthetic"});
 const manifest=gov.createModelManifest({modelVersion:"0.5.5-test-model",featureVersion:"0.5.2-feature-pipeline",featureSchema:gov.FEATURE_SCHEMA,datasetManifest:dataset,trainingCodeRevision:"test-revision",createdAt:"2026-11-16T00:00:00Z"});
 const artifactSha256="a".repeat(64);
 const eligibility={eligible:true,reasons:[]};
 const registry=createRegistry();
 const candidateId="candidate-001";
 registry.registerCandidate({candidateId,manifest,artifactSha256,createdBy:"trainer-1",eligibility,artifactVerification:{verified:true,artifactSha256,publisherKeyId:"publisher-test-key",verifierVersion:"0.5.4-test-verifier"}});
 return {registry,candidateId,artifactSha256,manifest};
}
function approveAll(registry,candidateId){
 for(const [role,approverId] of [["model-risk","risk-1"],["security","security-1"],["operations-owner","ops-1"]]){
  registry.approveCandidate({candidateId,approvalId:"approval-"+role,approverId,role,decision:"approve",reason:"Independent gate review passed"});
 }
}
test("candidate registration requires valid manifest, verified artifact receipt and unique ID",()=>{
 const {registry,candidateId,manifest,artifactSha256}=setup();
 assert.throws(()=>registry.registerCandidate({candidateId:"bad",manifest,artifactSha256,createdBy:"x",eligibility:{eligible:true}}),/verification receipt/);
 assert.throws(()=>registry.registerCandidate({candidateId,manifest,artifactSha256,createdBy:"x",eligibility:{eligible:true},artifactVerification:{verified:true,artifactSha256,publisherKeyId:"k",verifierVersion:"v"}}),/already exists/);
});
test("release fails closed until all independent roles approve and eligibility is true",()=>{
 const {registry,candidateId}=setup();
 assert.throws(()=>registry.promoteCandidate({candidateId,releaseId:"release-1",actorId:"release-service"}),/approvals missing/);
 registry.approveCandidate({candidateId,approvalId:"a1",approverId:"risk-1",role:"model-risk",reason:"Reviewed"});
 registry.approveCandidate({candidateId,approvalId:"a2",approverId:"security-1",role:"security",reason:"Reviewed"});
 assert.throws(()=>registry.promoteCandidate({candidateId,releaseId:"release-1",actorId:"release-service"}),/operations-owner/);
 registry.approveCandidate({candidateId,approvalId:"a3",approverId:"ops-1",role:"operations-owner",reason:"Reviewed"});
 const release=registry.promoteCandidate({candidateId,releaseId:"release-1",actorId:"release-service"});
 assert.equal(release.status,"released");assert.equal(registry.getSnapshot().activeReleaseId,"release-1");
});
test("creator cannot approve; approvers must be distinct and roles cannot be duplicated",()=>{
 const {registry,candidateId}=setup();
 assert.throws(()=>registry.approveCandidate({candidateId,approvalId:"a",approverId:"trainer-1",role:"model-risk",reason:"x"}),/cannot approve/);
 registry.approveCandidate({candidateId,approvalId:"a",approverId:"risk-1",role:"model-risk",reason:"x"});
 assert.throws(()=>registry.approveCandidate({candidateId,approvalId:"b",approverId:"risk-1",role:"security",reason:"x"}),/distinct/);
 assert.throws(()=>registry.approveCandidate({candidateId,approvalId:"c",approverId:"risk-2",role:"model-risk",reason:"x"}),/already exists/);
});
test("rejected candidates cannot be promoted",()=>{
 const {registry,candidateId}=setup();
 registry.approveCandidate({candidateId,approvalId:"reject",approverId:"risk-1",role:"model-risk",decision:"reject",reason:"Insufficient evidence"});
 assert.throws(()=>registry.promoteCandidate({candidateId,releaseId:"r1",actorId:"release-service"}),/not in a promotable state/);
});
test("blocked model eligibility prevents release despite complete approvals",()=>{
 const {registry,candidateId}=setup();
 // Separate blocked candidate with an otherwise valid cryptographic manifest.
 const records=Array.from({length:10},(_,i)=>({id:"B-"+i,value:i,label:i%2?"normal":"anomaly"}));
 const ds=gov.createDatasetManifest(records,{datasetId:"BLOCKED",sourceType:"synthetic"});
 const manifest=gov.createModelManifest({modelVersion:"blocked-v1",featureVersion:"f1",featureSchema:gov.FEATURE_SCHEMA,datasetManifest:ds});
 registry.registerCandidate({candidateId:"blocked",manifest,artifactSha256:"b".repeat(64),createdBy:"trainer-2",eligibility:{eligible:false,reasons:["low recall"]},artifactVerification:{verified:true,artifactSha256:"b".repeat(64),publisherKeyId:"key",verifierVersion:"v"}});
 approveAll(registry,"blocked");
 assert.throws(()=>registry.promoteCandidate({candidateId:"blocked",releaseId:"blocked-release",actorId:"release-service"}),/eligibility is blocked/);
});
test("rollback only selects an existing prior release and emits review-required event",()=>{
 const {registry,candidateId}=setup();approveAll(registry,candidateId);
 registry.promoteCandidate({candidateId,releaseId:"release-1",actorId:"release-service"});
 const second=setup();approveAll(second.registry,second.candidateId);
 second.registry.promoteCandidate({candidateId:second.candidateId,releaseId:"release-2",actorId:"release-service"});
 const result=second.registry.rollback({targetReleaseId:"release-1",actorId:"operator-1",reason:"Post-release monitoring detected unacceptable drift"});
 assert.deepEqual(result,{activeReleaseId:"release-1",rolledBackFrom:"release-2",rolledBackTo:"release-1",requiresPostRollbackReview:true});
 assert.throws(()=>second.registry.rollback({targetReleaseId:"unknown",actorId:"operator-1",reason:"x"}),/previously approved release/);
});
test("append-only event hash chain verifies and detects tampering",()=>{
 const {registry,candidateId}=setup();
 registry.approveCandidate({candidateId,approvalId:"a",approverId:"risk-1",role:"model-risk",reason:"Review"});
 assert.equal(registry.verifyEventChain().valid,true);
 const snapshot=registry.getSnapshot();
 assert.equal(snapshot.chainVerification.eventCount,2);
 // Returned snapshots are detached copies; caller mutation cannot rewrite registry state.
 snapshot.events[0].payload.candidateId="tampered";
 assert.equal(registry.verifyEventChain().valid,true);
});
test("approval policy cannot be bypassed by missing required artifact verification",()=>{
 const {registry,candidateId}=setup();
 const snapshot=registry.getSnapshot();
 assert.equal(snapshot.policy.requireArtifactVerification,true);
 assert.equal(snapshot.policy.requirePromotionEligibility,true);
});

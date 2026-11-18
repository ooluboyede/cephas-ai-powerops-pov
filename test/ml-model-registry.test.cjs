const test=require("node:test");
const assert=require("node:assert/strict");
const crypto=require("node:crypto");
const gov=require("../src/ml-governance.js");
const {signModelArtifact}=require("../src/ml-training-pipeline.js");
const {canonical}=gov;
const {createTrustedArtifactVerifier}=require("../src/trusted-artifact-verifier.js");
const {createRegistry}=require("../src/ml-model-registry.js");

function makeCandidate(registry,keyPair,{candidateId="candidate-001",modelVersion="0.6.1-test-model",createdBy="trainer-1",eligible=true,datasetId="POWEROPS-SYNTHETIC-REGISTRY-V1"}={}){
 const records=Array.from({length:12},(_,i)=>({id:datasetId+"-"+i,label:i%2?"normal":"anomaly"}));
 const dataset=gov.createDatasetManifest(records,{datasetId,sourceType:"synthetic"});
 const model={schemaVersion:"1.0",modelVersion,algorithm:"standardized-logistic-regression",featureSchema:gov.FEATURE_SCHEMA.slice(),datasetSha256:dataset.contentSha256,weights:[0,0,0,0,0,0],bias:0,threshold:0.5};
 const manifest=gov.createModelManifest({modelVersion,featureVersion:"0.5.2-feature-pipeline",algorithm:model.algorithm,featureSchema:model.featureSchema,datasetManifest:dataset,trainingCodeRevision:"test-revision",createdAt:"2026-11-18T00:00:00Z"});
 const artifactBytes=Buffer.from(canonical(model),"utf8");
 const artifactSignature=signModelArtifact(artifactBytes,keyPair.privateKey);
 const result=registry.registerCandidate({candidateId,manifest,artifactBytes,artifactSignature,publisherKeyId:"publisher-test-key",createdBy,eligibility:{eligible,reasons:eligible?[]:["synthetic test block"]}});
 return {result,candidateId,artifactBytes,artifactSignature,manifest,model,dataset};
}
function setup(){
 const keyPair=crypto.generateKeyPairSync("ed25519");
 const artifactVerifier=createTrustedArtifactVerifier({trustedPublishers:{"publisher-test-key":keyPair.publicKey}});
 const registry=createRegistry({artifactVerifier});
 const created=makeCandidate(registry,keyPair);
 return {registry,keyPair,artifactVerifier,...created};
}
function approveAll(registry,candidateId){
 for(const [role,approverId] of [["model-risk","risk-1"],["security","security-1"],["operations-owner","ops-1"]]){
  registry.approveCandidate({candidateId,approvalId:"approval-"+role,approverId,role,decision:"approve",reason:"Independent gate review passed"});
 }
}

test("registry refuses to start without a trusted verifier when artifact verification is mandatory",()=>{
 assert.throws(()=>createRegistry(),/Trusted artifact verifier must be injected/);
});
test("candidate registration verifies raw signed bytes inside the registry and stores its own receipt",()=>{
 const {registry,keyPair,candidateId,result,artifactBytes}=setup();
 assert.equal(result.artifactVerification.verified,true);
 assert.equal(result.artifactVerification.artifactSha256,crypto.createHash("sha256").update(artifactBytes).digest("hex"));
 assert.equal(result.artifactVerification.publisherKeyId,"publisher-test-key");
 assert.equal(result.artifactVerification.verificationMethod,"ed25519-sha256-before-json-parse");
 assert.throws(()=>registry.registerCandidate({candidateId:"forged",manifest:result.manifest,artifactSha256:"a".repeat(64),createdBy:"attacker",eligibility:{eligible:true},artifactVerification:{verified:true,artifactSha256:"a".repeat(64),publisherKeyId:"fake",verifierVersion:"fake"}}),/Raw model artifact bytes are required/);
 assert.throws(()=>registry.registerCandidate({candidateId:"bad-signature",manifest,artifactBytes,artifactSignature:"bad",publisherKeyId:"publisher-test-key",createdBy:"trainer-2"}),/canonical base64 Ed25519/);
});
test("tampered artifact bytes fail signature verification before JSON parsing",()=>{
 const {artifactVerifier,artifactBytes,artifactSignature}=setup();
 const tampered=Buffer.from(artifactBytes);tampered[0]^=1;
 assert.throws(()=>artifactVerifier.verify({bytes:tampered,signature:artifactSignature,publisherKeyId:"publisher-test-key"}),/signature verification failed/);
});
test("unknown publisher key IDs fail closed",()=>{
 const {artifactVerifier,artifactBytes,artifactSignature}=setup();
 assert.throws(()=>artifactVerifier.verify({bytes:artifactBytes,signature:artifactSignature,publisherKeyId:"attacker-key"}),/not in the trusted key ring/);
});
test("manifest and signed artifact metadata must match",()=>{
 const {registry,keyPair,manifest,artifactBytes,artifactSignature}=setup();
 const changed={...manifest,modelVersion:"different-model"};
 const {manifestSha256,...descriptor}=changed;
 const validChanged={...descriptor,manifestSha256:gov.sha256(descriptor)};
 assert.throws(()=>registry.registerCandidate({candidateId:"mismatch",manifest:validChanged,artifactBytes,artifactSignature,publisherKeyId:"publisher-test-key",createdBy:"trainer-2"}),/modelVersion mismatch/);
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
 const {registry,keyPair}=setup();
 const {candidateId}=makeCandidate(registry,keyPair,{candidateId:"blocked",modelVersion:"blocked-v1",createdBy:"trainer-2",eligible:false,datasetId:"BLOCKED"});
 approveAll(registry,candidateId);
 assert.throws(()=>registry.promoteCandidate({candidateId,releaseId:"blocked-release",actorId:"release-service"}),/eligibility is blocked/);
});
test("rollback only selects an existing prior release and emits review-required event",()=>{
 const {registry,keyPair,candidateId}=setup();approveAll(registry,candidateId);
 registry.promoteCandidate({candidateId,releaseId:"release-1",actorId:"release-service"});
 const {candidateId:secondId}=makeCandidate(registry,keyPair,{candidateId:"candidate-002",modelVersion:"0.6.1-test-model-2",createdBy:"trainer-2",datasetId:"SECOND"});
 approveAll(registry,secondId);
 registry.promoteCandidate({candidateId:secondId,releaseId:"release-2",actorId:"release-service"});
 const result=registry.rollback({targetReleaseId:"release-1",actorId:"operator-1",reason:"Post-release monitoring detected unacceptable drift"});
 assert.deepEqual(result,{activeReleaseId:"release-1",rolledBackFrom:"release-2",rolledBackTo:"release-1",requiresPostRollbackReview:true});
 assert.throws(()=>registry.rollback({targetReleaseId:"unknown",actorId:"operator-1",reason:"x"}),/previously approved release/);
});
test("append-only event hash chain verifies and detects detached snapshot mutation",()=>{
 const {registry,candidateId}=setup();
 registry.approveCandidate({candidateId,approvalId:"a",approverId:"risk-1",role:"model-risk",reason:"Review"});
 assert.equal(registry.verifyEventChain().valid,true);
 const snapshot=registry.getSnapshot();assert.equal(snapshot.chainVerification.eventCount,2);
 snapshot.events[0].payload.candidateId="tampered";
 assert.equal(registry.verifyEventChain().valid,true);
});

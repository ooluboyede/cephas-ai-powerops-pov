const test=require("node:test");
const assert=require("node:assert/strict");
const crypto=require("node:crypto");
const gov=require("../src/ml-governance.js");
const {signModelArtifact}=require("../src/ml-training-pipeline.js");
const {canonical}=gov;
const {createTrustedArtifactVerifier}=require("../src/trusted-artifact-verifier.js");
const {createTrustedPromotionEvaluator}=require("../src/trusted-promotion-evaluator.js");
const {createRegistry}=require("../src/ml-model-registry.js");

function makeCandidate(registry,keyPair,evaluatorKeyPair,{candidateId="candidate-001",modelVersion="0.6.2-test-model",createdBy="trainer-1",eligible=true,datasetId="POWEROPS-SYNTHETIC-REGISTRY-V1",callerEligibility}={}){
 const records=Array.from({length:12},(_,i)=>({id:datasetId+"-"+i,label:i%2?"normal":"anomaly"}));
 const dataset=gov.createDatasetManifest(records,{datasetId,sourceType:"synthetic"});
 const model={schemaVersion:"1.0",modelVersion,algorithm:"standardized-logistic-regression",featureSchema:gov.FEATURE_SCHEMA.slice(),datasetSha256:dataset.contentSha256,weights:[0,0,0,0,0,0],bias:0,threshold:0.5};
 const manifest=gov.createModelManifest({modelVersion,featureVersion:"0.5.2-feature-pipeline",algorithm:model.algorithm,featureSchema:model.featureSchema,datasetManifest:dataset,trainingCodeRevision:"test-revision",createdAt:"2026-11-18T00:00:00Z"});
 const artifactBytes=Buffer.from(canonical(model),"utf8");
 const artifactSignature=signModelArtifact(artifactBytes,keyPair.privateKey);
 const artifactSha256=crypto.createHash("sha256").update(artifactBytes).digest("hex");
 const report={schemaVersion:"1.0",manifestSha256:manifest.manifestSha256,artifactSha256,evaluationDatasetSha256:gov.sha256("heldout-"+datasetId),evaluationDatasetId:"HELDOUT-"+datasetId,evaluationMethod:"held-out-synthetic-test-v1",cases:120,precision:eligible?0.96:0.50,recall:eligible?0.95:0.40,driftPsi:eligible?0.08:0.31,createdAt:"2026-11-18T00:00:00.000Z"};
 const evaluationReportBytes=Buffer.from(canonical(report),"utf8");
 const evaluationReportSignature=crypto.sign(null,evaluationReportBytes,evaluatorKeyPair.privateKey).toString("base64");
 const result=registry.registerCandidate({candidateId,manifest,artifactBytes,artifactSignature,publisherKeyId:"publisher-test-key",createdBy,evaluationReportBytes,evaluationReportSignature,evaluatorKeyId:"evaluator-test-key",eligibility:callerEligibility});
 return {result,candidateId,artifactBytes,artifactSignature,artifactSha256,manifest,model,dataset,evaluationReportBytes,evaluationReportSignature};
}
function setup(){
 const keyPair=crypto.generateKeyPairSync("ed25519");
 const evaluatorKeyPair=crypto.generateKeyPairSync("ed25519");
 const artifactVerifier=createTrustedArtifactVerifier({trustedPublishers:{"publisher-test-key":keyPair.publicKey}});
 const promotionEvaluator=createTrustedPromotionEvaluator({trustedEvaluators:{"evaluator-test-key":evaluatorKeyPair.publicKey}});
 const registry=createRegistry({artifactVerifier,promotionEvaluator});
 const created=makeCandidate(registry,keyPair,evaluatorKeyPair);
 return {registry,keyPair,evaluatorKeyPair,artifactVerifier,promotionEvaluator,...created};
}
function approveAll(registry,candidateId){
 for(const [role,approverId] of [["model-risk","risk-1"],["security","security-1"],["operations-owner","ops-1"]]){
  registry.approveCandidate({candidateId,approvalId:"approval-"+role,approverId,role,decision:"approve",reason:"Independent gate review passed"});
 }
}

test("registry refuses to start without trusted artifact and promotion verifiers",()=>{
 assert.throws(()=>createRegistry(),/Trusted artifact verifier must be injected/);
 const keyPair=crypto.generateKeyPairSync("ed25519");
 const artifactVerifier=createTrustedArtifactVerifier({trustedPublishers:{"publisher-test-key":keyPair.publicKey}});
 assert.throws(()=>createRegistry({artifactVerifier}),/Trusted promotion evaluator must be injected/);
});
test("candidate registration verifies signed artifact and derives eligibility from trusted signed evaluation evidence",()=>{
 const {result,artifactBytes,evaluationReportBytes}=setup();
 assert.equal(result.artifactVerification.verified,true);
 assert.equal(result.artifactVerification.artifactSha256,crypto.createHash("sha256").update(artifactBytes).digest("hex"));
 assert.equal(result.artifactVerification.publisherKeyId,"publisher-test-key");
 assert.equal(result.eligibility.eligible,true);
 assert.equal(result.eligibilityVerification.verified,true);
 assert.equal(result.eligibilityVerification.reportSha256,crypto.createHash("sha256").update(evaluationReportBytes).digest("hex"));
});
test("caller-supplied eligibility cannot override a signed blocked evaluation report",()=>{
 const {registry,keyPair,evaluatorKeyPair}=setup();
 const {candidateId,result}=makeCandidate(registry,keyPair,evaluatorKeyPair,{candidateId:"blocked",modelVersion:"blocked-v1",createdBy:"trainer-2",eligible:false,callerEligibility:{eligible:true,reasons:[]}});
 assert.equal(result.eligibility.eligible,false);
 approveAll(registry,candidateId);
 assert.throws(()=>registry.promoteCandidate({candidateId,releaseId:"blocked-release",actorId:"release-service"}),/eligibility is blocked/);
});
test("tampered evaluation report bytes fail signature verification before parsing",()=>{
 const {promotionEvaluator,evaluationReportBytes,evaluationReportSignature,evaluatorKeyPair,manifest,artifactSha256}=setup();
 const tampered=Buffer.from(evaluationReportBytes);tampered[0]^=1;
 assert.throws(()=>promotionEvaluator.evaluate({bytes:tampered,signature:evaluationReportSignature,evaluatorKeyId:"evaluator-test-key",manifest,artifactSha256}),/signature verification failed/);
});
test("unknown evaluator key IDs and malformed signatures fail closed",()=>{
 const {promotionEvaluator,evaluationReportBytes,evaluationReportSignature,manifest,artifactSha256}=setup();
 assert.throws(()=>promotionEvaluator.evaluate({bytes:evaluationReportBytes,signature:evaluationReportSignature,evaluatorKeyId:"attacker-key",manifest,artifactSha256}),/not trusted/);
 assert.throws(()=>promotionEvaluator.evaluate({bytes:evaluationReportBytes,signature:"bad",evaluatorKeyId:"evaluator-test-key",manifest,artifactSha256}),/canonical base64/);
});
test("evaluation report must bind the exact manifest and artifact and use a separate holdout dataset",()=>{
 const {promotionEvaluator,evaluationReportBytes,evaluationReportSignature,manifest,artifactSha256,evaluatorKeyPair}=setup();
 const parsed=JSON.parse(evaluationReportBytes.toString("utf8"));
 const mismatch={...parsed,artifactSha256:"a".repeat(64)};
 const mismatchBytes=Buffer.from(canonical(mismatch),"utf8");
 const mismatchSignature=crypto.sign(null,mismatchBytes,evaluatorKeyPair.privateKey).toString("base64");
 assert.throws(()=>promotionEvaluator.evaluate({bytes:mismatchBytes,signature:mismatchSignature,evaluatorKeyId:"evaluator-test-key",manifest,artifactSha256}),/artifact binding mismatch/);
 const sameTraining={...parsed,evaluationDatasetSha256:manifest.datasetSha256};
 const sameBytes=Buffer.from(canonical(sameTraining),"utf8");
 const sameSignature=crypto.sign(null,sameBytes,evaluatorKeyPair.privateKey).toString("base64");
 assert.throws(()=>promotionEvaluator.evaluate({bytes:sameBytes,signature:sameSignature,evaluatorKeyId:"evaluator-test-key",manifest,artifactSha256}),/separate from training data/);
});
test("release fails closed until all independent roles approve and trusted eligibility is true",()=>{
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
test("rollback only selects an existing prior release and emits review-required event",()=>{
 const {registry,keyPair,evaluatorKeyPair,candidateId}=setup();approveAll(registry,candidateId);
 registry.promoteCandidate({candidateId,releaseId:"release-1",actorId:"release-service"});
 const {candidateId:secondId}=makeCandidate(registry,keyPair,evaluatorKeyPair,{candidateId:"candidate-002",modelVersion:"0.6.2-test-model-2",createdBy:"trainer-2",datasetId:"SECOND"});
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

const test=require('node:test');
const assert=require('node:assert/strict');
const gov=require('../src/ml-governance.js');
const records=Array.from({length:120},(_,i)=>({id:"SYN-"+i,load:50+(i%20),label:i%2?"normal":"anomaly"}));
function fixture(){
 const dataset=gov.createDatasetManifest(records,{datasetId:"POWEROPS-SYNTHETIC-GOVERNANCE-V1",sourceType:"synthetic"});
 const manifest=gov.createModelManifest({modelVersion:"0.5.3-test-model",featureVersion:"0.5.2-feature-pipeline",featureSchema:gov.FEATURE_SCHEMA,datasetManifest:dataset,algorithm:"knn-novelty",hyperparameters:{k:3,scaler:"fixed-reference-v1"},trainingCodeRevision:"test-revision",createdAt:"2026-11-14T00:00:00Z"});
 return {dataset,manifest};
}
test("dataset manifests are deterministic, hashed and explicitly source-labelled",()=>{
 const a=gov.createDatasetManifest(records,{datasetId:"SYN-1",sourceType:"synthetic"});
 const b=gov.createDatasetManifest(records,{datasetId:"SYN-1",sourceType:"synthetic"});
 assert.equal(a.contentSha256,b.contentSha256);
 assert.equal(a.recordCount,120);assert.equal(a.sourceType,"synthetic");
 assert.throws(()=>gov.createDatasetManifest(records,{datasetId:"X",sourceType:"customer-approved"}),/approval reference/);
 assert.throws(()=>gov.createDatasetManifest(records,{datasetId:"X",sourceType:"synthetic",approvalReference:"fake"}),/must not claim/);
});
test("model manifests bind model, feature schema, dataset lineage and artifact hash",()=>{
 const {manifest}=fixture();
 assert.equal(gov.verifyModelManifest(manifest).valid,true);
 const tampered={...manifest,featureVersion:"changed"};
 assert.equal(gov.verifyModelManifest(tampered).valid,false);
});
test("evaluation reports confusion matrix and refuses malformed or empty labels",()=>{
 const result=gov.confusionMetrics(["normal","normal","anomaly","anomaly"],["normal","anomaly","anomaly","normal"]);
 assert.deepEqual([result.tp,result.tn,result.fp,result.fn],[1,1,1,1]);
 assert.equal(result.precision,0.5);assert.equal(result.recall,0.5);
 assert.throws(()=>gov.confusionMetrics([],[]),/non-empty/);
});
test("PSI drift calculation is deterministic and distinguishes shifted distributions",()=>{
 const reference=Array.from({length:100},(_,i)=>20+(i%10));
 const stable=reference.slice();
 const shifted=Array.from({length:100},(_,i)=>80+(i%10));
 assert.equal(gov.populationStabilityIndex(reference,stable),0);
 assert.ok(gov.populationStabilityIndex(reference,shifted)>0.2);
 assert.throws(()=>gov.populationStabilityIndex([],[]),/non-empty/);
});
test("release gate fails closed for tiny synthetic benchmark and passes only configured thresholds",()=>{
 const {manifest}=fixture();
 const blocked=gov.assessPromotion({manifest,evaluation:{cases:4,precision:1,recall:1},driftPsi:0.01});
 assert.equal(blocked.eligible,false);assert.match(blocked.reasons.join(" "),/minimum case count/);
 const accepted=gov.assessPromotion({manifest,evaluation:{cases:120,precision:0.95,recall:0.92},driftPsi:0.08});
 assert.equal(accepted.eligible,true);
 assert.throws(()=>gov.createRegistryRecord({...manifest,artifactSha256:"0".repeat(64)},accepted),/invalid model manifest/);
 const entry=gov.createRegistryRecord(manifest,blocked);
 assert.equal(entry.decision,"blocked");assert.match(entry.recordSha256,/^[a-f0-9]{64}$/);
});
test("feature schema changes block promotion even when the manifest hash is valid",()=>{
 const {dataset}=fixture();
 const manifest=gov.createModelManifest({modelVersion:"0.5.3-other",featureVersion:"x",featureSchema:["load"],datasetManifest:dataset});
 const decision=gov.assessPromotion({manifest,evaluation:{cases:200,precision:1,recall:1},driftPsi:0});
 assert.equal(decision.eligible,false);assert.match(decision.reasons.join(" "),/Feature schema/);
});

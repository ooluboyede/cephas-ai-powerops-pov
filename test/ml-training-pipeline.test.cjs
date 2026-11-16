const test=require("node:test");
const assert=require("node:assert/strict");
const crypto=require("node:crypto");
const pipeline=require("../src/ml-training-pipeline.js");
const gov=require("../src/ml-governance.js");
function dataset(){
 return Array.from({length:160},(_,i)=>{
  const anomaly=i%2===1,noise=(i%7)*0.03;
  const f=anomaly?{availability_pct:90+noise,mean_load_pct:90+noise,load_stddev_pct:5+noise,mean_voltage_deviation_pct:5+noise,voltage_load_interaction:4.5+noise,high_load_interval_ratio:0.8}:{availability_pct:98-noise,mean_load_pct:60+noise,load_stddev_pct:1+noise,mean_voltage_deviation_pct:1+noise,voltage_load_interaction:0.6+noise,high_load_interval_ratio:0.05};
  return {id:"SYN-"+String(i).padStart(4,"0"),label:anomaly?"anomaly":"normal",features:f};
 });
}
function trained(){const rows=dataset(),manifest=gov.createDatasetManifest(rows,{datasetId:"POWEROPS-TRAINING-SYN-V1",sourceType:"synthetic"});return pipeline.trainModel(rows,{seed:42,datasetSha256:manifest.contentSha256,epochs:350});}
test("deterministic seeded split is repeatable, complete and disjoint",()=>{
 const rows=dataset(),a=pipeline.splitDataset(rows,{seed:17}),b=pipeline.splitDataset(rows,{seed:17});
 assert.deepEqual(a.train.map(x=>x.id),b.train.map(x=>x.id));
 const ids=[...a.train,...a.validation,...a.test].map(x=>x.id);
 assert.equal(ids.length,rows.length);assert.equal(new Set(ids).size,rows.length);
 assert.throws(()=>pipeline.splitDataset([...rows,rows[0]]),/Duplicate record/);
});
test("standardization and model fitting use training partition only",()=>{
 const {model,splits,evaluation}=trained();
 const trainMeans={};
 for(const key of gov.FEATURE_SCHEMA)trainMeans[key]=splits.train.reduce((s,r)=>s+r.features[key],0)/splits.train.length;
 assert.equal(model.standardizer.means.mean_load_pct,trainMeans.mean_load_pct);
 assert.equal(model.training.fitPartition,"train-only");
 assert.ok(evaluation.test.cases>0);assert.equal(model.split.testCount,splits.test.length);
});
test("training is reproducible for identical data and seed",()=>{
 const a=trained().model,b=trained().model;
 assert.deepEqual(a,b);
});
test("artifact SHA-256 is a hash of the serialized model bytes",()=>{
 const {model}=trained(),artifact=pipeline.serializeModelArtifact(model);
 assert.equal(artifact.sha256,crypto.createHash("sha256").update(artifact.bytes).digest("hex"));
 assert.equal(artifact.bytes.toString("utf8").includes(model.modelVersion),true);
});
test("Ed25519 signature and binary hash are verified before deserialization",()=>{
 const {publicKey,privateKey}=crypto.generateKeyPairSync("ed25519");
 const {model}=trained(),artifact=pipeline.serializeModelArtifact(model),signature=pipeline.signModelArtifact(artifact.bytes,privateKey);
 let calls=0;const deserialize=raw=>{calls++;return JSON.parse(raw)};
 const loaded=pipeline.verifyArtifactBeforeLoad({bytes:artifact.bytes,expectedSha256:artifact.sha256,signature,publicKey,deserialize});
 assert.equal(loaded.modelVersion,model.modelVersion);assert.equal(calls,1);
 assert.throws(()=>pipeline.verifyArtifactBeforeLoad({bytes:Buffer.from("tampered"),expectedSha256:artifact.sha256,signature,publicKey,deserialize}),/SHA-256 mismatch/);
 assert.equal(calls,1,"tampered bytes must not reach deserializer");
 assert.throws(()=>pipeline.verifyArtifactBeforeLoad({bytes:artifact.bytes,expectedSha256:artifact.sha256,signature:Buffer.from("bad").toString("base64"),publicKey,deserialize}),/signature verification failed/);
 assert.equal(calls,1,"invalid signature must not reach deserializer");
});
test("missing signatures, wrong publisher keys and wrong key types fail closed",()=>{
 const keys=crypto.generateKeyPairSync("ed25519"),other=crypto.generateKeyPairSync("ed25519");
 const artifact=pipeline.serializeModelArtifact(trained().model),signature=pipeline.signModelArtifact(artifact.bytes,keys.privateKey);
 const args={bytes:artifact.bytes,expectedSha256:artifact.sha256,signature,publicKey:other.publicKey,deserialize:JSON.parse};
 assert.throws(()=>pipeline.verifyArtifactBeforeLoad({...args,signature:""}),/signature is missing/);
 assert.throws(()=>pipeline.verifyArtifactBeforeLoad(args),/signature verification failed/);
 const rsa=crypto.generateKeyPairSync("rsa",{modulusLength:2048});
 assert.throws(()=>pipeline.verifyArtifactBeforeLoad({...args,publicKey:rsa.publicKey}),/must be Ed25519/);
});
test("dataset schema, labels, thresholds and lineage requirements reject invalid training input",()=>{
 const rows=dataset(),manifest=gov.createDatasetManifest(rows,{datasetId:"SYN",sourceType:"synthetic"});
 assert.throws(()=>pipeline.trainModel(rows,{datasetSha256:"bad"}),/SHA-256/);
 assert.throws(()=>pipeline.trainModel(rows,{datasetSha256:manifest.contentSha256,epochs:0}),/epoch count/);
 assert.throws(()=>pipeline.trainModel(rows,{datasetSha256:manifest.contentSha256,threshold:2}),/classification threshold/);
 const invalid=rows.slice();invalid[0]={...invalid[0],features:{...invalid[0].features,mean_load_pct:NaN}};
 assert.throws(()=>pipeline.splitDataset(invalid),/Missing numeric feature/);
});

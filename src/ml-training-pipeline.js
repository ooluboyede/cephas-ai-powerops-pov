"use strict";
const crypto=require("node:crypto");
const {canonical,sha256,FEATURE_SCHEMA,confusionMetrics}=require("./ml-governance.js");

function assert(condition,message){if(!condition)throw new Error(message)}
function seededRandom(seed){
 let state=(Number(seed)>>>0)||1;
 return ()=>{state=(state*1664525+1013904223)>>>0;return state/4294967296};
}
function splitDataset(records,{seed=20261116,trainRatio=0.6,validationRatio=0.2}={}){
 assert(Array.isArray(records)&&records.length>=10,"At least 10 labelled records are required");
 assert(trainRatio>0&&validationRatio>0&&trainRatio+validationRatio<1,"Invalid split ratios");
 const ids=new Set();
 records.forEach((r,i)=>{assert(r&&typeof r.id==="string"&&r.id.length>0,"Every record requires a stable id");assert(!ids.has(r.id),"Duplicate record id: "+r.id);ids.add(r.id);assert(r.label==="normal"||r.label==="anomaly","Labels must be normal or anomaly");FEATURE_SCHEMA.forEach(k=>assert(Number.isFinite(r.features&&r.features[k]),"Missing numeric feature "+k+" in "+r.id));});
 const rows=records.slice(),rand=seededRandom(seed);
 for(let i=rows.length-1;i>0;i--){const j=Math.floor(rand()*(i+1));[rows[i],rows[j]]=[rows[j],rows[i]];}
 const trainEnd=Math.floor(rows.length*trainRatio),validationEnd=trainEnd+Math.floor(rows.length*validationRatio);
 const result={seed,train:rows.slice(0,trainEnd),validation:rows.slice(trainEnd,validationEnd),test:rows.slice(validationEnd)};
 const partitions=[...result.train,...result.validation,...result.test];
 assert(partitions.length===records.length&&new Set(partitions.map(x=>x.id)).size===records.length,"Dataset split leakage or loss detected");
 return result;
}
function fitStandardizer(rows){
 const means={},scales={};
 FEATURE_SCHEMA.forEach(k=>{const values=rows.map(r=>r.features[k]);const mean=values.reduce((a,b)=>a+b,0)/values.length;const variance=values.reduce((a,x)=>a+(x-mean)**2,0)/values.length;means[k]=mean;scales[k]=Math.sqrt(variance)||1;});
 return {means,scales};
}
function vector(record,standardizer){return FEATURE_SCHEMA.map(k=>(record.features[k]-standardizer.means[k])/standardizer.scales[k])}
function sigmoid(z){if(z>30)return 1;if(z< -30)return 0;return 1/(1+Math.exp(-z))}
function trainModel(records,{seed=20261116,learningRate=0.08,epochs=600,threshold=0.5,modelVersion="0.5.4-logistic-baseline",datasetSha256}={}){
 assert(Array.isArray(records)&&records.length>=10,"Training dataset is too small");
 assert(Number.isFinite(learningRate)&&learningRate>0&&learningRate<=1,"Invalid learning rate");
 assert(Number.isInteger(epochs)&&epochs>=1&&epochs<=10000,"Invalid epoch count");
 assert(Number.isFinite(threshold)&&threshold>0&&threshold<1,"Invalid classification threshold");
 assert(/^[a-f0-9]{64}$/.test(datasetSha256||""),"A verified dataset SHA-256 is required");
 const splits=splitDataset(records,{seed});
 const standardizer=fitStandardizer(splits.train);
 let weights=FEATURE_SCHEMA.map(()=>0),bias=0;
 for(let epoch=0;epoch<epochs;epoch++){
  const gradients=weights.map(()=>0);let biasGradient=0;
  for(const row of splits.train){const x=vector(row,standardizer),y=row.label==="anomaly"?1:0,p=sigmoid(weights.reduce((s,w,i)=>s+w*x[i],bias));x.forEach((v,i)=>gradients[i]+=(p-y)*v);biasGradient+=p-y;}
  weights=weights.map((w,i)=>w-learningRate*gradients[i]/splits.train.length);
  bias-=learningRate*biasGradient/splits.train.length;
 }
 const model={schemaVersion:"1.0",modelVersion,algorithm:"standardized-logistic-regression",featureSchema:FEATURE_SCHEMA.slice(),datasetSha256,split:{seed,trainCount:splits.train.length,validationCount:splits.validation.length,testCount:splits.test.length},standardizer,weights,bias,threshold,training:{epochs,learningRate,fitPartition:"train-only"},createdAt:"REPRODUCIBLE_BUILD_TIMESTAMP_OMITTED"};
 const predict=row=>sigmoid(weights.reduce((s,w,i)=>s+w*vector(row,standardizer)[i],bias))>=threshold?"anomaly":"normal";
 const evaluate=partition=>{const actual=partition.map(x=>x.label),predicted=partition.map(predict);return confusionMetrics(actual,predicted)};
 return {model,splits,evaluation:{validation:evaluate(splits.validation),test:evaluate(splits.test)},predict};
}
function serializeModelArtifact(model){
 assert(model&&model.algorithm==="standardized-logistic-regression","Unsupported model artifact");
 const bytes=Buffer.from(canonical(model),"utf8");
 return {bytes,sha256:crypto.createHash("sha256").update(bytes).digest("hex")};
}
function signModelArtifact(bytes,privateKey){
 assert(Buffer.isBuffer(bytes),"Artifact bytes must be a Buffer");
 assert(privateKey,"Ed25519 private key is required");
 const key=privateKey&&privateKey.type==="private"?privateKey:crypto.createPrivateKey(privateKey);
 assert(key.asymmetricKeyType==="ed25519","Signing key must be Ed25519");
 return crypto.sign(null,bytes,key).toString("base64");
}
function verifyArtifactBeforeLoad({bytes,expectedSha256,signature,publicKey,deserialize}){
 assert(Buffer.isBuffer(bytes),"Artifact bytes must be a Buffer");
 assert(typeof deserialize==="function","A deserializer must be supplied by the trusted loader");
 const actual=crypto.createHash("sha256").update(bytes).digest("hex");
 if(!/^[a-f0-9]{64}$/.test(expectedSha256||"")||actual!==expectedSha256)throw new Error("Artifact SHA-256 mismatch; refusing to load");
 if(typeof signature!=="string"||!signature)throw new Error("Artifact signature is missing; refusing to load");
 assert(publicKey,"Trusted publisher public key is required");
 const key=publicKey&&publicKey.type==="public"?publicKey:crypto.createPublicKey(publicKey);
 if(key.asymmetricKeyType!=="ed25519")throw new Error("Trusted publisher key must be Ed25519");
 let valid=false;
 try{valid=crypto.verify(null,bytes,key,Buffer.from(signature,"base64"));}catch(_){valid=false;}
 if(!valid)throw new Error("Artifact signature verification failed; refusing to load");
 // This is deliberately the first point at which artifact bytes are parsed.
 return deserialize(bytes.toString("utf8"));
}
module.exports={seededRandom,splitDataset,fitStandardizer,trainModel,serializeModelArtifact,signModelArtifact,verifyArtifactBeforeLoad};

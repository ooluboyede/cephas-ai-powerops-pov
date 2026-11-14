"use strict";
const crypto=require("node:crypto");
const FEATURE_SCHEMA=[
 "availability_pct","mean_load_pct","load_stddev_pct",
 "mean_voltage_deviation_pct","voltage_load_interaction","high_load_interval_ratio"
];
const POLICY=Object.freeze({minimumEvaluationCases:100,minimumPrecision:0.9,minimumRecall:0.9,maximumPsi:0.2});
function canonical(value){
 if(Array.isArray(value))return "["+value.map(canonical).join(",")+"]";
 if(value&&typeof value==="object")return "{"+Object.keys(value).sort().map(k=>JSON.stringify(k)+":"+canonical(value[k])).join(",")+"}";
 return JSON.stringify(value);
}
function sha256(value){return crypto.createHash("sha256").update(typeof value==="string"?value:canonical(value)).digest("hex")}
function assertText(v,name){if(typeof v!=="string"||!v.trim())throw new Error(name+" is required")}
function createDatasetManifest(records,metadata={}){
 if(!Array.isArray(records)||records.length===0)throw new Error("Dataset must contain records");
 assertText(metadata.datasetId,"datasetId");assertText(metadata.sourceType,"sourceType");
 if(!["synthetic","customer-approved"].includes(metadata.sourceType))throw new Error("Unsupported dataset sourceType");
 if(metadata.sourceType==="customer-approved"&&metadata.approvalReference===undefined)throw new Error("Customer data requires an approval reference");
 if(metadata.sourceType==="synthetic"&&metadata.approvalReference)throw new Error("Synthetic dataset must not claim customer approval");
 const payload={datasetId:metadata.datasetId,sourceType:metadata.sourceType,recordCount:records.length,records};
 return Object.freeze({schemaVersion:"1.0",datasetId:metadata.datasetId,sourceType:metadata.sourceType,recordCount:records.length,approvalReference:metadata.approvalReference||null,retentionPolicy:metadata.retentionPolicy||"synthetic-demo-no-customer-retention",contentSha256:sha256(payload)});
}
function createModelManifest(input){
 assertText(input.modelVersion,"modelVersion");assertText(input.featureVersion,"featureVersion");
 if(!input.datasetManifest||!/^[a-f0-9]{64}$/.test(input.datasetManifest.contentSha256||""))throw new Error("Valid dataset manifest is required");
 if(!Array.isArray(input.featureSchema)||input.featureSchema.length===0)throw new Error("Feature schema is required");
 const descriptor={schemaVersion:"1.0",modelVersion:input.modelVersion,algorithm:input.algorithm||"knn-novelty",featureVersion:input.featureVersion,featureSchema:input.featureSchema.slice(),datasetSha256:input.datasetManifest.contentSha256,datasetId:input.datasetManifest.datasetId,hyperparameters:input.hyperparameters||{},trainingCodeRevision:input.trainingCodeRevision||"unrecorded",createdAt:input.createdAt||"UNSPECIFIED"};
 return Object.freeze({...descriptor,artifactSha256:sha256(descriptor)});
}
function verifyModelManifest(manifest){
 if(!manifest||!/^[a-f0-9]{64}$/.test(manifest.artifactSha256||""))return {valid:false,reason:"Missing or malformed artifact SHA-256"};
 const {artifactSha256,...descriptor}=manifest;
 const valid=sha256(descriptor)===artifactSha256;
 return {valid,reason:valid?"Manifest integrity verified":"Manifest integrity mismatch"};
}
function confusionMetrics(actual,predicted){
 if(!Array.isArray(actual)||!Array.isArray(predicted)||actual.length!==predicted.length||actual.length===0)throw new Error("Actual and predicted labels must be non-empty arrays of equal length");
 let tp=0,tn=0,fp=0,fn=0;
 actual.forEach((label,i)=>{if(!["normal","anomaly"].includes(label)||!["normal","anomaly"].includes(predicted[i]))throw new Error("Labels must be normal or anomaly");if(label==="anomaly"&&predicted[i]==="anomaly")tp++;else if(label==="normal"&&predicted[i]==="normal")tn++;else if(predicted[i]==="anomaly")fp++;else fn++});
 return {cases:actual.length,tp,tn,fp,fn,precision:tp+fp?tp/(tp+fp):0,recall:tp+fn?tp/(tp+fn):0,falsePositiveRate:fp+tn?fp/(fp+tn):0};
}
function populationStabilityIndex(reference,current,bins=[0,20,40,60,80,100,Infinity]){
 if(!Array.isArray(reference)||!Array.isArray(current)||!reference.length||!current.length)throw new Error("Reference and current samples must be non-empty");
 const counts=values=>bins.slice(0,-1).map((lo,i)=>values.filter(v=>Number.isFinite(v)&&v>=lo&&v<bins[i+1]).length);
 const a=counts(reference),b=counts(current),n=a.reduce((s,x)=>s+x,0),m=b.reduce((s,x)=>s+x,0);
 if(!n||!m)throw new Error("Samples must contain finite values in configured bins");
 return Number(a.reduce((s,x,i)=>{const p=Math.max(x/n,0.0001),q=Math.max(b[i]/m,0.0001);return s+(q-p)*Math.log(q/p)},0).toFixed(6));
}
function assessPromotion({manifest,evaluation,driftPsi,policy=POLICY}){
 const integrity=verifyModelManifest(manifest),reasons=[];
 if(!integrity.valid)reasons.push("Model manifest integrity check failed");
 if(!manifest||manifest.featureSchema?.join("|")!==FEATURE_SCHEMA.join("|"))reasons.push("Feature schema does not match the approved schema");
 if(!evaluation||evaluation.cases<policy.minimumEvaluationCases)reasons.push("Evaluation sample is below the minimum case count");
 if(!evaluation||!Number.isFinite(evaluation.precision)||evaluation.precision<policy.minimumPrecision)reasons.push("Precision is missing or below the release threshold");
 if(!evaluation||!Number.isFinite(evaluation.recall)||evaluation.recall<policy.minimumRecall)reasons.push("Recall is missing or below the release threshold");
 if(!Number.isFinite(driftPsi)||driftPsi>policy.maximumPsi)reasons.push("Feature drift is missing or exceeds the release threshold");
 return {eligible:reasons.length===0,status:reasons.length===0?"Eligible for independent release review":"Blocked",reasons,policy:{...policy},note:"Eligibility is not automatic deployment approval; independent review, security approval and customer validation remain separate controls."};
}
function createRegistryRecord(manifest,decision){
 if(!verifyModelManifest(manifest).valid)throw new Error("Cannot register an invalid model manifest");
 return Object.freeze({registrySchema:"1.0",modelVersion:manifest.modelVersion,artifactSha256:manifest.artifactSha256,decision:decision.eligible?"eligible-for-independent-review":"blocked",reasons:decision.reasons.slice(),recordSha256:sha256({modelVersion:manifest.modelVersion,artifactSha256:manifest.artifactSha256,decision:decision.eligible,reasons:decision.reasons})});
}
module.exports={FEATURE_SCHEMA,POLICY,canonical,sha256,createDatasetManifest,createModelManifest,verifyModelManifest,confusionMetrics,populationStabilityIndex,assessPromotion,createRegistryRecord};

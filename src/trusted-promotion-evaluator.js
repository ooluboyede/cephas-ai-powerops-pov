"use strict";
const crypto=require("node:crypto");
const {canonical,assessPromotion,POLICY}=require("./ml-governance.js");

function assert(ok,message){if(!ok)throw new Error(message)}
function createTrustedPromotionEvaluator({trustedEvaluators,policy=POLICY,verifierVersion="0.6.2"}={}){
 assert(trustedEvaluators&&typeof trustedEvaluators==="object","Trusted evaluator key map is required");
 const keys=new Map();
 const entries=trustedEvaluators instanceof Map?[...trustedEvaluators.entries()]:Object.entries(trustedEvaluators);
 for(const [keyId,material] of entries){
  assert(typeof keyId==="string"&&/^[A-Za-z0-9._-]{1,128}$/.test(keyId),"Invalid evaluator key ID");
  const key=material&&material.type==="public"?material:crypto.createPublicKey(material);
  assert(key.asymmetricKeyType==="ed25519"&&key.type==="public","Evaluator key must be Ed25519 public key");
  assert(!keys.has(keyId),"Duplicate evaluator key ID");
  keys.set(keyId,key);
 }
 assert(keys.size>0,"At least one trusted evaluator key is required");
 const releasePolicy=Object.freeze({...policy});
 return Object.freeze({
  evaluate({bytes,signature,evaluatorKeyId,manifest,artifactSha256}={}){
   assert(Buffer.isBuffer(bytes)&&bytes.length>0&&bytes.length<=1024*1024,"Bounded evaluation report bytes are required");
   assert(typeof evaluatorKeyId==="string"&&keys.has(evaluatorKeyId),"Evaluator key is not trusted");
   assert(typeof signature==="string"&&signature.length>0&&signature.length<=256,"A bounded Ed25519 report signature is required");
   const decoded=Buffer.from(signature,"base64");
   assert(decoded.length===64&&decoded.toString("base64")===signature,"Report signature must be canonical base64 Ed25519");
   const actualSha256=crypto.createHash("sha256").update(bytes).digest("hex");
   let valid=false;
   try{valid=crypto.verify(null,bytes,keys.get(evaluatorKeyId),decoded)}catch(_){valid=false}
   assert(valid,"Evaluation report signature verification failed");
   const serialized=bytes.toString("utf8");
   const report=JSON.parse(serialized);
   assert(canonical(report)===serialized,"Evaluation report must use canonical JSON encoding");
   assert(report&&report.schemaVersion==="1.0","Unsupported evaluation report schema");
   assert(report.manifestSha256===manifest.manifestSha256,"Evaluation report manifest binding mismatch");
   assert(report.artifactSha256===artifactSha256,"Evaluation report artifact binding mismatch");
   assert(/^[a-f0-9]{64}$/.test(report.evaluationDatasetSha256||""),"Evaluation dataset digest is invalid");
   assert(report.evaluationDatasetSha256!==manifest.datasetSha256,"Evaluation dataset must be separate from training data");
   assert(typeof report.evaluationDatasetId==="string"&&report.evaluationDatasetId.trim(),"Evaluation dataset ID is required");
   assert(typeof report.evaluationMethod==="string"&&report.evaluationMethod.trim(),"Evaluation method is required");
   assert(typeof report.createdAt==="string"&&Number.isFinite(Date.parse(report.createdAt)),"Evaluation report timestamp is invalid");
   assert(Number.isInteger(report.cases)&&report.cases>=0,"Evaluation case count is invalid");
   assert(Number.isFinite(report.precision)&&report.precision>=0&&report.precision<=1,"Evaluation precision is invalid");
   assert(Number.isFinite(report.recall)&&report.recall>=0&&report.recall<=1,"Evaluation recall is invalid");
   assert(Number.isFinite(report.driftPsi)&&report.driftPsi>=0,"Evaluation drift PSI is invalid");
   const decision=assessPromotion({manifest,evaluation:{cases:report.cases,precision:report.precision,recall:report.recall},driftPsi:report.driftPsi,policy:releasePolicy});
   return Object.freeze({
    decision:Object.freeze(decision),
    receipt:Object.freeze({verified:true,evaluatorKeyId,verifierVersion,reportSha256:actualSha256,manifestSha256:manifest.manifestSha256,artifactSha256,verifiedAt:new Date().toISOString(),verificationMethod:"ed25519-sha256-before-canonical-json-parse"})
   });
  }
 });
}
module.exports={createTrustedPromotionEvaluator};

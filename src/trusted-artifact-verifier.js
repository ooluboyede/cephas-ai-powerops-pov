"use strict";
const crypto=require("node:crypto");
const {verifyArtifactBeforeLoad}=require("./ml-training-pipeline.js");

function assert(ok,message){if(!ok)throw new Error(message)}
function createTrustedArtifactVerifier({trustedPublishers,verifierVersion="0.6.1"}={}){
 assert(trustedPublishers&&typeof trustedPublishers==="object","Trusted publisher key map is required");
 assert(typeof verifierVersion==="string"&&verifierVersion.trim(),"Verifier version is required");
 const keys=new Map();
 const entries=trustedPublishers instanceof Map?[...trustedPublishers.entries()]:Object.entries(trustedPublishers);
 for(const [keyId,material] of entries){
  assert(typeof keyId==="string"&&/^[A-Za-z0-9._-]{1,128}$/.test(keyId),"Invalid publisher key ID");
  const key=material&&material.type==="public"?material:crypto.createPublicKey(material);
  assert(key.asymmetricKeyType==="ed25519"&&key.type==="public","Publisher key must be an Ed25519 public key");
  assert(!keys.has(keyId),"Duplicate publisher key ID");
  keys.set(keyId,key);
 }
 assert(keys.size>0,"At least one trusted publisher key is required");
 return Object.freeze({
  verify({bytes,signature,publisherKeyId}={}){
   assert(Buffer.isBuffer(bytes),"Model artifact bytes must be a Buffer");
   assert(typeof publisherKeyId==="string"&&keys.has(publisherKeyId),"Publisher key is not in the trusted key ring");
   assert(typeof signature==="string"&&signature.length>0&&signature.length<=256,"A bounded Ed25519 signature is required");
   const decoded=Buffer.from(signature,"base64");
   assert(decoded.length===64&&decoded.toString("base64")===signature,"Signature must be canonical base64 Ed25519");
   const artifactSha256=crypto.createHash("sha256").update(bytes).digest("hex");
   const model=verifyArtifactBeforeLoad({
    bytes,expectedSha256:artifactSha256,signature,publicKey:keys.get(publisherKeyId),
    deserialize:serialized=>JSON.parse(serialized)
   });
   assert(model&&model.schemaVersion==="1.0","Unsupported model artifact schema");
   assert(model.algorithm==="standardized-logistic-regression","Unsupported model artifact algorithm");
   assert(typeof model.modelVersion==="string"&&model.modelVersion.trim(),"Artifact modelVersion is required");
   assert(Array.isArray(model.featureSchema)&&model.featureSchema.length>0,"Artifact feature schema is required");
   assert(/^[a-f0-9]{64}$/.test(model.datasetSha256||""),"Artifact dataset digest is invalid");
   return Object.freeze({
    model,
    receipt:Object.freeze({
     verified:true,artifactSha256,publisherKeyId,verifierVersion,
     verifiedAt:new Date().toISOString(),verificationMethod:"ed25519-sha256-before-json-parse"
    })
   });
  }
 });
}
module.exports={createTrustedArtifactVerifier};
